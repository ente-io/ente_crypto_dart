import 'dart:async';
import 'dart:convert';
import 'dart:io' as io;
import 'dart:developer';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart';
import 'package:ente_crypto_dart/src/core/errors.dart';
import 'package:ente_crypto_dart/src/models/derived_key_result.dart';
import 'package:ente_crypto_dart/src/models/device_info.dart';
import 'package:ente_crypto_dart/src/models/encryption_result.dart';
import 'package:logging/logging.dart';
import 'package:sodium/sodium_sumo.dart';
import 'package:sodium_libs/sodium_libs.dart';

export 'core/errors.dart';

const int encryptionChunkSize = 4 * 1024 * 1024;
const int hashChunkSize = 4 * 1024 * 1024;
const int loginSubKeyLen = 32;
const int loginSubKeyId = 1;
const String loginSubKeyContext = "loginctx";
late SodiumSumo sodium;

// Computes and returns the hash of the source file
Future<Uint8List> getHash(io.File source) {
  return sodium.runIsolated(
    (sodium, secureKeys, keyPairs) => cryptoGenericHash(source.path, sodium),
  );
}

Uint8List cryptoSecretboxEasy(
    Uint8List source, Uint8List nonce, Uint8List key) {
  return sodium.crypto.secretBox.easy(
      message: source, nonce: nonce, key: SecureKey.fromList(sodium, key));
}

Uint8List cryptoSecretboxOpenEasy(
    Uint8List cipher, Uint8List key, Uint8List nonce, Sodium sodium) {
  return sodium.crypto.secretBox.openEasy(
    cipherText: cipher,
    nonce: nonce,
    key: SecureKey.fromList(sodium, key),
  );
}

Uint8List cryptoPwHash(Uint8List password, Uint8List salt, int memLimit,
    int opsLimit, dynamic sodium) {
  return (sodium as Sodium)
      .crypto
      // ignore: deprecated_member_use
      .pwhash
      .call(
        outLen: sodium.crypto.secretBox.keyBytes,
        password: Int8List.view((password).buffer),
        salt: salt,
        opsLimit: opsLimit,
        memLimit: memLimit,
        alg: CryptoPwhashAlgorithm.argon2id13,
      )
      .extractBytes();
}

Uint8List cryptoKdfDeriveFromKey(
  Uint8List key,
  int subkeyId,
  int subkeyLen,
  String context,
  Sodium sodium,
) {
  return sodium.crypto.kdf
      .deriveFromKey(
        subkeyLen: subkeyLen,
        subkeyId: subkeyId,
        context: context,
        masterKey: SecureKey.fromList(sodium, key),
      )
      .extractBytes();
}

// Returns the hash for a given file, chunking it in batches of hashChunkSize
Future<Uint8List> cryptoGenericHash(
    String sourceFilePath, Sodium sodium) async {
  final sourceFile = io.File(sourceFilePath);
  final sourceFileLength = await sourceFile.length();
  final inputFile = sourceFile.openSync(mode: io.FileMode.read);
  final state = sodium.crypto.genericHash.createConsumer(
    key: null,
    outLen: sodium.crypto.genericHash.bytesMax,
  );
  var bytesRead = 0;
  bool isDone = false;
  while (!isDone) {
    var chunkSize = hashChunkSize;
    if (bytesRead + chunkSize >= sourceFileLength) {
      chunkSize = sourceFileLength - bytesRead;
      isDone = true;
    }
    final buffer = await inputFile.read(chunkSize);
    bytesRead += chunkSize;
    state.addStream(Stream.value(buffer));
  }
  await inputFile.close();
  return state.close();
}

Future<EncryptionResult> chachaEncryptData(
    Uint8List source, Uint8List key, Sodium sodium) async {
  // Use createPushEx like chachaEncryptFile does for consistent behavior
  final initPushResult = sodium.crypto.secretStream.createPushEx(
    SecureKey.fromList(sodium, key),
  );

  StreamController<SecretStreamPlainMessage> controller = StreamController();
  final res = initPushResult.bind(controller.stream);

  // Add the data with finalPush tag to match Mobile implementation
  controller.add(
    SecretStreamPlainMessage(
      source,
      tag: SecretStreamMessageTag.finalPush,
    ),
  );
  controller.close();

  final result = await res.toList();

  // result[0].message contains the header
  // result[1].message contains the encrypted data with TagFinal
  return EncryptionResult(
    encryptedData: result[1].message,
    header: result[0].message,
  );
}

// Encrypts a given file, in chunks of encryptionChunkSize
Future<EncryptionResult> chachaEncryptFile(
  String sourceFilePath,
  String destinationFilePath,
  Uint8List? skey,
  Sodium sodium,
) async {
  final encryptionStartTime = DateTime.now().millisecondsSinceEpoch;
  final logger = Logger("ChaChaEncrypt");
  final sourceFile = io.File(sourceFilePath);
  final destinationFile = io.File(destinationFilePath);
  final sourceFileLength = await sourceFile.length();
  logger.info("Encrypting file of size $sourceFileLength");

  final inputFile = sourceFile.openSync(mode: io.FileMode.read);
  final key = skey ?? sodium.crypto.secretStream.keygen().extractBytes();
  final initPushResult = sodium.crypto.secretStream.createPushEx(
    SecureKey.fromList(sodium, key),
  );
  StreamController<SecretStreamPlainMessage> controller = StreamController();
  final res = initPushResult.bind(controller.stream);
  var bytesRead = 0;

  var stop = false;
  while (!stop) {
    var chunkSize = encryptionChunkSize;
    if (bytesRead + chunkSize >= sourceFileLength) {
      chunkSize = sourceFileLength - bytesRead;
      stop = true;
    }
    final buffer = await inputFile.read(chunkSize);
    bytesRead += chunkSize;
    controller.add(
      SecretStreamPlainMessage(
        buffer,
        tag: stop
            ? SecretStreamMessageTag.finalPush
            : SecretStreamMessageTag.push,
      ),
    );
  }
  controller.close();
  final result = (await res.toList());
  Uint8List header = Uint8List(0);

  // Delete the destination file if it exists to avoid appending to old data
  if (await destinationFile.exists()) {
    await destinationFile.delete();
  }

  for (int i = 0; i < result.length; i++) {
    final data = result[i];
    if (i == 0) {
      header = data.message;
      continue;
    }
    await destinationFile.writeAsBytes(data.message, mode: io.FileMode.append);
  }
  await inputFile.close();

  logger.info(
    "Encryption time: ${DateTime.now().millisecondsSinceEpoch - encryptionStartTime}",
  );

  return EncryptionResult(key: key, header: header);
}

Future<void> chachaDecryptFile(
    String sourceFilePath,
    String destinationFilePath,
    Uint8List header,
    Uint8List key,
    Sodium sodium) async {
  final logger = Logger("ChaChaDecrypt");
  final decryptionStartTime = DateTime.now().millisecondsSinceEpoch;
  final sourceFile = io.File(sourceFilePath);
  final destinationFile = io.File(destinationFilePath);
  final sourceFileLength = await sourceFile.length();
  logger.info("Decrypting file of size $sourceFileLength");
  final int decryptionChunkSize =
      encryptionChunkSize + sodium.crypto.secretStream.aBytes;

  final inputFile = sourceFile.openSync(mode: io.FileMode.read);
  StreamController<Uint8List> controller = StreamController();

  final s = sodium.crypto.secretStream
      .createPull(SecureKey.fromList(sodium, key), requireFinalized: false);
  final res = s.bind(controller.stream);

  controller.add(header);

  var bytesRead = 0;
  var stop = false;
  while (!stop) {
    var chunkSize = decryptionChunkSize;
    if (bytesRead + chunkSize >= sourceFileLength) {
      chunkSize = sourceFileLength - bytesRead;
      stop = true;
    }
    final buffer = await inputFile.read(chunkSize);
    bytesRead += chunkSize;
    controller.add(buffer);
  }
  controller.close();
  final result = (await res.toList());

  // Delete the destination file if it exists to avoid appending to old data
  if (await destinationFile.exists()) {
    await destinationFile.delete();
  }

  for (final data in result) {
    await destinationFile.writeAsBytes(data, mode: io.FileMode.append);
  }
  inputFile.closeSync();

  logger.info(
    "ChaCha20 Decryption time: ${DateTime.now().millisecondsSinceEpoch - decryptionStartTime}",
  );
}

Future<Uint8List> chachaDecryptData(
    Uint8List source,
    Uint8List key,
    Uint8List header,
    Sodium sodium, {
    Uint8List? nonce,
  }) async {
  StreamController<Uint8List> controller = StreamController();

  final s = sodium.crypto.secretStream
      .createPull(SecureKey.fromList(sodium, key), requireFinalized: false);
  final res = s.bind(controller.stream);

  controller.add(header);

  // For backward compatibility: if nonce is provided, concatenate it to source.
  // Old implementation incorrectly stored the final authentication block as "nonce".
  if (nonce != null && nonce.isNotEmpty) {
    final combined = Uint8List.fromList([...source, ...nonce]);
    controller.add(combined);
  } else {
    controller.add(source);
  }

  controller.close();

  return (await res.toList()).reduce((a, b) => Uint8List.fromList(
        a.toList()..addAll(b.toList()),
      ));
}

// Encrypts a file with MD5 calculation and real-time verification
Future<FileEncryptResult> chachaEncryptFileWithVerification(
  String sourceFilePath,
  String destinationFilePath,
  Uint8List? skey,
  int? multiPartChunkSizeInBytes,
  Sodium sodium,
) async {
  final encryptionStartTime = DateTime.now();
  final logger = Logger('ChaChaEncryptWithMD5');
  final sourceFile = io.File(sourceFilePath);
  final destinationFile = io.File(destinationFilePath);
  final sourceFileLength = await sourceFile.length();

  // Delete the destination file if it exists to avoid appending to old data
  if (await destinationFile.exists()) {
    await destinationFile.delete();
  }

  logger.info('Encrypting file of size $sourceFileLength');
  if (multiPartChunkSizeInBytes != null) {
    logger.info('Using multipart chunk size: $multiPartChunkSizeInBytes bytes');
  }

  final inputFile = sourceFile.openSync(mode: io.FileMode.read);

  final key = skey ?? sodium.crypto.secretStream.keygen().extractBytes();
  final pushState = sodium.crypto.secretStream.createPushEx(
    SecureKey.fromList(sodium, key),
  );

  // Create controllers for streaming encryption
  StreamController<SecretStreamPlainMessage> pushController =
      StreamController();
  final encryptedStream = pushState.bind(pushController.stream);

  // MD5 setup
  AccumulatorSink<Digest>? fullAccumulator;
  ChunkedConversionSink<List<int>>? fullMd5Sink;
  AccumulatorSink<Digest>? partAccumulator;
  ChunkedConversionSink<List<int>>? partMd5Sink;

  final List<String> partMd5s = [];
  final BytesBuilder partBuffer = BytesBuilder();

  if (multiPartChunkSizeInBytes == null) {
    fullAccumulator = AccumulatorSink<Digest>();
    fullMd5Sink = md5.startChunkedConversion(fullAccumulator);
  } else {
    partAccumulator = AccumulatorSink<Digest>();
    partMd5Sink = md5.startChunkedConversion(partAccumulator);
  }

  var bytesRead = 0;
  var chunkIndex = 0;

  try {
    // Read and add all chunks to the controller
    var stop = false;
    while (!stop) {
      var chunkSize = encryptionChunkSize;
      if (bytesRead + chunkSize >= sourceFileLength) {
        chunkSize = sourceFileLength - bytesRead;
        stop = true;
      }

      final buffer = await inputFile.read(chunkSize);
      if (buffer.length != chunkSize) {
        throw Exception(
          'Failed to read $chunkSize bytes, but got ${buffer.length} bytes',
        );
      }

      bytesRead += chunkSize;
      pushController.add(
        SecretStreamPlainMessage(
          buffer,
          tag: stop
              ? SecretStreamMessageTag.finalPush
              : SecretStreamMessageTag.push,
        ),
      );
    }
    pushController.close();
    await inputFile.close();

    // Collect all encrypted outputs
    final encryptedResults = await encryptedStream.toList();

    // First output is the header
    if (encryptedResults.isEmpty) {
      throw Exception('No encrypted data produced');
    }

    final header = encryptedResults[0].message;
    logger.info(
        'Header extracted, ${encryptedResults.length - 1} encrypted chunks');

    // Write encrypted chunks to file and calculate MD5
    var totalEncryptedBytes = 0;
    for (int i = 1; i < encryptedResults.length; i++) {
      final encryptedChunk = encryptedResults[i].message;
      totalEncryptedBytes += encryptedChunk.length;

      if (multiPartChunkSizeInBytes == null) {
        // Single-part: calculate full file MD5 and write directly
        fullMd5Sink!.add(encryptedChunk);
        await destinationFile.writeAsBytes(
          encryptedChunk,
          mode: io.FileMode.append,
        );
      } else {
        // Multi-part: buffer data and flush at exact part boundaries
        partBuffer.add(encryptedChunk);

        // Flush complete parts from buffer
        while (partBuffer.length >= multiPartChunkSizeInBytes) {
          final partBytes =
              partBuffer.toBytes().sublist(0, multiPartChunkSizeInBytes);

          // Calculate MD5 for this part
          partMd5Sink!.add(partBytes);
          partMd5Sink.close();
          final digest = partAccumulator!.events.single;
          partMd5s.add(base64.encode(digest.bytes));

          logger.info(
            'Part ${partMd5s.length}: $multiPartChunkSizeInBytes bytes',
          );

          // Write to disk
          await destinationFile.writeAsBytes(
            partBytes,
            mode: io.FileMode.append,
          );

          // Keep remaining bytes for next part
          final remaining =
              partBuffer.toBytes().sublist(multiPartChunkSizeInBytes);
          partBuffer.clear();
          partBuffer.add(remaining);

          // Start new MD5 for next part
          partAccumulator = AccumulatorSink<Digest>();
          partMd5Sink = md5.startChunkedConversion(partAccumulator);
        }

        // Handle last chunk (remaining data < partSize)
        if (i == encryptedResults.length - 1 && partBuffer.isNotEmpty) {
          final lastPartBytes = partBuffer.toBytes();

          // Calculate MD5 for last part
          partMd5Sink!.add(lastPartBytes);
          partMd5Sink.close();
          final digest = partAccumulator!.events.single;
          partMd5s.add(base64.encode(digest.bytes));

          // Write to disk
          await destinationFile.writeAsBytes(
            lastPartBytes,
            mode: io.FileMode.append,
          );
          partBuffer.clear();
        }
      }
    }

    // Finalize MD5
    String? finalFileMd5;
    if (multiPartChunkSizeInBytes == null && fullMd5Sink != null) {
      fullMd5Sink.close();
      final digest = fullAccumulator!.events.single;
      finalFileMd5 = base64.encode(digest.bytes);
      logger.info('File MD5: $finalFileMd5');
    }

    final encryptionTimeSeconds = (DateTime.now().millisecondsSinceEpoch -
            encryptionStartTime.millisecondsSinceEpoch) /
        1000;
    final partsInfo =
        multiPartChunkSizeInBytes != null ? ' Parts: ${partMd5s.length}' : '';
    logger.info(
      'FileEncryption: Time: ${encryptionTimeSeconds}s '
      'Total encrypted: $totalEncryptedBytes bytes$partsInfo',
    );

    return FileEncryptResult(
      key: key,
      header: header,
      fileMd5: finalFileMd5,
      partMd5s: multiPartChunkSizeInBytes != null && partMd5s.isNotEmpty
          ? partMd5s
          : null,
      partSize: multiPartChunkSizeInBytes,
    );
  } catch (e) {
    try {
      await inputFile.close();
    } catch (_) {}
    if (await destinationFile.exists()) {
      try {
        await destinationFile.delete();
      } catch (_) {}
    }
    rethrow;
  }
}

// Fast equality check for Uint8List
bool _uint8listEquals(Uint8List a, Uint8List b) {
  if (identical(a, b)) return true;
  if (a.length != b.length) return false;

  final len = a.length;
  int i = 0;

  // Compare 8 bytes at a time for speed
  while (i + 7 < len) {
    final va =
        a.buffer.asByteData().getUint64(a.offsetInBytes + i, Endian.little);
    final vb =
        b.buffer.asByteData().getUint64(b.offsetInBytes + i, Endian.little);
    if (va != vb) return false;
    i += 8;
  }

  // Remaining bytes
  while (i < len) {
    if (a[i] != b[i]) return false;
    i++;
  }

  return true;
}

class CryptoUtil {
  static Future<void> init() async {
    try {
      sodium = await SodiumPlatform.instance.loadSodiumSumo();
    } catch (e, s) {
      Logger("CryptoUtil").severe("Failed to load sodium", e, s);
      rethrow;
    }
  }

  static Uint8List strToBin(String str) {
    return Uint8List.fromList(str.codeUnits);
  }

  static Uint8List base642bin(String b64) {
    return base64.decode(b64);
  }

  static String bin2base64(
    Uint8List bin, {
    bool urlSafe = false,
  }) {
    if (urlSafe) {
      return base64UrlEncode(bin);
    } else {
      return base64.encode(bin);
    }
  }

  static String bin2hex(Uint8List bin) {
    return bin.map((e) => e.toRadixString(16).padLeft(2, '0')).join();
  }

  static Uint8List hex2bin(String hex) {
    // Convert pairs of hex characters to code units
    final codeUnits = hex
        .replaceAllMapped(RegExp(r".{2}"), (match) => "${match.group(0)},")
        .split(",")
        .where((e) => e.isNotEmpty)
        .map((hexPair) => int.parse(hexPair, radix: 16))
        .toList();

    // Convert the code units to a string
    return Uint8List.fromList(codeUnits);
  }

  // Encrypts the given source, with the given key and a randomly generated
  // nonce, using XSalsa20 (w Poly1305 MAC).
  // This function runs on the same thread as the caller, so should be used only
  // for small amounts of data where thread switching can result in a degraded
  // user experience
  static EncryptionResult encryptSync(Uint8List source, Uint8List key) {
    final nonce = sodium.randombytes.buf(sodium.crypto.secretBox.nonceBytes);

    final encryptedData = cryptoSecretboxEasy(source, nonce, key);
    return EncryptionResult(
      key: key,
      nonce: nonce,
      encryptedData: encryptedData,
    );
  }

  // Decrypts the given cipher, with the given key and nonce using XSalsa20
  // (w Poly1305 MAC).
  static Future<Uint8List> decrypt(
    Uint8List cipher,
    Uint8List key,
    Uint8List nonce,
  ) async {
    return sodium.runIsolated(
      (sodium, secureKeys, keyPairs) =>
          cryptoSecretboxOpenEasy(cipher, key, nonce, sodium),
    );
  }

  // Decrypts the given cipher, with the given key and nonce using XSalsa20
  // (w Poly1305 MAC).
  // This function runs on the same thread as the caller, so should be used only
  // for small amounts of data where thread switching can result in a degraded
  // user experience
  static Uint8List decryptSync(
    Uint8List cipher,
    Uint8List key,
    Uint8List nonce,
  ) {
    return cryptoSecretboxOpenEasy(cipher, key, nonce, sodium);
  }

  // Encrypts the given source, with the given key and a randomly generated
  // nonce, using XChaCha20 (w Poly1305 MAC).
  static Future<EncryptionResult> encryptData(
    Uint8List source,
    Uint8List key,
  ) async {
    return await sodium.runIsolated(
      (sodium, secureKeys, keyPairs) => chachaEncryptData(source, key, sodium),
    );
  }

  // Decrypts the given source, with the given key and header using XChaCha20
  // (w Poly1305 MAC).
  // For backward compatibility, accepts optional nonce parameter which was used
  // in older implementation to store the final authentication block separately.
  static Future<Uint8List> decryptData(
    Uint8List source,
    Uint8List key,
    Uint8List header, {
    Uint8List? nonce,
  }) async {
    return await sodium.runIsolated((sodium, secureKeys, keyPairs) =>
        chachaDecryptData(source, key, header, sodium, nonce: nonce));
  }

  // Encrypts the file at sourceFilePath, with the key (if provided) and a
  // randomly generated nonce using XChaCha20 (w Poly1305 MAC), and writes it
  // to the destinationFilePath.
  // If a key is not provided, one is generated and returned.
  static Future<EncryptionResult> encryptFile(
    String sourceFilePath,
    String destinationFilePath, {
    Uint8List? key,
  }) {
    return sodium.runIsolated((sodium, secureKeys, keyPairs) =>
        chachaEncryptFile(sourceFilePath, destinationFilePath, key, sodium));
  }

  // Encrypts the file with MD5 calculation and real-time verification
  static Future<FileEncryptResult> encryptFileWithMD5(
    String sourceFilePath,
    String destinationFilePath, {
    Uint8List? key,
    int? multiPartChunkSizeInBytes,
  }) {
    return sodium.runIsolated(
      (sodium, secureKeys, keyPairs) => chachaEncryptFileWithVerification(
        sourceFilePath,
        destinationFilePath,
        key,
        multiPartChunkSizeInBytes,
        sodium,
      ),
    );
  }

  // Decrypts the file at sourceFilePath, with the given key and header using
  // XChaCha20 (w Poly1305 MAC), and writes it to the destinationFilePath.
  static Future<void> decryptFile(
    String sourceFilePath,
    String destinationFilePath,
    Uint8List header,
    Uint8List key,
  ) {
    return sodium.runIsolated(
      (sodium, secureKeys, keyPairs) => chachaDecryptFile(
          sourceFilePath, destinationFilePath, header, key, sodium),
    );
  }

  // Generates and returns a 256-bit key.
  static Uint8List generateKey() {
    return sodium.crypto.secretBox.keygen().extractBytes();
  }

  // Generates and returns a random byte buffer of length
  // crypto_pwhash_SALTBYTES (16)
  static Uint8List getSaltToDeriveKey() {
    return sodium.randombytes.buf(sodium.crypto.pwhash.saltBytes);
  }

  // Generates and returns a secret key and the corresponding public key.
  static KeyPair generateKeyPair() {
    return sodium.crypto.box.keyPair();
  }

  // Decrypts the input using the given publicKey-secretKey pair
  static Uint8List openSealSync(
    Uint8List input,
    Uint8List publicKey,
    Uint8List secretKey,
  ) {
    return sodium.crypto.box.sealOpen(
      cipherText: input,
      publicKey: publicKey,
      secretKey: SecureKey.fromList(sodium, secretKey),
    );
  }

  // Encrypts the input using the given publicKey
  static Uint8List sealSync(Uint8List input, Uint8List publicKey) {
    return sodium.crypto.box.seal(message: input, publicKey: publicKey);
  }

  // Derives a key for a given password and salt using Argon2id, v1.3.
  // The function first attempts to derive a key with both memLimit and opsLimit
  // set to their Sensitive variants.
  // If this fails, say on a device with insufficient RAM, we retry by halving
  // the memLimit and doubling the opsLimit, while ensuring that we stay within
  // the min and max limits for both parameters.
  // At all points, we ensure that the product of these two variables (the area
  // under the graph that determines the amount of work required) is a constant.
  static Future<DerivedKeyResult> deriveSensitiveKey(
    Uint8List password,
    Uint8List salt,
  ) async {
    final logger = Logger("pwhash");
    final int desiredStrength = sodium.crypto.pwhash.memLimitSensitive *
        sodium.crypto.pwhash.opsLimitSensitive;

    // When sensitive memLimit (1 GB) is used, on low spec device the OS might
    // kill the app with OOM. To avoid that, start with 256 MB and
    // corresponding ops limit (16).
    // This ensures that the product of these two variables
    // (the area under the graph that determines the amount of work required)
    // stays the same
    // SODIUM_CRYPTO_PWHASH_MEMLIMIT_SENSITIVE: 1073741824
    // SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE: 268435456
    // SODIUM_CRYPTO_PWHASH_OPSLIMIT_SENSITIVE: 4
    int memLimit = sodium.crypto.pwhash.memLimitModerate;
    final factor = sodium.crypto.pwhash.memLimitSensitive ~/
        sodium.crypto.pwhash.memLimitModerate; // = 4
    int opsLimit = sodium.crypto.pwhash.opsLimitSensitive * factor; // = 16

    if (memLimit * opsLimit != desiredStrength) {
      throw UnsupportedError(
        "unexpcted values for memLimit $memLimit and opsLimit: $opsLimit",
      );
    }
    Uint8List key;
    while (memLimit >= sodium.crypto.pwhash.memLimitMin &&
        opsLimit <= sodium.crypto.pwhash.opsLimitMax) {
      try {
        key = await deriveKey(password, salt, memLimit, opsLimit);
        return DerivedKeyResult(key, memLimit, opsLimit);
      } catch (e, s) {
        logger.warning(
          "failed to deriveKey mem: $memLimit, ops: $opsLimit",
          e,
          s,
        );
      }
      memLimit = (memLimit / 2).round();
      opsLimit = opsLimit * 2;
    }
    throw UnsupportedError("Cannot perform this operation on this device");
  }

  // Derives a key for the given password and salt, using Argon2id, v1.3
  // with memory and ops limit hardcoded to their Interactive variants
  // NOTE: This is only used while setting passwords for shared links, as an
  // extra layer of authentication (atop the access token and collection key).
  // More details @ https://ente.io/blog/building-shareable-links/
  static Future<DerivedKeyResult> deriveInteractiveKey(
    Uint8List password,
    Uint8List salt,
  ) async {
    final int memLimit = sodium.crypto.pwhash.memLimitInteractive;
    final int opsLimit = sodium.crypto.pwhash.opsLimitInteractive;
    final key = await deriveKey(password, salt, memLimit, opsLimit);
    return DerivedKeyResult(key, memLimit, opsLimit);
  }

  // Derives a key for a given password, salt, memLimit and opsLimit using
  // Argon2id, v1.3.
  static Future<Uint8List> deriveKey(
    Uint8List password,
    Uint8List salt,
    int memLimit,
    int opsLimit,
  ) async {
    try {
      return await sodium.runIsolated(
        (sodium, secureKeys, keyPairs) =>
            cryptoPwHash(password, salt, memLimit, opsLimit, sodium),
      );
    } catch (e, s) {
      final String errMessage = 'failed to deriveKey memLimit: $memLimit and '
          'opsLimit: $opsLimit';
      Logger("CryptoUtilDeriveKey").warning(errMessage, e, s);
      throw KeyDerivationError();
    }
  }

  // derives a Login key as subKey from the given key by applying KDF
  // (Key Derivation Function) with the `loginSubKeyId` and
  // `loginSubKeyLen` and `loginSubKeyContext` as context
  static Future<Uint8List> deriveLoginKey(
    Uint8List key,
  ) async {
    try {
      final Uint8List derivedKey = await sodium.runIsolated(
        (sodium, secureKeys, keyPairs) => cryptoKdfDeriveFromKey(
            key, loginSubKeyId, loginSubKeyLen, loginSubKeyContext, sodium),
      );

      return derivedKey.sublist(0, 16);
    } catch (e, s) {
      Logger("deriveLoginKey").severe("loginKeyDerivation failed", e, s);
      throw LoginKeyDerivationError();
    }
  }
}
