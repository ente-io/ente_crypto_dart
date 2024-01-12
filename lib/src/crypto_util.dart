import 'dart:convert';
import 'dart:io' as io;
import 'dart:typed_data';

import 'package:computer/computer.dart';
import 'package:ente_crypto_dart/src/core/errors.dart';
import 'package:ente_crypto_dart/src/models/derived_key_result.dart';
import 'package:ente_crypto_dart/src/models/device_info.dart';
import 'package:ente_crypto_dart/src/models/encryption_result.dart';
import 'package:logging/logging.dart';
import 'package:sodium/sodium_sumo.dart';
import 'package:sodium_libs/sodium_libs.dart';

const int encryptionChunkSize = 4 * 1024 * 1024;
const int hashChunkSize = 4 * 1024 * 1024;
const int loginSubKeyLen = 32;
const int loginSubKeyId = 1;
const String loginSubKeyContext = "loginctx";

class CryptoUtil {
  // Note: workers are turned on during app startup.
  static final Computer _computer = Computer.shared();

  static late SodiumSumo sodium;
  static final int decryptionChunkSize =
      encryptionChunkSize + sodium.crypto.secretStream.aBytes;

  static init() async {
    sodium = await SodiumPlatform.instance.loadSodiumSumo();
  }

  static Uint8List base642bin(String b64) {
    return base64.decode(b64);
  }

  static String bin2base64(Uint8List bin) {
    return base64.encode(bin);
  }

  static String bin2hex(Uint8List bin) {
    return bin.map((e) => e.toRadixString(16).padLeft(2, '0')).join();
  }

  static Uint8List hex2bin(String hex) {
    return Uint8List.fromList(
      hex.split('').map((e) {
        return int.parse(e, radix: 16);
      }).toList(),
    );
  }

  // Encrypts the given source, with the given key and a randomly generated
  // nonce, using XSalsa20 (w Poly1305 MAC).
  // This function runs on the same thread as the caller, so should be used only
  // for small amounts of data where thread switching can result in a degraded
  // user experience
  static EncryptionResult encryptSync(Uint8List source, Uint8List key) {
    final nonce = sodium.randombytes.buf(sodium.crypto.secretBox.nonceBytes);

    final args = <String, dynamic>{};
    args["source"] = source;
    args["nonce"] = nonce;
    args["key"] = key;
    final encryptedData = cryptoSecretboxEasy(args);
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
    final args = <String, dynamic>{};
    args["cipher"] = cipher;
    args["nonce"] = nonce;
    args["key"] = key;
    return _computer.compute(
      cryptoSecretboxOpenEasy,
      param: args,
      taskName: "decrypt",
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
    final args = <String, dynamic>{};
    args["cipher"] = cipher;
    args["nonce"] = nonce;
    args["key"] = key;
    return cryptoSecretboxOpenEasy(args);
  }

  // Encrypts the given source, with the given key and a randomly generated
  // nonce, using XChaCha20 (w Poly1305 MAC).
  // This function runs on the isolate pool held by `_computer`.
  // TODO: Remove "ChaCha", an implementation detail from the function name
  static Future<EncryptionResult> encryptChaCha(
    Uint8List source,
    Uint8List key,
  ) async {
    final args = <String, dynamic>{};
    args["source"] = source;
    args["key"] = key;
    return _computer.compute(
      chachaEncryptData,
      param: args,
      taskName: "encryptChaCha",
    );
  }

  // Decrypts the given source, with the given key and header using XChaCha20
  // (w Poly1305 MAC).
  // TODO: Remove "ChaCha", an implementation detail from the function name
  static Future<Uint8List> decryptChaCha(
    Uint8List source,
    Uint8List key,
    Uint8List header,
  ) async {
    final args = <String, dynamic>{};
    args["source"] = source;
    args["key"] = key;
    args["header"] = header;
    return _computer.compute(
      chachaDecryptData,
      param: args,
      taskName: "decryptChaCha",
    );
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
    final args = <String, dynamic>{};
    args["sourceFilePath"] = sourceFilePath;
    args["destinationFilePath"] = destinationFilePath;
    args["key"] = key;
    return _computer.compute(
      chachaEncryptFile,
      param: args,
      taskName: "encryptFile",
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
    final args = <String, dynamic>{};
    args["sourceFilePath"] = sourceFilePath;
    args["destinationFilePath"] = destinationFilePath;
    args["header"] = header;
    args["key"] = key;
    return _computer.compute(
      chachaDecryptFile,
      param: args,
      taskName: "decryptFile",
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
  static Future<KeyPair> generateKeyPair() async {
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
    int memLimit = sodium.crypto.pwhash.memLimitSensitive;
    int opsLimit = sodium.crypto.pwhash.opsLimitSensitive;
    if (await isLowSpecDevice()) {
      logger.info("low spec device detected");
      // When sensitive memLimit (1 GB) is used, on low spec device the OS might
      // kill the app with OOM. To avoid that, start with 256 MB and
      // corresponding ops limit (16).
      // This ensures that the product of these two variables
      // (the area under the graph that determines the amount of work required)
      // stays the same
      // SODIUM_CRYPTO_PWHASH_MEMLIMIT_SENSITIVE: 1073741824
      // SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE: 268435456
      // SODIUM_CRYPTO_PWHASH_OPSLIMIT_SENSITIVE: 4
      memLimit = sodium.crypto.pwhash.memLimitModerate;
      final factor = sodium.crypto.pwhash.memLimitSensitive ~/
          sodium.crypto.pwhash.memLimitModerate; // = 4
      opsLimit = opsLimit * factor; // = 16
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
      return await _computer.compute(
        cryptoPwHash,
        param: {
          "password": password,
          "salt": salt,
          "memLimit": memLimit,
          "opsLimit": opsLimit,
        },
        taskName: "deriveKey",
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
      final Uint8List derivedKey = await _computer.compute(
        cryptoKdfDeriveFromKey,
        param: {
          "key": key,
          "subkeyId": loginSubKeyId,
          "subkeyLen": loginSubKeyLen,
          "context": utf8.encode(loginSubKeyContext),
        },
        taskName: "deriveLoginKey",
      );
      // return the first 16 bytes of the derived key
      return derivedKey.sublist(0, 16);
    } catch (e, s) {
      Logger("deriveLoginKey").severe("loginKeyDerivation failed", e, s);
      throw LoginKeyDerivationError();
    }
  }

  // Computes and returns the hash of the source file
  static Future<Uint8List> getHash(io.File source) {
    return _computer.compute(
      cryptoGenericHash,
      param: {
        "sourceFilePath": source.path,
      },
      taskName: "fileHash",
    );
  }

  static Uint8List cryptoSecretboxEasy(Map<String, dynamic> args) {
    return sodium.crypto.secretBox
        .easy(message: args["source"], nonce: args["nonce"], key: args["key"]);
  }

  static Uint8List cryptoSecretboxOpenEasy(Map<String, dynamic> args) {
    return sodium.crypto.secretBox.openEasy(
      cipherText: args["cipher"],
      nonce: args["nonce"],
      key: args["key"],
    );
  }

  static Uint8List cryptoPwHash(Map<String, dynamic> args) {
    return sodium.crypto.pwhash
        .call(
          outLen: sodium.crypto.secretBox.keyBytes,
          password: args["password"],
          salt: args["salt"],
          opsLimit: args["opsLimit"],
          memLimit: args["memLimit"],
          alg: CryptoPwhashAlgorithm.argon2id13,
        )
        .extractBytes();
  }

  static Uint8List cryptoKdfDeriveFromKey(
    Map<String, dynamic> args,
  ) {
    return sodium.crypto.kdf
        .deriveFromKey(
          subkeyLen: args["subkeyLen"],
          subkeyId: args["subkeyId"],
          context: args["context"],
          masterKey: args["key"],
        )
        .extractBytes();
  }

// Returns the hash for a given file, chunking it in batches of hashChunkSize
  static Future<Uint8List> cryptoGenericHash(Map<String, dynamic> args) async {
    final sourceFile = io.File(args["sourceFilePath"]);
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

  static Future<EncryptionResult> chachaEncryptData(
    Map<String, dynamic> args,
  ) async {
    final initPushResult = sodium.crypto.secretStream.createPushEx(args["key"]);
    final stream = Stream.value(
      SecretStreamPlainMessage(
        args["source"],
        tag: SecretStreamMessageTag.finalPush,
      ),
    );
    initPushResult.bind(stream);
    final encryptedData = sodium.crypto.secretStream.pushEx(
      key: SecureKey.fromList(sodium, args["key"]),
      messageStream: stream,
    );
    return EncryptionResult(
      encryptedData: (await encryptedData.first).additionalData,
      header: (await encryptedData.first).additionalData,
    );
  }

// Encrypts a given file, in chunks of encryptionChunkSize
  static Future<EncryptionResult> chachaEncryptFile(
    Map<String, dynamic> args,
  ) async {
    final encryptionStartTime = DateTime.now().millisecondsSinceEpoch;
    final logger = Logger("ChaChaEncrypt");
    final sourceFile = io.File(args["sourceFilePath"]);
    final destinationFile = io.File(args["destinationFilePath"]);
    final sourceFileLength = await sourceFile.length();
    logger.info("Encrypting file of size $sourceFileLength");

    final inputFile = sourceFile.openSync(mode: io.FileMode.read);
    final key = args["key"] ?? sodium.crypto.secretStream.keygen();

    final initPushResult = sodium.crypto.secretStream
        .createPushEx(SecureKey.fromList(sodium, key));
    var bytesRead = 0;
    var tag = SecretStreamMessageTag.message;
    late SecretExStream<SecretStreamCipherMessage> encryptedData;
    while (tag != SecretStreamMessageTag.finalPush) {
      var chunkSize = encryptionChunkSize;
      if (bytesRead + chunkSize >= sourceFileLength) {
        chunkSize = sourceFileLength - bytesRead;
        tag = SecretStreamMessageTag.finalPush;
      }
      final buffer = await inputFile.read(chunkSize);
      bytesRead += chunkSize;
      final s = Stream.value(SecretStreamPlainMessage(buffer, tag: tag));
      encryptedData = sodium.crypto.secretStream.pushEx(
        key: SecureKey.fromList(sodium, key),
        messageStream: s,
      );
      initPushResult.bind(s);
      await destinationFile.writeAsBytes(
        (await encryptedData.first).additionalData!.toList(),
        mode: io.FileMode.append,
      );
    }
    await inputFile.close();

    logger.info(
      "Encryption time: ${DateTime.now().millisecondsSinceEpoch - encryptionStartTime}",
    );

    return EncryptionResult(
      key: key,
      header: (await encryptedData.first).additionalData,
    );
  }

  static Future<void> chachaDecryptFile(Map<String, dynamic> args) async {
    final logger = Logger("ChaChaDecrypt");
    final decryptionStartTime = DateTime.now().millisecondsSinceEpoch;
    final sourceFile = io.File(args["sourceFilePath"]);
    final destinationFile = io.File(args["destinationFilePath"]);
    final sourceFileLength = await sourceFile.length();
    logger.info("Decrypting file of size $sourceFileLength");

    final inputFile = sourceFile.openSync(mode: io.FileMode.read);
    final pullState = await sodium.crypto.secretStream
        .pull(
          cipherStream: Stream.value(args["header"] as Uint8List),
          key: SecureKey.fromList(sodium, args["key"]),
        )
        .first;

    var bytesRead = 0;
    var tag = SecretStreamMessageTag.message;
    while (tag != SecretStreamMessageTag.finalPush) {
      var chunkSize = decryptionChunkSize;
      if (bytesRead + chunkSize >= sourceFileLength) {
        chunkSize = sourceFileLength - bytesRead;
      }
      final buffer = await inputFile.read(chunkSize);
      bytesRead += chunkSize;
      final pullResult = await sodium.crypto.secretStream
          .pullEx(
            key: SecureKey.fromList(sodium, pullState),
            cipherStream: Stream.value(SecretStreamCipherMessage(buffer)),
          )
          .first;
      await destinationFile.writeAsBytes(
        pullResult.message,
        mode: io.FileMode.append,
      );
      tag = pullResult.tag;
    }
    inputFile.closeSync();

    logger.info(
      "ChaCha20 Decryption time: ${DateTime.now().millisecondsSinceEpoch - decryptionStartTime}",
    );
  }

  static Future<Uint8List> chachaDecryptData(Map<String, dynamic> args) async {
    final pullState = await sodium.crypto.secretStream
        .pull(
          cipherStream: Stream.value(args["header"]),
          key: SecureKey.fromList(sodium, args["key"] as Uint8List),
        )
        .first;
    final pullResult = await sodium.crypto.secretStream
        .pullEx(
          key: SecureKey.fromList(sodium, pullState),
          cipherStream: Stream.value(
            SecretStreamCipherMessage(
              args["source"],
            ),
          ),
        )
        .first;
    return pullResult.message;
  }
}
