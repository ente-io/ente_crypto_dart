import 'dart:async';
import 'dart:convert';
import 'dart:io' as io;
import 'dart:developer';
import 'dart:typed_data';

import 'package:ente_crypto_dart/src/core/errors.dart';
import 'package:ente_crypto_dart/src/models/derived_key_result.dart';
import 'package:ente_crypto_dart/src/models/device_info.dart';
import 'package:ente_crypto_dart/src/models/encryption_result.dart';
import 'package:logging/logging.dart';
import 'package:rxdart/rxdart.dart';
import 'package:sodium/sodium_sumo.dart';
import 'package:sodium_libs/sodium_libs.dart';

export 'core/errors.dart';

const int encryptionChunkSize = 4 * 1024 * 1024;
const int hashChunkSize = 4 * 1024 * 1024;
const int loginSubKeyLen = 32;
const int loginSubKeyId = 1;
const String loginSubKeyContext = "loginctx";
late SodiumSumo sodium;

class CryptoUtil {
  static final int decryptionChunkSize =
      encryptionChunkSize + sodium.crypto.secretStream.aBytes;

  static Future<void> init() async {
    try {
      sodium = await SodiumPlatform.instance.loadSodiumSumo();
    } catch (e) {
      log(e.toString());
    }
  }

  static Uint8List strToBin(String str) {
    return Uint8List.fromList(str.codeUnits);
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

  static EncryptionResult encryptSync(Uint8List source, Uint8List key) {
    final nonce = sodium.randombytes.buf(sodium.crypto.secretBox.nonceBytes);

    final encryptedData = cryptoSecretboxEasy(source, nonce, key);
    return EncryptionResult(
      key: key,
      nonce: nonce,
      encryptedData: encryptedData,
    );
  }

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

  static Uint8List decryptSync(
    Uint8List cipher,
    Uint8List key,
    Uint8List nonce,
  ) {
    return cryptoSecretboxOpenEasy(cipher, key, nonce, sodium);
  }

  static Future<EncryptionResult> encryptData(
    Uint8List source,
    Uint8List key,
  ) async {
    return await sodium.runIsolated(
      (sodium, secureKeys, keyPairs) => chachaEncryptData(source, key, sodium),
    );
  }

  static Future<Uint8List> decryptData(
    Uint8List source,
    Uint8List key,
    Uint8List header,
  ) async {
    return await sodium.runIsolated((sodium, secureKeys, keyPairs) =>
        chachaDecryptData(source, key, header, sodium));
  }

  static Future<EncryptionResult> encryptFile(
    String sourceFilePath,
    String destinationFilePath, {
    Uint8List? key,
  }) {
    return sodium.runIsolated((sodium, secureKeys, keyPairs) =>
        chachaEncryptFile(sourceFilePath, destinationFilePath, key, sodium));
  }

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

  static Uint8List generateKey() {
    return sodium.crypto.secretBox.keygen().extractBytes();
  }

  static Uint8List getSaltToDeriveKey() {
    return sodium.randombytes.buf(sodium.crypto.pwhash.saltBytes);
  }

  static KeyPair generateKeyPair() {
    return sodium.crypto.box.keyPair();
  }

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

  static Uint8List sealSync(Uint8List input, Uint8List publicKey) {
    return sodium.crypto.box.seal(message: input, publicKey: publicKey);
  }

  static Future<DerivedKeyResult> deriveSensitiveKey(
    Uint8List password,
    Uint8List salt,
  ) async {
    final logger = Logger("pwhash");
    int memLimit = sodium.crypto.pwhash.memLimitSensitive;
    int opsLimit = sodium.crypto.pwhash.opsLimitSensitive;
    if (await isLowSpecDevice()) {
      logger.info("low spec device detected");

      memLimit = sodium.crypto.pwhash.memLimitModerate;
      final factor = sodium.crypto.pwhash.memLimitSensitive ~/
          sodium.crypto.pwhash.memLimitModerate;
      opsLimit = opsLimit * factor;
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

  static Future<DerivedKeyResult> deriveInteractiveKey(
    Uint8List password,
    Uint8List salt,
  ) async {
    final int memLimit = sodium.crypto.pwhash.memLimitInteractive;
    final int opsLimit = sodium.crypto.pwhash.opsLimitInteractive;
    final key = await deriveKey(password, salt, memLimit, opsLimit);
    return DerivedKeyResult(key, memLimit, opsLimit);
  }

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

  static Future<Uint8List> getHash(io.File source) {
    return sodium.runIsolated(
      (sodium, secureKeys, keyPairs) => cryptoGenericHash(source.path, sodium),
    );
  }

  static Uint8List cryptoSecretboxEasy(
      Uint8List source, Uint8List nonce, Uint8List key) {
    return sodium.crypto.secretBox.easy(
        message: source, nonce: nonce, key: SecureKey.fromList(sodium, key));
  }

  static Uint8List randomKey([int length = 32]) {
    return SecureKey.random(sodium, length).extractBytes();
  }

  static Uint8List cryptoSecretboxOpenEasy(
      Uint8List cipher, Uint8List key, Uint8List nonce, Sodium sodium) {
    return sodium.crypto.secretBox.openEasy(
      cipherText: cipher,
      nonce: nonce,
      key: SecureKey.fromList(sodium, key),
    );
  }

  static Uint8List cryptoPwHash(Uint8List password, Uint8List salt,
      int memLimit, int opsLimit, dynamic sodium) {
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

  static Uint8List cryptoKdfDeriveFromKey(
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

  static Future<Uint8List> cryptoGenericHash(
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

  static Future<EncryptionResult> chachaEncryptData(
      Uint8List source, Uint8List key, Sodium sodium) async {
    StreamController<Uint8List> controller = StreamController();

    final s = sodium.crypto.secretStream.createPush(
      SecureKey.fromList(sodium, key),
    );

    controller.add(source);
    final res = s.bind(controller.stream);
    controller.close();

    List<Uint8List> encBytes = await res.toList();
    return EncryptionResult(
      encryptedData: encBytes[1],
      header: encBytes[0],
      nonce: encBytes[2],
    );
  }

  static Future<EncryptionResult> chachaEncryptFile(
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
    final key = SecureKey.fromList(
        sodium, skey ?? sodium.crypto.secretStream.keygen().extractBytes());

    final controller = StreamController<Uint8List>();
    final encryptedData = sodium.crypto.secretStream.push(
      key: key,
      messageStream: controller.stream,
    );

    StreamController<Uint8List> consumer = StreamController();
    final Stream<List<int>> source = sourceFile
        .openRead()
        .expand((bytes) => bytes)
        .bufferCount(encryptionChunkSize);
    await source
        .map<Uint8List>((chunk) {
          return Uint8List.fromList(chunk);
        })
        .transform(sodium.crypto.secretStream.createPush(key))
        .pipe(consumer);

    final destinationFileSink = destinationFile.openWrite();
    await consumer.stream.forEach((chunk) {
      destinationFileSink.add(chunk);
    });
    await destinationFileSink.close();
    await consumer.close();
    await inputFile.close();

    logger.info(
      "Encryption time: ${DateTime.now().millisecondsSinceEpoch - encryptionStartTime}",
    );

    return EncryptionResult(
      key: key.extractBytes(),
      header: await encryptedData.first,
    );
  }

  static Future<void> chachaDecryptFile(
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

    final inputFile = sourceFile.openSync(mode: io.FileMode.read);

    final consumer = StreamController<List<int>>();

    final Stream<List<int>> source = sourceFile
        .openRead()
        .expand((bytes) => bytes)
        .bufferCount(100 + sodium.crypto.secretStream.aBytes);
    await source
        .map<Uint8List>((chunk) => Uint8List.fromList(chunk))
        .transform(sodium.crypto.secretStream
            .createPull(SecureKey.fromList(sodium, key)))
        .cast<List<int>>()
        .pipe(consumer);

    final destinationFileSink = destinationFile.openWrite();
    await consumer.stream.forEach((chunk) {
      destinationFileSink.add(chunk);
    });
    await destinationFileSink.close();
    await consumer.close();
    inputFile.closeSync();

    logger.info(
      "ChaCha20 Decryption time: ${DateTime.now().millisecondsSinceEpoch - decryptionStartTime}",
    );
  }

  static Future<Uint8List> chachaDecryptData(
      Uint8List source, Uint8List key, Uint8List header, Sodium sodium) async {
    StreamController<Uint8List> controller = StreamController();

    final s = sodium.crypto.secretStream
        .createPull(SecureKey.fromList(sodium, key), requireFinalized: false);
    final res = s.bind(controller.stream);

    controller.add(header);
    controller.add(source);

    controller.close();

    return (await res.toList()).reduce((a, b) => Uint8List.fromList(
          a.toList()..addAll(b.toList()),
        ));
  }
}
