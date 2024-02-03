import 'dart:io';

import 'package:computer/computer.dart';
import 'package:ente_crypto_dart/ente_crypto_dart.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'crypto_dart_2.dart' as fs;

void main() async {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  await CryptoUtil.init();
  Computer.shared().turnOn(workersCount: 4, verbose: kDebugMode);
  await fs.CryptoUtil.init();

  test('decodes base64 string to Uint8List', () {
    const b64 = 'aGVsbG8gd29ybGQ=';
    final expectedBin = CryptoUtil.strToBin('hello world');
    final actualBin = CryptoUtil.base642bin(b64);
    expect(actualBin, equals(expectedBin));
  });

  test('encodes Uint8List to base64 string', () {
    final bin = CryptoUtil.strToBin('hello world');
    const expectedB64 = 'aGVsbG8gd29ybGQ=';
    final actualB64 = CryptoUtil.bin2base64(bin);
    expect(actualB64, equals(expectedB64));
  });

  test('converts Uint8List to hex string', () {
    final bin = CryptoUtil.strToBin('hello world');
    final nowHex = CryptoUtil.bin2hex(bin);
    final nowBin = CryptoUtil.hex2bin(nowHex);
    expect(bin, equals(nowBin));
  });

  test('Encrypt sodium_libs, Decrypt flutter_sodium', () async {
    final source = CryptoUtil.strToBin('Hello, world!');
    final key = CryptoUtil.generateKey();

    final encryptionResult = CryptoUtil.encryptSync(source, key);

    final cipher = encryptionResult.encryptedData;
    final nonce = encryptionResult.nonce;

    final out = await fs.CryptoUtil.decrypt(cipher!, key, nonce!);

    expect(source, equals(out));
  });

  test('throws an error for invalid key length', () {
    // Invalid key length
    final invalidKey = Uint8List(10); // Assuming keyBytes is not 10
    final source = CryptoUtil.strToBin('data');

    expect(() => CryptoUtil.encryptSync(source, invalidKey),
        throwsA(isA<Error>()));
  });

  test('Encrypt flutter_sodium, Decrypt sodium_libs', () async {
    final source = CryptoUtil.strToBin('Hello, world!');
    final key = fs.CryptoUtil.generateKey();

    final encryptionResult = fs.CryptoUtil.encryptSync(source, key);

    final cipher = encryptionResult.encryptedData;
    final nonce = encryptionResult.nonce;

    final out = await CryptoUtil.decrypt(cipher!, key, nonce!);

    expect(source, equals(out));
  });

  test('Encrypt Data', () async {
    final source = CryptoUtil.strToBin('hello world');
    final key = CryptoUtil.strToBin('thisisof32lengthandmustbesecret1');

    final encrypted = await CryptoUtil.encryptData(source, key);
    expect(encrypted.encryptedData, isNotNull);
    expect(encrypted.header, isNotNull);
  });

  test('Decrypt Data', () async {
    final source = CryptoUtil.strToBin('hello world');
    final encryptedData =
        CryptoUtil.base642bin("cmZftCy/74d/J1O2J0Sl9hFUuewRzGQD6R/6vQ==");
    final header = CryptoUtil.base642bin("qgBcUcziMyq15n/YjxIDN1CloyIGH8WT");
    final key = CryptoUtil.strToBin('thisisof32lengthandmustbesecret1');

    final decrypted = await CryptoUtil.decryptData(
      encryptedData,
      key,
      header,
    );

    expect(decrypted, source);
  });

  test('check generated keypair', () async {
    final keyPair = CryptoUtil.generateKeyPair();
    expect(keyPair.publicKey, isNotNull);
    expect(keyPair.secretKey, isNotNull);
  });

  test('test salt to derive key', () {
    final result = CryptoUtil.getSaltToDeriveKey();
    expect(result, isNotNull);
  });

  test('openSealSync decrypts ciphertextfrom sodium_libs correctly', () async {
    final keyPair = CryptoUtil.generateKeyPair();
    final publicKey = keyPair.publicKey;
    final secretKey = keyPair.secretKey.extractBytes();
    final message = CryptoUtil.strToBin('Hello, world!');
    final cipherText = CryptoUtil.sealSync(message, publicKey);

    final decryptedMessage =
        fs.CryptoUtil.openSealSync(cipherText, publicKey, secretKey);

    expect(decryptedMessage, equals(message));
  });
  test('openSealSync decrypts ciphertext from flutter_sodium correctly',
      () async {
    final keyPair = CryptoUtil.generateKeyPair();
    final publicKey = keyPair.publicKey;
    final secretKey = keyPair.secretKey.extractBytes();
    final message = CryptoUtil.strToBin('Hello, world!');
    final cipherText = fs.CryptoUtil.sealSync(message, publicKey);

    final decryptedMessage =
        CryptoUtil.openSealSync(cipherText, publicKey, secretKey);

    expect(decryptedMessage, equals(message));
  });

  test('openSealSync throws SodiumException if secretKey is invalid', () async {
    final keyPair = CryptoUtil.generateKeyPair();
    final publicKey = keyPair.publicKey;
    final message = CryptoUtil.strToBin('Hello, world!');
    final cipherText = CryptoUtil.sealSync(message, publicKey);

    // Invalid secretKey
    final invalidSecretKey = Uint8List(sodium.crypto.box.secretKeyBytes);

    expect(
        () => CryptoUtil.openSealSync(cipherText, publicKey, invalidSecretKey),
        throwsA(isA<SodiumException>()));
  });

  test('succeeds with default memLimit and opsLimit on high-spec device',
      () async {
    final password = CryptoUtil.strToBin('password');
    final salt = CryptoUtil.strToBin('thisisof16length');
    final result = await CryptoUtil.deriveSensitiveKey(password, salt);

    expect(result.key, isNotNull);
    expect(result.memLimit, sodium.crypto.pwhash.memLimitSensitive);
    expect(result.opsLimit, sodium.crypto.pwhash.opsLimitSensitive);
  });

  test('succeeds with adjusted limits on low-spec device', () async {
    if (await isLowSpecDevice()) {
      final password = CryptoUtil.strToBin('password');
      final salt = CryptoUtil.strToBin('thisisof16length');
      final result = await CryptoUtil.deriveSensitiveKey(password, salt);

      expect(result.key, isNotNull);
      expect(result.memLimit, sodium.crypto.pwhash.memLimitModerate);
      expect(result.opsLimit, 16);
    }
  });

  test('throws UnsupportedError if all attempts fail', () async {
    expect(CryptoUtil.deriveSensitiveKey(Uint8List(0), Uint8List(0)),
        throwsUnsupportedError);
  });

  test('derives a key with the correct parameters', () async {
    final password = CryptoUtil.strToBin('password');
    final salt = CryptoUtil.strToBin('thisisof16length');

    final result = await CryptoUtil.deriveInteractiveKey(password, salt);

    expect(result.key, isNotNull);
    expect(result.key.length, greaterThan(0));
    expect(result.memLimit, equals(sodium.crypto.pwhash.memLimitInteractive));
    expect(result.opsLimit, equals(sodium.crypto.pwhash.opsLimitInteractive));
  });

  test('throws an KeyDerivationError if password is null', () async {
    final salt = CryptoUtil.strToBin('salt456');

    expect(
        () async => await CryptoUtil.deriveInteractiveKey(Uint8List(0), salt),
        throwsA(isA<KeyDerivationError>()));
  });

  test('throws an ArgumentError if salt is null', () async {
    final password = CryptoUtil.strToBin('password123');

    expect(
        () async =>
            await CryptoUtil.deriveInteractiveKey(password, Uint8List(0)),
        throwsA(isA<KeyDerivationError>()));
  });

  test('derives a login key with the correct parameters', () async {
    final key = CryptoUtil.generateKey();

    final derivedKey = await CryptoUtil.deriveLoginKey(key);

    expect(derivedKey, isNotNull);
    expect(derivedKey.length, equals(16)); // Ensures expected length
  });

  test('throws a LoginKeyDerivationError if key derivation fails', () async {
    expect(() async => await CryptoUtil.deriveLoginKey(Uint8List(0)),
        throwsA(isA<LoginKeyDerivationError>()));
  });

  test('calculates the hash of a file correctly', () async {
    final testFile =
        File('test_file.txt'); // Create a test file with known content
    await testFile.writeAsString('test content');

    final hash = await getHash(testFile);

    expect(hash, isNotNull);
    expect(hash.length,
        equals(sodium.crypto.genericHash.bytesMax)); // Verify hash length
    // Compare the hash with the expected value for the test content
    expect(hash.length, equals(64));
  });

  test('throws an error if the file does not exist', () async {
    final nonExistentFile = File('non_existent_file.txt');

    expect(() async => await getHash(nonExistentFile),
        throwsA(isA<FileSystemException>()));
  });

  test('Encrypts a file successfully flutter_sodium', () async {
    // Set up test data
    const staticPath = String.fromEnvironment('PWD');

    const sourceFilePath = '$staticPath/test_data/png-5mb-1.png';
    const encryptPath = '$staticPath/test_data/encrypted.txt';
    const decryptPath = '$staticPath/test_data/decrypted.png';
    final key = fs.CryptoUtil.base642bin(
        "/IEuAJ+fC8z6D9xlHOMf2qEbOkrBFjbtKDIZKMoNu3U=");

    if (File(encryptPath).existsSync()) {
      File(encryptPath).deleteSync();
    }
    if (File(decryptPath).existsSync()) {
      File(decryptPath).deleteSync();
    }

    // Encrypt the file
    final encryptionResult = await fs.CryptoUtil.encryptFile(
      sourceFilePath,
      encryptPath,
      key: key,
    );

    // Verify encryption
    expect(encryptionResult.header, isNotNull);

    final expectedContent = await File(sourceFilePath).readAsBytes();

    // Decrypt the file to confirm
    await CryptoUtil.decryptFile(
      encryptPath,
      decryptPath,
      encryptionResult.header!,
      key,
    );

    final decryptedContent = await File(decryptPath).readAsBytes();
    expect(decryptedContent, equals(expectedContent));
  });

  test('Encrypts a file successfully sodium_libs', () async {
    // Set up test data
    const staticPath = String.fromEnvironment('PWD');

    const sourceFilePath = '$staticPath/test_data/png-5mb-1.png';
    const encryptPath = '$staticPath/test_data/encrypted_sd.txt';
    const decryptPath = '$staticPath/test_data/decrypted_sd.png';

    final key =
        CryptoUtil.base642bin("/IEuAJ+fC8z6D9xlHOMf2qEbOkrBFjbtKDIZKMoNu3U=");

    if (File(encryptPath).existsSync()) {
      File(encryptPath).deleteSync();
    }
    if (File(decryptPath).existsSync()) {
      File(decryptPath).deleteSync();
    }

    // Encrypt the file
    final encryptionResult = await CryptoUtil.encryptFile(
      sourceFilePath,
      encryptPath,
      key: key,
    );

    // Verify encryption
    expect(encryptionResult.header, isNotNull);

    final expectedContent = await File(sourceFilePath).readAsBytes();
    final encryptedData = await File(encryptPath).readAsBytes();
    expect(encryptedData, isNot(expectedContent)); // Encrypted content differs

    // Decrypt the file to confirm
    await fs.CryptoUtil.decryptFile(
      encryptPath,
      decryptPath,
      encryptionResult.header!,
      key,
    );
    final decryptedContent = await File(decryptPath).readAsBytes();
    expect(decryptedContent, equals(expectedContent));
  });
}
