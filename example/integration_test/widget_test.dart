import 'dart:io';
import 'dart:typed_data';

import 'package:ente_crypto_dart/ente_crypto_dart.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:sodium_libs/sodium_libs.dart';

void main() async {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  await initCryptoUtil();

  test('verify consts', () async {
    // Load app widget.
    expect(CryptoUtil.decryptionChunkSize, 4194321);
  });
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
    final bin = CryptoUtil.strToBin('Hello');
    const expectedHex = '48656c6c6f';
    final actualHex = CryptoUtil.bin2hex(bin);
    expect(actualHex, equals(expectedHex));
  });

  test(
      'encrypts data with a randomly generated nonce and returns an EncryptionResult',
      () async {
    final source = CryptoUtil.strToBin('Hello, world!');
    final key = SecureKey.random(sodium, sodium.crypto.secretBox.keyBytes);

    final encryptionResult = CryptoUtil.encryptSync(source, key.extractBytes());

    // Assertions
    expect(encryptionResult, isNotNull);
    expect(encryptionResult.encryptedData, isNotEmpty);
    expect(encryptionResult.key, equals(key.extractBytes()));
    expect(encryptionResult.nonce?.length,
        equals(sodium.crypto.secretBox.nonceBytes));
  });

  test('throws an error for invalid key length', () {
    // Invalid key length
    final invalidKey = Uint8List(10); // Assuming keyBytes is not 10
    final source = CryptoUtil.strToBin('data');

    expect(() => CryptoUtil.encryptSync(source, invalidKey),
        throwsA(isA<Error>()));
  });

  test('Decrypts cipher with valid key and nonce', () async {
    // Sample data
    final source = CryptoUtil.strToBin('Hello, world!');
    final key = SecureKey.random(sodium, sodium.crypto.secretBox.keyBytes);

    final encryptionResult = CryptoUtil.encryptSync(source, key.extractBytes());
    final cipher = encryptionResult.encryptedData;

    final nonce = encryptionResult.nonce;

    final plaintext =
        await CryptoUtil.decrypt(cipher!, key.extractBytes(), nonce!);

    expect(plaintext, source);
  });

  test('encryptData and DecryptData', () async {
    final source = CryptoUtil.strToBin('hello world');
    final key = CryptoUtil.randomKey();

    final encrypted = await CryptoUtil.encryptData(source, key);
    expect(encrypted.encryptedData, isNotNull);
    const lengthForEncrypt = (24 + 2 * 17);
    expect(encrypted.encryptedData!.length - lengthForEncrypt,
        equals(source.length));

    final decrypted = await CryptoUtil.decryptData(
      encrypted.encryptedData!,
      key,
      null,
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

  test('openSealSync decrypts ciphertext correctly', () async {
    final keyPair = CryptoUtil.generateKeyPair();
    final publicKey = keyPair.publicKey;
    final secretKey = keyPair.secretKey.extractBytes();
    final message = CryptoUtil.strToBin('Hello, world!');
    final cipherText = CryptoUtil.sealSync(message, publicKey);

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
    final key = CryptoUtil.randomKey();

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

    final hash = await CryptoUtil.getHash(testFile);

    expect(hash, isNotNull);
    expect(hash.length,
        equals(sodium.crypto.genericHash.bytesMax)); // Verify hash length
    // Compare the hash with the expected value for the test content
    expect(hash.length, equals(64));
  });

  test('throws an error if the file does not exist', () async {
    final nonExistentFile = File('non_existent_file.txt');

    expect(() async => await CryptoUtil.getHash(nonExistentFile),
        throwsA(isA<FileSystemException>()));
  });

  // TBD: encryptFile, decryptFile,
}
