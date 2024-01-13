// This is a basic Flutter widget test.
//
// To perform an interaction with a widget in your test, use the WidgetTester
// utility in the flutter_test package. For example, you can send tap and scroll
// gestures. You can also use WidgetTester to find child widgets in the widget
// tree, read text, and verify that the values of widget properties are correct.

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
    final bin = Uint8List.fromList([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // Hello
    const expectedHex = '48656c6c6f';
    final actualHex = CryptoUtil.bin2hex(bin);
    expect(actualHex, equals(expectedHex));
  });

  test(
      'encrypts data with a randomly generated nonce and returns an EncryptionResult',
      () async {
    // Sample data
    final source = CryptoUtil.strToBin('Hello, world!');
    final key = SecureKey.random(
        sodium, sodium.crypto.secretBox.keyBytes); // Generate a suitable key

    // Encrypt the data
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

  // test('Decrypts cipher with valid key and nonce', () async {
  //   final cipher = CryptoUtil.base642bin(
  //       'QXJlIHlvdSBhcmUgZGVjb2RlZCB0byB0aGUgYmVzdCB0ZXN0IGtleQ==');

  //   final key = CryptoUtil.randomKey();
  //   // allowed value is 24
  //   final nonce = CryptoUtil.base642bin('dGhpcyBpcyBleGFjdGx5IDI0IHdvcmRz');
  //   final expectedPlaintext = CryptoUtil.strToBin([10, 11, 12]);

  //   // Act
  //   final plaintext = await CryptoUtil.decrypt(cipher, key, nonce);

  //   // Assert
  //   expect(plaintext, expectedPlaintext);
  // });

  test('encryptData', () async {
    final source = CryptoUtil.strToBin('hello w');
    final key = CryptoUtil.randomKey();

    final encrypted = await CryptoUtil.encryptData(source, key);
    expect(encrypted.encryptedData, isNotNull);
  });

  // test('decryptData', () async {
  //   final source = SecretStreamCipherMessage(CryptoUtil.randomKey(24));
  //   final key = CryptoUtil.randomKey();

  //   final decrypted = await CryptoUtil.decryptData(
  //     source.message,
  //     key,
  //     null,
  //   );
  //   expect(decrypted.length, 24);
  // });

  // encryptFile, decryptFile

  test('check generated keypair', () async {
    final keyPair = await CryptoUtil.generateKeyPair();
    expect(keyPair.publicKey, isNotNull);
    expect(keyPair.secretKey, isNotNull);
  });

  test('test salt to derive key', () {
    final result = CryptoUtil.getSaltToDeriveKey();
    expect(result, isNotNull);
  });
}
