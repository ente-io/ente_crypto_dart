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

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  CryptoUtil.init();

  test('verify consts', () async {
    // Load app widget.
    expect(CryptoUtil.decryptionChunkSize, 4194321);
  });
  test('decodes base64 string to Uint8List', () {
    const b64 = 'aGVsbG8gd29ybGQ=';
    final expectedBin = Uint8List.fromList('hello world'.codeUnits);
    final actualBin = CryptoUtil.base642bin(b64);
    expect(actualBin, equals(expectedBin));
  });

  test('encodes Uint8List to base64 string', () {
    final bin = Uint8List.fromList('hello world'.codeUnits);
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
    final source = Uint8List.fromList('Hello, world!'.codeUnits);
    final key = SecureKey.random(CryptoUtil.sodium,
        CryptoUtil.sodium.crypto.secretBox.keyBytes); // Generate a suitable key

    // Encrypt the data
    final encryptionResult = CryptoUtil.encryptSync(source, key.extractBytes());

    // Assertions
    expect(encryptionResult, isNotNull);
    expect(encryptionResult.encryptedData, isNotEmpty);
    expect(encryptionResult.key, equals(key.extractBytes()));
    expect(encryptionResult.nonce?.length,
        equals(CryptoUtil.sodium.crypto.secretBox.nonceBytes));
  });

  test('throws an error for invalid key length', () {
    // Invalid key length
    final invalidKey = Uint8List(10); // Assuming keyBytes is not 10
    final source = Uint8List.fromList('data'.codeUnits);

    expect(() => CryptoUtil.encryptSync(source, invalidKey),
        throwsA(isA<Error>()));
  });

  // test('Decrypts cipher with valid key and nonce', () async {
  //   final cipher = CryptoUtil.base642bin(
  //       'QXJlIHlvdSBhcmUgZGVjb2RlZCB0byB0aGUgYmVzdCB0ZXN0IGtleQ==');

  //   final key = CryptoUtil.randomKey();
  //   // allowed value is 24
  //   final nonce = CryptoUtil.base642bin('dGhpcyBpcyBleGFjdGx5IDI0IHdvcmRz');
  //   final expectedPlaintext = Uint8List.fromList([10, 11, 12]);

  //   // Act
  //   final plaintext = CryptoUtil.decryptSync(cipher, key, nonce);

  //   // Assert
  //   expect(plaintext, expectedPlaintext);
  // });

  test('encryptChaCha', () async {
    final source = Uint8List.fromList('data'.codeUnits);
    final key = CryptoUtil.randomKey();

    final encrypted = await CryptoUtil.encryptChaCha(source, key);
    expect(encrypted.encryptedData, isNotNull);
  });
}
