# ente_crypto_dart
The core of the ente's crypto library.

## Getting started

- Import the package
```dart
import 'package:ente_crypto_dart/ente_crypto_dart.dart';
```
- Call the following inside the main function
```dart
WidgetsFlutterBinding.ensureInitialized();
initCryptoUtil();
```
- Just start consuming the CryptoUtil class, see usage below

## Usage

```dart
import 'package:ente_crypto_dart/ente_crypto_dart.dart';

const utf8Str = CryptoUtil.strToBin("Hello");
const decryptionChunk = CryptoUtil.decryptionChunkSize;
```

## Additional information

This library is made by Ente.io developers and used in auth and photos app.

This is GPL-3.0 Licensed and wouldn't be possible without `libsodium` library and the `sodium` dart package.