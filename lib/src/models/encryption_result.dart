import 'dart:isolate';
import 'dart:typed_data';

class EncryptionResult {
  final Uint8List? encryptedData;
  final Uint8List? key;
  final Uint8List? header;
  final Uint8List? nonce;

  EncryptionResult({
    this.encryptedData,
    this.key,
    this.header,
    this.nonce,
  });

  Map<String, Object?> toIsolateMap() => {
        'encryptedData': encryptedData == null
            ? null
            : TransferableTypedData.fromList([encryptedData!]),
        'key': key == null ? null : TransferableTypedData.fromList([key!]),
        'header':
            header == null ? null : TransferableTypedData.fromList([header!]),
        'nonce':
            nonce == null ? null : TransferableTypedData.fromList([nonce!]),
      };

  factory EncryptionResult.fromIsolateMap(Map<dynamic, dynamic> map) =>
      EncryptionResult(
        encryptedData: map['encryptedData'] == null
            ? null
            : (map['encryptedData'] as TransferableTypedData)
                .materialize()
                .asUint8List(),
        key: map['key'] == null
            ? null
            : (map['key'] as TransferableTypedData).materialize().asUint8List(),
        header: map['header'] == null
            ? null
            : (map['header'] as TransferableTypedData)
                .materialize()
                .asUint8List(),
        nonce: map['nonce'] == null
            ? null
            : (map['nonce'] as TransferableTypedData)
                .materialize()
                .asUint8List(),
      );
}

class FileEncryptResult {
  final Uint8List key;
  final Uint8List header;
  final String? fileMd5;
  final List<String>? partMd5s;
  final int? partSize;

  FileEncryptResult({
    required this.key,
    required this.header,
    this.fileMd5,
    this.partMd5s,
    this.partSize,
  });

  Map<String, Object?> toIsolateMap() => {
        'key': TransferableTypedData.fromList([key]),
        'header': TransferableTypedData.fromList([header]),
        'fileMd5': fileMd5,
        'partMd5s': partMd5s,
        'partSize': partSize,
      };

  factory FileEncryptResult.fromIsolateMap(Map<dynamic, dynamic> map) =>
      FileEncryptResult(
        key: (map['key'] as TransferableTypedData).materialize().asUint8List(),
        header: (map['header'] as TransferableTypedData)
            .materialize()
            .asUint8List(),
        fileMd5: map['fileMd5'] as String?,
        partMd5s: (map['partMd5s'] as List?)?.cast<String>(),
        partSize: map['partSize'] as int?,
      );
}
