import 'dart:io';
import 'dart:typed_data';
import 'package:ente_crypto_dart/ente_crypto_dart.dart';
import 'package:flutter/material.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  initCryptoUtil();
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'ChaCha Encryption Demo',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: const HomePage(),
    );
  }
}

class HomePage extends StatelessWidget {
  const HomePage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('ChaCha20-Poly1305 Demo'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Text(
              'ChaCha20-Poly1305 Encryption Demo',
              style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 40),
            _DemoCard(
              title: 'Text Data Encryption',
              description: 'Encrypt and decrypt text data',
              icon: Icons.text_fields,
              onTap: () => Navigator.push(
                context,
                MaterialPageRoute(builder: (context) => const TextDataDemo()),
              ),
            ),
            const SizedBox(height: 20),
            _DemoCard(
              title: 'File Encryption',
              description: 'Encrypt and decrypt files (images, text files)',
              icon: Icons.file_present,
              onTap: () => Navigator.push(
                context,
                MaterialPageRoute(builder: (context) => const FileEncryptionDemo()),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _DemoCard extends StatelessWidget {
  final String title;
  final String description;
  final IconData icon;
  final VoidCallback onTap;

  const _DemoCard({
    required this.title,
    required this.description,
    required this.icon,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 40),
      child: InkWell(
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Row(
            children: [
              Icon(icon, size: 48, color: Theme.of(context).primaryColor),
              const SizedBox(width: 20),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(title, style: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
                    const SizedBox(height: 4),
                    Text(description, style: TextStyle(color: Colors.grey[600])),
                  ],
                ),
              ),
              const Icon(Icons.arrow_forward_ios),
            ],
          ),
        ),
      ),
    );
  }
}

// Text Data Encryption Demo
class TextDataDemo extends StatefulWidget {
  const TextDataDemo({super.key});

  @override
  State<TextDataDemo> createState() => _TextDataDemoState();
}

class _TextDataDemoState extends State<TextDataDemo> {
  final TextEditingController _inputController = TextEditingController(text: 'Hello, World!');
  String _encryptedData = '';
  String _decryptedData = '';
  Uint8List? _key;
  Uint8List? _header;
  Uint8List? _encryptedBytes;
  bool _isProcessing = false;

  @override
  void dispose() {
    _inputController.dispose();
    super.dispose();
  }

  Future<void> _encrypt() async {
    if (_inputController.text.isEmpty) {
      _showSnackBar('Please enter some text to encrypt');
      return;
    }

    setState(() {
      _isProcessing = true;
      _encryptedData = '';
      _decryptedData = '';
    });

    try {
      _key = CryptoUtil.generateKey();
      final source = Uint8List.fromList(_inputController.text.codeUnits);

      final result = await CryptoUtil.encryptData(source, _key!);

      _header = result.header;
      _encryptedBytes = result.encryptedData;

      final base64Data = CryptoUtil.bin2base64(_encryptedBytes!);
      final preview = base64Data.length > 100
          ? '${base64Data.substring(0, 100)}...'
          : base64Data;

      setState(() {
        _encryptedData = 'Header: ${_header!.length} bytes\n'
            'Encrypted: ${_encryptedBytes!.length} bytes\n'
            'Original: ${source.length} bytes\n\n'
            '$preview';
        _isProcessing = false;
      });

      _showSnackBar('✓ Encryption successful!');
    } catch (e) {
      setState(() {
        _encryptedData = 'Error: $e';
        _isProcessing = false;
      });
      _showSnackBar('✗ Encryption failed');
    }
  }

  Future<void> _decrypt() async {
    if (_encryptedBytes == null || _key == null || _header == null) {
      _showSnackBar('Please encrypt some data first');
      return;
    }

    setState(() {
      _isProcessing = true;
      _decryptedData = '';
    });

    try {
      final decrypted = await CryptoUtil.decryptData(_encryptedBytes!, _key!, _header!);

      setState(() {
        _decryptedData = String.fromCharCodes(decrypted);
        _isProcessing = false;
      });

      _showSnackBar('✓ Decryption successful!');
    } catch (e) {
      setState(() {
        _decryptedData = 'Error: $e';
        _isProcessing = false;
      });
      _showSnackBar('✗ Decryption failed');
    }
  }

  void _showSnackBar(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message), duration: const Duration(seconds: 2)),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Text Data Encryption'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            TextField(
              controller: _inputController,
              decoration: const InputDecoration(
                labelText: 'Enter text to encrypt',
                border: OutlineInputBorder(),
              ),
              maxLines: 5,
            ),
            const SizedBox(height: 16),
            ElevatedButton.icon(
              onPressed: _isProcessing ? null : _encrypt,
              icon: const Icon(Icons.lock),
              label: const Text('Encrypt Text'),
            ),
            if (_encryptedData.isNotEmpty) ...[
              const SizedBox(height: 24),
              const Text('Encrypted:', style: TextStyle(fontWeight: FontWeight.bold)),
              const SizedBox(height: 8),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.grey[200],
                  borderRadius: BorderRadius.circular(8),
                ),
                child: SelectableText(_encryptedData, style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
              ),
              const SizedBox(height: 16),
              ElevatedButton.icon(
                onPressed: _isProcessing ? null : _decrypt,
                icon: const Icon(Icons.lock_open),
                label: const Text('Decrypt Text'),
              ),
            ],
            if (_decryptedData.isNotEmpty) ...[
              const SizedBox(height: 24),
              const Text('Decrypted:', style: TextStyle(fontWeight: FontWeight.bold)),
              const SizedBox(height: 8),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.green[100],
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: Colors.green),
                ),
                child: SelectableText(_decryptedData),
              ),
            ],
            if (_isProcessing) const Center(child: CircularProgressIndicator()),
          ],
        ),
      ),
    );
  }
}

// File Encryption Demo
class FileEncryptionDemo extends StatefulWidget {
  const FileEncryptionDemo({super.key});

  @override
  State<FileEncryptionDemo> createState() => _FileEncryptionDemoState();
}

class _FileEncryptionDemoState extends State<FileEncryptionDemo> {
  String _status = '';
  Uint8List? _key;
  Uint8List? _header;
  bool _isProcessing = false;
  File? _originalFile;
  File? _encryptedFile;
  File? _decryptedFile;
  bool _isImageFile = false;

  String get _tempDir => Directory.systemTemp.path;

  Future<void> _selectFile(bool useImage) async {
    setState(() {
      _isProcessing = true;
      _status = useImage ? 'Loading image...' : 'Creating text file...';
      _isImageFile = useImage;
      _originalFile = null;
      _encryptedFile = null;
      _decryptedFile = null;
    });

    try {
      if (useImage) {
        // Try multiple possible paths for the test image
        final possiblePaths = [
          'test_data/png-5mb-1.png',
          '../test_data/png-5mb-1.png',
          '${Directory.current.path}/test_data/png-5mb-1.png',
        ];

        File? imageFile;
        for (final path in possiblePaths) {
          final file = File(path);
          if (await file.exists()) {
            imageFile = file;
            break;
          }
        }

        if (imageFile != null) {
          _originalFile = imageFile;
          final size = await imageFile.length();
          setState(() {
            _status = 'Image loaded: ${size} bytes\nPath: ${imageFile!.path}';
            _isProcessing = false;
          });
        } else {
          setState(() {
            _status = 'Image not found. Tried paths:\n${possiblePaths.join('\n')}\n\nPlease ensure test_data/png-5mb-1.png exists.';
            _isProcessing = false;
          });
        }
      } else {
        // Create a sample text file
        final file = File('$_tempDir/sample.txt');
        await file.writeAsString('This is a sample file for encryption demo!\n' * 100);

        _originalFile = file;
        final size = await file.length();

        setState(() {
          _status = 'Sample file created: ${size} bytes';
          _isProcessing = false;
        });
      }
    } catch (e) {
      setState(() {
        _status = 'Error: $e';
        _isProcessing = false;
      });
    }
  }

  Future<void> _encryptFile() async {
    if (_originalFile == null) {
      _showSnackBar('Please select a file first');
      return;
    }

    setState(() {
      _isProcessing = true;
      _status = 'Encrypting file...';
    });

    try {
      final originalSize = await _originalFile!.length();
      print('DEBUG: Encrypting file...');
      print('  Original file: ${_originalFile!.path} ($originalSize bytes)');

      final ext = _isImageFile ? 'bin' : 'bin';
      final encryptedPath = '$_tempDir/encrypted_file.$ext';
      final result = await CryptoUtil.encryptFile(
        _originalFile!.path,
        encryptedPath,
      );

      _key = result.key;
      _header = result.header;
      _encryptedFile = File(encryptedPath);

      final encryptedSize = await _encryptedFile!.length();

      print('DEBUG: Encryption complete');
      print('  Encrypted file: $encryptedPath ($encryptedSize bytes)');
      print('  Header length: ${_header!.length} bytes');
      print('  Key length: ${_key!.length} bytes');
      print('  Overhead: ${encryptedSize - originalSize} bytes');

      setState(() {
        _status = 'File encrypted!\n'
            'Original: $originalSize bytes\n'
            'Encrypted: $encryptedSize bytes\n'
            'Overhead: ${encryptedSize - originalSize} bytes';
        _isProcessing = false;
      });

      _showSnackBar('✓ File encrypted successfully');
    } catch (e, stackTrace) {
      print('DEBUG: Encryption error: $e');
      print('Stack trace: $stackTrace');
      setState(() {
        _status = 'Encryption failed: $e';
        _isProcessing = false;
      });
      _showSnackBar('✗ Encryption failed');
    }
  }

  Future<void> _decryptFile() async {
    if (_encryptedFile == null || _key == null || _header == null) {
      _showSnackBar('Please encrypt a file first');
      return;
    }

    setState(() {
      _isProcessing = true;
      _status = 'Decrypting file...';
    });

    try {
      // Verify encrypted file exists and has content
      if (!await _encryptedFile!.exists()) {
        throw Exception('Encrypted file not found at: ${_encryptedFile!.path}');
      }

      final encryptedSize = await _encryptedFile!.length();
      if (encryptedSize == 0) {
        throw Exception('Encrypted file is empty');
      }

      print('DEBUG: Decrypting file...');
      print('  Encrypted file: ${_encryptedFile!.path} ($encryptedSize bytes)');
      print('  Header length: ${_header!.length} bytes');
      print('  Key length: ${_key!.length} bytes');

      final ext = _isImageFile ? 'png' : 'txt';
      final decryptedPath = '$_tempDir/decrypted_file.$ext';
      await CryptoUtil.decryptFile(
        _encryptedFile!.path,
        decryptedPath,
        _header!,
        _key!,
      );

      _decryptedFile = File(decryptedPath);

      // Verify content matches
      final originalBytes = await _originalFile!.readAsBytes();
      final decryptedBytes = await _decryptedFile!.readAsBytes();
      final matches = _bytesEqual(originalBytes, decryptedBytes);

      print('DEBUG: Decryption complete');
      print('  Original size: ${originalBytes.length} bytes');
      print('  Decrypted size: ${decryptedBytes.length} bytes');
      print('  Match: $matches');

      setState(() {
        _status += '\n\nFile decrypted!\n'
            'Content verification: ${matches ? "✓ PASS" : "✗ FAIL"}\n'
            'Decrypted file: $decryptedPath';
        _isProcessing = false;
      });

      _showSnackBar(matches ? '✓ Decryption successful!' : '✗ Content mismatch!');
    } catch (e, stackTrace) {
      print('DEBUG: Decryption error: $e');
      print('Stack trace: $stackTrace');
      setState(() {
        _status = 'Decryption failed: $e';
        _isProcessing = false;
      });
      _showSnackBar('✗ Decryption failed');
    }
  }

  bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  void _showSnackBar(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message), duration: const Duration(seconds: 2)),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('File Encryption'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text('1. Select File Type:', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: ElevatedButton.icon(
                    onPressed: _isProcessing ? null : () => _selectFile(false),
                    icon: const Icon(Icons.text_snippet),
                    label: const Text('Text File'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: ElevatedButton.icon(
                    onPressed: _isProcessing ? null : () => _selectFile(true),
                    icon: const Icon(Icons.image),
                    label: const Text('Image File'),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 24),
            const Text('2. Encrypt & Decrypt:', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
            const SizedBox(height: 12),
            ElevatedButton.icon(
              onPressed: _isProcessing || _originalFile == null ? null : _encryptFile,
              icon: const Icon(Icons.lock),
              label: const Text('Encrypt File'),
            ),
            const SizedBox(height: 12),
            ElevatedButton.icon(
              onPressed: _isProcessing || _encryptedFile == null ? null : _decryptFile,
              icon: const Icon(Icons.lock_open),
              label: const Text('Decrypt File'),
            ),
            const SizedBox(height: 24),
            if (_status.isNotEmpty) ...[
              const Text('Status:', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
              const SizedBox(height: 8),
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.grey[100],
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: Colors.grey[300]!),
                ),
                child: SelectableText(
                  _status,
                  style: const TextStyle(fontFamily: 'monospace'),
                ),
              ),
            ],
            if (_isImageFile && _decryptedFile != null) ...[
              const SizedBox(height: 24),
              const Text('Decrypted Image:', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
              const SizedBox(height: 12),
              Container(
                height: 400,
                decoration: BoxDecoration(
                  border: Border.all(color: Colors.green, width: 2),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(8),
                  child: Image.file(
                    _decryptedFile!,
                    fit: BoxFit.contain,
                    errorBuilder: (context, error, stackTrace) {
                      return Center(child: Text('Error loading image: $error'));
                    },
                  ),
                ),
              ),
              const SizedBox(height: 12),
              const Text(
                '✓ Image decrypted successfully!',
                style: TextStyle(color: Colors.green, fontWeight: FontWeight.bold),
                textAlign: TextAlign.center,
              ),
            ],
            if (_isProcessing) ...[
              const SizedBox(height: 16),
              const Center(child: CircularProgressIndicator()),
            ],
          ],
        ),
      ),
    );
  }
}
