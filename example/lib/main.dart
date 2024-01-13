import 'dart:typed_data';

import 'package:ente_crypto_dart/ente_crypto_dart.dart';
import 'package:flutter/material.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  CryptoUtil.init();
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Demo',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: const MyHomePage(title: 'Flutter Demo Home Page'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  func() async {
    try {
      final cipher = Uint8List.fromList("hello world this".codeUnits);
      final key = CryptoUtil.randomKey();
      final nonce = Uint8List.fromList("this is exactly 24 words".codeUnits);
      final expectedPlaintext = Uint8List.fromList([10, 11, 12]);
      final val = await CryptoUtil.decrypt(cipher, key, nonce).then((value) {
        print(value);
      });

      print(val);
    } catch (e) {
      print(e);
    }
  }

  @override
  void initState() {
    super.initState();
    func();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: Text(widget.title),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            Text(
              CryptoUtil.decryptionChunkSize.toString(),
              style: Theme.of(context).textTheme.displayMedium,
            ),
          ],
        ),
      ),
    );
  }
}