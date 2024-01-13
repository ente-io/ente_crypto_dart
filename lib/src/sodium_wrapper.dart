import 'package:sodium_libs/sodium_libs_sumo.dart';

class SodiumWrapper {
  late SodiumSumo sodium;

  static Future<SodiumSumo> init() async {
    final sod = await SodiumPlatform.instance.loadSodiumSumo();
    SodiumWrapper.instance.sodium = sod;
    return sod;
  }

  SodiumWrapper._();
  static final instance = SodiumWrapper._();
}
