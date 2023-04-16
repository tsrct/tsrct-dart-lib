import 'dart:typed_data';

abstract class KeyActionsProvider {
  /// sign the [bytes] payload given the resource address of the signing private key
  Future<String> sign(String sigKeyResource, Uint8List bytes);

  /// generate a base64 encoded AES128 key that can be used for encryption
  Future<String> generateAES128();

  /// decrypt a payload using the asymmetric
  Future<String> decrypt(String encKeyResource, Uint8List bytes);
}
