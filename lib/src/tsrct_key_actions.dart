import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;
import 'package:tsrct_dart_lib/src/tsrct_utils_gcp.dart';

abstract class KeyActionsProvider {

  Future<pc.RSAPublicKey> getPublicKeyFromResourceName(String resourceName);

  Future<Map<String,dynamic>> getJWKS(
      String keySetId,
      String sigResourceName,
      String encResourceName,
      );

  Future<Map<String,dynamic>> getPublicKeyJWKFromResourceName(
      String keyId,
      String resourceName,
      );

  /// sign the [bytes] payload given the resource address of the signing private key
  /// return the answer as base64 encoded with trailing '=' trimmed
  Future<String> sign(String sigKeyResource, Uint8List bytes);

  /// generate a base64 encoded AES128 key that can be used for encryption
  Future<String> generateAES128();

  /// decrypt a payload using the asymmetric
  Future<String> decrypt(String encKeyResource, Uint8List bytes);

  /// close any connections or do any cleanup
  void close();
}

class GCPKeyActionsProvider extends KeyActionsProvider {
  late GCPUtils _gcpUtils;

  Future<void> init() async {
    _gcpUtils = await GCPUtils.instance();
  }

  @override
  Future<Map<String,dynamic>> getJWKS(
      String keySetId,
      String sigResourceName,
      String encResourceName,
      ) async {
    Map<String,dynamic> sigJwk = await getPublicKeyJWKFromResourceName("$keySetId-sig", sigResourceName);
    Map<String,dynamic> encJwk = await getPublicKeyJWKFromResourceName("$keySetId-enc", encResourceName);

    Map<String,dynamic> jwks = {
      "keys": [
        sigJwk,
        encJwk
      ]
    };

    return jwks;
  }


  /// will return the jwk for this resource name,
  /// will have the fields:
  /// kid -- key id as provided
  /// kty -- key type
  /// alg -- algorithm
  /// use -- use, either sig or enc
  /// exp -- exponent
  /// mod -- modulus
  @override
  Future<Map<String,dynamic>> getPublicKeyJWKFromResourceName(
      String keyId,
      String resourceName,
      ) async {
    return await _gcpUtils.getPublicKeyJwk(keyId, resourceName);
  }

  @override
  Future<pc.RSAPublicKey> getPublicKeyFromResourceName(String resourceName) async {
    pc.RSAPublicKey publicKey = await _gcpUtils.getPublicKey(resourceName);
    return publicKey;
  }

  @override
  Future<String> decrypt(String encKeyResource, Uint8List bytes) {
    // TODO: implement decrypt
    throw UnimplementedError();
  }

  @override
  Future<String> generateAES128() {
    // TODO: implement generateAES128
    throw UnimplementedError();
  }

  @override
  Future<String> sign(String sigKeyResource, Uint8List bytes) async {
    return await _gcpUtils.sign(sigKeyResource, bytes);
  }

  @override
  void close() {
    if(_gcpUtils != null) {
      _gcpUtils.close();
    }
  }



}

class LocalKeyActionsProvider extends KeyActionsProvider {

  @override
  Future<Map<String,dynamic>> getJWKS(
      String keySetId,
      String sigResourceName,
      String encResourceName,
      ) {
    // TODO: implement getJWKS
    throw UnimplementedError();
  }


  @override
  Future<Map<String,dynamic>> getPublicKeyJWKFromResourceName(String keyId, String resourceName) async {
    // TODO: implement getPublicKeyJWKFromResourceName
    throw UnimplementedError();
  }


  @override
  Future<pc.RSAPublicKey> getPublicKeyFromResourceName(String resourceName) {
    // TODO: implement getPublicKeyFromResourceName
    throw UnimplementedError();
  }

  @override
  Future<String> decrypt(String encKeyResource, Uint8List bytes) {
    // TODO: implement decrypt
    throw UnimplementedError();
  }

  @override
  Future<String> generateAES128() {
    // TODO: implement generateAES128
    throw UnimplementedError();
  }

  @override
  Future<String> sign(String sigKeyResource, Uint8List bytes) {
    // TODO: implement sign
    throw UnimplementedError();
  }

  @override
  void close() {
    // for local, this can close the file handle or just free up memory
  }

}