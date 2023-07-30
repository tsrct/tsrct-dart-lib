import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:googleapis/cloudkms/v1.dart';
import 'package:pointycastle/src/utils.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:tsrct_dart_lib/src/tsrct_codec_utils.dart';
import 'package:tsrct_dart_lib/src/tsrct_utils_gcp.dart';
import 'package:tsrct_dart_lib/tsrct_dart_lib.dart';

abstract class KeyActionsProvider {
  Future<pc.RSAPublicKey> getPublicKeyFromResourceName(String resourceName);

  Future<Map<String, dynamic>> getJWKS(
    String keySetId,
    String sigResourceName,
    String encResourceName,
  );

  Future<Map<String, dynamic>> getPublicKeyJWKFromResourceName(
    String keyId,
    String resourceName,
  );

  /// sign the [bytes] payload given the resource address of the signing private key
  /// return the answer as base64 encoded with trailing '=' trimmed
  Future<String> sign(String sigKeyResource, Uint8List bytes);

  /// generate a base64 encoded AES128 key that can be used for encryption
  Future<String> generateAES128();

  /// decrypt a payload using the asymmetric key resource
  /// return the result as a base64 encoded string with no padding
  Future<String> decrypt(String encKeyResource, Uint8List bytes);

  /// encrypt a payload using the asymmetric key resource
  /// return the result as a base64 encoded string with no padding
  Future<String> encrypt(String encKeyResource, Uint8List input);

  Future<void> createDdxKey(String ddxId, String kekResource,);

  pc.SecureRandom _secureRandom() {
    final secureRandom = pc.FortunaRandom();

    final seedSource = Random.secure();
    final seeds = <int>[];
    for (int i = 0; i < 32; i++) {
      seeds.add(seedSource.nextInt(255));
    }
    secureRandom.seed(pc.KeyParameter(Uint8List.fromList(seeds)));

    return secureRandom;
  }

  pc.AsymmetricKeyPair<pc.RSAPublicKey, pc.RSAPrivateKey> _generateRSAkeyPair(
      {int bitLength = 2048}) {
    final pc.SecureRandom secureRandom = _secureRandom();
    // Create an RSA key generator and initialize it

    final keyGen = pc.RSAKeyGenerator()
      ..init(pc.ParametersWithRandom(
          pc.RSAKeyGeneratorParameters(BigInt.parse('65537'), bitLength, 64),
          secureRandom));

    // Use the generator

    final pair = keyGen.generateKeyPair();

    // Cast the generated key pair into the RSA key types

    final myPublic = pair.publicKey as pc.RSAPublicKey;
    final myPrivate = pair.privateKey as pc.RSAPrivateKey;

    return pc.AsymmetricKeyPair<pc.RSAPublicKey, pc.RSAPrivateKey>(myPublic, myPrivate);
  }

  Map<String,dynamic> _publicKeyToJwk(pc.RSAPublicKey publicKey) {
    Map<String,dynamic> publicJwk = {};
    publicJwk["kty"] = "RSA";
    publicJwk["alg"] = "RS256";
    publicJwk["use"] = "sig";
    publicJwk["typ"] = "public";

    Uint8List expBytes = encodeBigInt(publicKey.publicExponent);
    Uint8List modBytes = encodeBigInt(publicKey.modulus);

    String expStr = base64UrlEncode(expBytes);
    publicJwk['exp'] = expStr;

    String modStr = base64UrlEncode(modBytes);
    publicJwk['mod'] = modStr;

    return publicJwk;
  }

  Map<String,dynamic> _privateKeyToJwk(pc.RSAPrivateKey privateKey) {
    Map<String,dynamic> publicJwk = {};
    publicJwk["kty"] = "RSA";
    publicJwk["alg"] = "RS256";
    publicJwk["use"] = "sig";
    publicJwk["typ"] = "private";

    Uint8List expBytes = encodeBigInt(privateKey.privateExponent);
    Uint8List modBytes = encodeBigInt(privateKey.modulus);
    Uint8List pBytes = encodeBigInt(privateKey.p);
    Uint8List qBytes = encodeBigInt(privateKey.q);

    publicJwk['exp'] = base64UrlEncode(expBytes);
    publicJwk['mod'] = base64UrlEncode(modBytes);
    publicJwk["p"]   = base64UrlEncode(pBytes);
    publicJwk["q"]   = base64UrlEncode(qBytes);

    return publicJwk;
  }



  /// close any connections or do any cleanup
  void close();
}

class GCPKeyActionsProvider extends KeyActionsProvider {
  late GCPUtils _gcpUtils;

  Future<void> init() async {
    _gcpUtils = await GCPUtils.instance();
  }

  @override
  Future<Map<String, dynamic>> getJWKS(
    String keySetId,
    String sigResourceName,
    String encResourceName,
  ) async {
    Map<String, dynamic> sigJwk =
        await getPublicKeyJWKFromResourceName("$keySetId-sig", sigResourceName);
    Map<String, dynamic> encJwk =
        await getPublicKeyJWKFromResourceName("$keySetId-enc", encResourceName);

    Map<String, dynamic> jwks = {
      "keys": [sigJwk, encJwk]
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
  Future<Map<String, dynamic>> getPublicKeyJWKFromResourceName(
    String keyId,
    String resourceName,
  ) async {
    return await _gcpUtils.getPublicKeyJwk(keyId, resourceName);
  }

  @override
  Future<pc.RSAPublicKey> getPublicKeyFromResourceName(
      String resourceName) async {
    pc.RSAPublicKey publicKey = await _gcpUtils.getPublicKey(resourceName);
    return publicKey;
  }

  @override
  Future<String> decrypt(String encKeyResource, Uint8List bytes) async {
    // TODO: implement decrypt
    throw UnimplementedError();
  }

  @override
  Future<String> encrypt(String encKeyResource, Uint8List input) async {
    pc.RSAPublicKey gcpPublicKey = await _gcpUtils.getPublicKey(encKeyResource);
    Uint8List encryptedBytes = CryptoUtils.rsaEncrypt(gcpPublicKey, input);
    return base64UrlEncode(encryptedBytes);
  }

  @override
  Future<void> createDdxKey(
      String ddxId,
      String kekResource,
  ) async {
    pc.AsymmetricKeyPair<pc.RSAPublicKey, pc.RSAPrivateKey> keyPair = _generateRSAkeyPair();
    Map<String,dynamic> jwkPublicKey  = _publicKeyToJwk(keyPair.publicKey);
    Map<String,dynamic> jwkPrivateKey = _privateKeyToJwk(keyPair.privateKey);

    String jsonPublicKey = json.encode(jwkPublicKey);
    String privateKeyBase64 = convertJsonToBase64(jwkPrivateKey);
    Uint8List stringBytes = Uint8List.fromList(utf8.encode(privateKeyBase64));

    String encPrivateKeyBase64 = await encrypt(kekResource, stringBytes);

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
    if (_gcpUtils != null) {
      _gcpUtils.close();
    }
  }
}

class LocalKeyActionsProvider extends KeyActionsProvider {
  @override
  Future<Map<String, dynamic>> getJWKS(
    String keySetId,
    String sigResourceName,
    String encResourceName,
  ) {
    // TODO: implement getJWKS
    throw UnimplementedError();
  }

  @override
  Future<Map<String, dynamic>> getPublicKeyJWKFromResourceName(
      String keyId, String resourceName) async {
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

  Future<String> encrypt(String encKeyResource, Uint8List bytes) {
    // TODO: implement decrypt
    throw UnimplementedError();
  }

  @override
  Future<void> createDdxKey(
      String ddxId,
      String kekResource,
      ) {
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
