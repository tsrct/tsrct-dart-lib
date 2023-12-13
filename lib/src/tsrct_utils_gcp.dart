import 'dart:convert';
import 'dart:typed_data';
import 'package:googleapis/cloudkms/v1.dart';
import 'package:googleapis_auth/auth_io.dart' as auth;

import 'package:pointycastle/src/utils.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:tsrct_dart_lib/src/tsrct_codec_utils.dart';
import 'package:tsrct_dart_lib/src/tsrct_utils_crypto.dart';

class GCPUtils {

  static final GCPUtils _instance = GCPUtils._internal();

  static final Map<String,String> _gcpToJwaAlgs = {
    "RSA_DECRYPT_OAEP_2048_SHA256": "RSA-OAEP-256",
    "RSA_SIGN_PKCS1_2048_SHA256": "RS256",
  };

  static final Map<String,String> _gcpToJwkUse = {
    "RSA_DECRYPT_OAEP_2048_SHA256": "enc",
    "RSA_SIGN_PKCS1_2048_SHA256": "sig",
  };

  late auth.AutoRefreshingAuthClient _client;
  bool isInit = false;

  GCPUtils._internal();

  static Future<GCPUtils> instance() async {
    if(!_instance.isInit) {
      await _instance._init();
      _instance.isInit = true;
    }
    return _instance;
  }

  Future<void> _init() async {
    try {
      _client = await auth.clientViaMetadataServer();
      print("metadata client is: $_client");
    } catch (e) {
      print(">> authing app def client");
      _client = await auth.clientViaApplicationDefaultCredentials(scopes: ["https://www.googleapis.com/auth/cloudkms"]);
      print(">> app def client is: $_client");
    }
  }

  Future<Map<String,dynamic>> getPublicKeyJwk(String keyId, String resourceName) async {
    PublicKey publicKey = await _getPublicKey(resourceName);
    pc.RSAPublicKey rsaPublicKey = CryptoUtils.rsaPublicKeyFromPem(publicKey.pem!);
    Map<String,dynamic> publicJwk = {};

    publicJwk["kid"] = keyId;
    publicJwk["kty"] = "RSA";
    publicJwk["alg"] = _gcpToJwaAlgs[publicKey.algorithm!];
    publicJwk["use"] = _gcpToJwkUse[publicKey.algorithm!];

    Uint8List expBytes = encodeBigInt(rsaPublicKey.publicExponent);
    Uint8List modBytes = encodeBigInt(rsaPublicKey.modulus);

    String expStr = base64UrlEncode(expBytes);
    publicJwk['e'] = expStr;

    String modStr = base64UrlEncode(modBytes);
    publicJwk['n'] = modStr;

    return publicJwk;
  }

  Future<pc.RSAPublicKey> getPublicKey(String resourceName) async {
    PublicKey publicKey = await _getPublicKey(resourceName);
    Map<String,dynamic> publicKeyJson = publicKey.toJson();
    print('>> >> public key json: $publicKeyJson');

    pc.RSAPublicKey rsaPublicKey = CryptoUtils.rsaPublicKeyFromPem(publicKey.pem!);
    return rsaPublicKey;
  }

  Future<PublicKey> _getPublicKey(String resourceName) async {
    CloudKMSApi kmsApi = CloudKMSApi(_client);
    ProjectsResource projectsResource = kmsApi.projects;
    print('>> >> projectsResource: $projectsResource');
    ProjectsLocationsKeyRingsCryptoKeysCryptoKeyVersionsResource keyResource =
        projectsResource.locations.keyRings.cryptoKeys.cryptoKeyVersions;
    print(">> >> locations resource: $keyResource");
    CryptoKeyVersion keyVersion = await keyResource.get(resourceName);
    print('>> >> key version: ${keyVersion.name}');
    Map<String,dynamic> keyJson = keyVersion.toJson();
    print(">> >> key json: $keyJson");

    PublicKey publicKey = await keyResource.getPublicKey(keyVersion.name!);
    return publicKey;
  }

  /// sign and return an unpadded base64 signature
  Future<String> sign(
      String sigResourceName,
      Uint8List bytesToSign,
      ) async {
    CloudKMSApi kmsApi = CloudKMSApi(_client);
    ProjectsResource projectsResource = kmsApi.projects;
    print('>> >> projectsResource: $projectsResource');
    ProjectsLocationsKeyRingsCryptoKeysCryptoKeyVersionsResource keyResource =
        projectsResource.locations.keyRings.cryptoKeys.cryptoKeyVersions;
    print(">> >> locations resource: $keyResource");

    String inputBase64 = base64UrlEncode(bytesToSign);
    AsymmetricSignRequest request =
      AsymmetricSignRequest(
        data: inputBase64
      );
    AsymmetricSignResponse response = await keyResource.asymmetricSign(request, sigResourceName);
    return base64UrlConform(response.signature!);
  }

  Future<String> decrypt(
      String encResourceName,
      String base64EncodedCipherText,
      ) async {
    CloudKMSApi kmsApi = CloudKMSApi(_client);
    ProjectsResource projectsResource = kmsApi.projects;
    print('>> >> projectsResource: $projectsResource');
    ProjectsLocationsKeyRingsCryptoKeysCryptoKeyVersionsResource keyResource =
        projectsResource.locations.keyRings.cryptoKeys.cryptoKeyVersions;
    print(">> >> locations resource: $keyResource");

    AsymmetricDecryptRequest request =
      AsymmetricDecryptRequest(ciphertext: base64EncodedCipherText);

    AsymmetricDecryptResponse response = await keyResource.asymmetricDecrypt(request, encResourceName);
    return base64UrlConform(response.plaintext!);
  }

  void close() {
    _client.close();
  }
}