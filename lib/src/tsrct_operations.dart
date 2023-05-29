import 'dart:convert';
import 'dart:typed_data';
import 'dart:developer' as dev;

import 'package:intl/intl.dart';

import 'package:pointycastle/src/utils.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:tsrct_dart_lib/src/tsrct_codec_utils.dart';
import 'package:tsrct_dart_lib/src/tsrct_doc.dart';
import 'package:pointycastle/src/platform_check/platform_check.dart';

class TsrctCommonOps {
  static final DateFormat _keyIdDateFormat = DateFormat("yyyyMMddHHmmss");
  static final DateFormat _tdocDateFormat = DateFormat("yyyy-MM-dd'T'HH:mm:ss'Z");

  static String getNowAsTdocDateFormat() {
    return _tdocDateFormat.format(DateTime.now().toUtc());
  }

  static String getTimeAsTdocDateFormat(DateTime dateTime) {
    return _tdocDateFormat.format(dateTime);
  }

  static String getNowAsKeyIdDateFormat() {
    return _keyIdDateFormat.format(DateTime.now().toUtc());
  }

  static String getTimeAsKeyIdDateFormat(DateTime dateTime) {
    return _keyIdDateFormat.format(dateTime);
  }

  static int getNonce() {
    return DateTime.now().toUtc().millisecondsSinceEpoch~/1000;
  }

  /// takes a single jwk entry in the keys jwks to create the public key
  static pc.RSAPublicKey jwkToPublicKey(Map<String,dynamic> jwk) {
    String expStrBase64 = jwk['exp'];
    Uint8List expBytes = base64UrlDecode(expStrBase64);
    BigInt exp = decodeBigInt(expBytes);

    String modStrBase64 = jwk['mod'];
    Uint8List modbytes = base64UrlDecode(modStrBase64);
    BigInt mod = decodeBigInt(modbytes);

    pc.RSAPublicKey publicKey = pc.RSAPublicKey(mod, exp);
    return publicKey;
  }

  static pc.RSAPublicKey? publicKeyFromKeyTdoc(TsrctDoc keyTdoc) {
    Map<String,dynamic> jwks = extractJwksFromKeyTdoc(keyTdoc);
    Map<String,dynamic>? sigJwk = extractSigKeyFromJwks(jwks);
    if(sigJwk != null) {
      return jwkToPublicKey(sigJwk);
    }
    return null;
  }

  /// calculate the sha 256 digest of the payload and return the non-padded base64 string of the bytes
  static String sha256Digest(Uint8List payload) {
    final digest = pc.SHA256Digest();
    final Uint8List shaBytes = digest.process(payload);
    return base64UrlEncode(shaBytes);
  }

  static bool validateSignature(pc.RSAPublicKey publicKey, Uint8List signedData, Uint8List signature) {
    final sig = pc.RSASignature(signature);
    final verifier = pc.Signer('SHA-256/RSA');
    verifier.init(false, pc.PublicKeyParameter<pc.RSAPublicKey>(publicKey));
    return verifier.verifySignature(signedData, sig);
  }

  static Map<String,dynamic> extractJwksFromKeyTdoc(TsrctDoc tsrctDoc) {
    Map<String,dynamic> jwks = parseBase64ToJson(tsrctDoc.bodyBase64);
    return jwks;
  }

  static Map<String,dynamic>? extractSigKeyFromJwks(Map<String,dynamic> jwks) {
    List<dynamic> keys = jwks["keys"];
    for (var item in keys) {
      if(item["use"] == "sig") {
        return item;
      }
    }
    return null;
  }

  @deprecated
  static Map<String,dynamic> publicKeyToJwk(pc.RSAPublicKey publicKey, String kid, String alg, String use) {
    Map<String,dynamic> publicJwk = {};
    publicJwk["kid"] = kid;
    publicJwk["kty"] = "RSA";
    publicJwk["alg"] = alg;
    publicJwk["use"] = use; //"sig" or "enc";
    Uint8List expBytes = encodeBigInt(publicKey.publicExponent);
    Uint8List modBytes = encodeBigInt(publicKey.modulus);

    dev.log("public exponent: ${publicKey.publicExponent}");
    dev.log("public modulus: ${publicKey.modulus}");

    String expStr = base64UrlEncode(expBytes);
    publicJwk['exp'] = expStr;

    String modStr = base64UrlEncode(modBytes);
    publicJwk['mod'] = modStr;

    return publicJwk;
  }

  /// given the signing and encryption public keys, create the jwks key set that
  /// can be embedded in a tdoc
  /// prefer using [KeyActionsProvider] for the specific platform (e.g. gcp or aws, etc.)
  /// to get proper alg value setting
  @deprecated
  static Map<String,dynamic> convertKeySetToJwks(
      String keySetId,
      pc.RSAPublicKey sigKey,
      pc.RSAPublicKey encKey,
      ) {
    //alg types determined from: https://datatracker.ietf.org/doc/html/rfc7518#section-3.3
    Map<String,dynamic> sigJwk = publicKeyToJwk(sigKey, keySetId+"-sig", "RS256", "sig");

    //alg types determined from: https://datatracker.ietf.org/doc/html/rfc7518#section-4.3
    Map<String,dynamic> encJwk = publicKeyToJwk(encKey, keySetId+"-enc", "RSA-OAEP-256", "enc");

    Map<String,dynamic> jwks = {
      "keys": [
        sigJwk,
        encJwk
      ]
    };

    return jwks;
  }

  static pc.SecureRandom secureRandom() {

    final secureRandom = pc.SecureRandom('Fortuna')
      ..seed(pc.KeyParameter(Platform.instance.platformEntropySource().getBytes(32)));
    return secureRandom;
  }


  static ValidationResult validateTdoc(TsrctDoc tsrctDoc, TsrctDoc keyTdoc) {
    //track slf for syn type objects
    bool isSlf = false, slfOk = false;
    bool shaOk = false, sigOk = false, hbsOk = false;
    String errorMessage = "";

    pc.RSAPublicKey? currentPublicKey = publicKeyFromKeyTdoc(keyTdoc);
    if(currentPublicKey != null) {
      Uint8List bodyBytes = Uint8List.fromList(utf8.encode(tsrctDoc.bodyBase64));

      String calculatedSha = sha256Digest(bodyBytes);
      String providedSha = tsrctDoc.header["sha"];
      shaOk = providedSha == calculatedSha;
      if(!shaOk) {
        errorMessage += "sha not ok;";
      }
      if(tsrctDoc.header["slf"] != null) {
        isSlf = true;
        Uint8List slfBytes = base64UrlDecode(tsrctDoc.header["slf"]);
        slfOk = validateSignature(currentPublicKey, bodyBytes, slfBytes);
        if(!slfOk) {
          errorMessage += "slf not ok;";
        }
      }
      else {
        Uint8List sigBytes = base64UrlDecode(tsrctDoc.header["sig"]);
        sigOk = validateSignature(currentPublicKey, bodyBytes, sigBytes);
        if(!sigOk) {
          errorMessage += "sig not ok;";
        }
      }
      Uint8List hbsBytes = base64UrlDecode(tsrctDoc.hbsBase64);
      hbsOk = validateSignature(currentPublicKey, tsrctDoc.generateSignableBytes(), hbsBytes);
      if(!hbsOk) {
        errorMessage += "hbs not ok;";
      }
    }

    return ValidationResult(shaOk: shaOk, sigOk: sigOk, hbsOk: hbsOk, slfOk: slfOk, isSlf: isSlf, errorMessage: errorMessage);
  }

}

class ValidationResult {

  final bool isSlf;
  final bool slfOk;
  final bool shaOk;
  final bool sigOk;
  final bool hbsOk;

  final String? errorMessage;

  bool get ok => shaOk && sigOk && hbsOk;

  const ValidationResult({
    required this.isSlf,
    required this.slfOk,
    required this.shaOk,
    required this.sigOk,
    required this.hbsOk,
    this.errorMessage,
  });

}
