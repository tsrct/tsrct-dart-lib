import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'dart:developer' as dev;

import 'package:intl/intl.dart';

import 'package:pointycastle/src/utils.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:tsrct_dart_lib/src/tsrct_api.dart';
import 'package:tsrct_dart_lib/src/tsrct_codec_utils.dart';
import 'package:tsrct_dart_lib/src/tsrct_doc.dart';
import 'package:pointycastle/src/platform_check/platform_check.dart';
import 'package:tsrct_dart_lib/src/tsrct_key_actions.dart';

class TsrctCommonOps {
  static final DateFormat _keyIdDateFormat = DateFormat("yyyyMMddHHmmss");
  static final DateFormat _tdocDateFormat = DateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
  static final List<int> chars = "abcdefghijklmnopqrstuvwxyz0123456789".codeUnits;
  static final Random _random = Random.secure();

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

  static String generateUid(String prefix) {
    List<int> suffix = List.from(getNowAsKeyIdDateFormat().codeUnits, growable: true);
    for(int i=0; i<8; i++) {
      suffix.add(chars[_random.nextInt(chars.length)]);
    }
    return "$prefix.${String.fromCharCodes(suffix)}";
  }

  /// takes a single jwk entry in the keys jwks to create the public key
  static pc.RSAPublicKey jwkToPublicKey(Map<String,dynamic> jwk) {
    String expStrBase64 = jwk['e'];
    Uint8List expBytes = base64UrlDecode(expStrBase64);
    BigInt exp = decodeBigInt(expBytes);

    String modStrBase64 = jwk['n'];
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
    publicJwk['e'] = expStr;

    String modStr = base64UrlEncode(modBytes);
    publicJwk['n'] = modStr;

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
      Uint8List bodyBytes = convertStringToBytes(tsrctDoc.bodyBase64); //Uint8List.fromList(utf8.encode(tsrctDoc.bodyBase64));

      String calculatedSha = sha256Digest(bodyBytes);
      String providedSha = tsrctDoc.header["sha"];
      shaOk = providedSha == calculatedSha;
      if(!shaOk) {
        errorMessage += "sha not ok;";
      }
      if(tsrctDoc.header["slf"] != null) {
        isSlf = true;
        String slf = tsrctDoc.header["slf"];
        Uint8List slfBytes = base64UrlDecode(slf);
        pc.RSAPublicKey slfValidationKey = publicKeyFromKeyTdoc(tsrctDoc)!;
        slfOk = validateSignature(slfValidationKey, bodyBytes, slfBytes);
        if(!slfOk) {
          errorMessage += "slf not ok;";
        }
        // if(tsrctDoc.header["sig"] != null) {
        //   String sig = tsrctDoc.header["sig"];
        //   sigOk = sig == slf;
        // }
      }

      // validate sig
      Uint8List sigBytes = base64UrlDecode(tsrctDoc.header["sig"]);
      sigOk = validateSignature(currentPublicKey, bodyBytes, sigBytes);
      if(!sigOk) {
        errorMessage += "sig not ok;";
      }

      Uint8List hbsBytes = base64UrlDecode(tsrctDoc.hbsBase64);
      hbsOk = validateSignature(currentPublicKey, tsrctDoc.generateSignableBytes(), hbsBytes);
      if(!hbsOk) {
        errorMessage += "hbs not ok;";
      }
    }

    return ValidationResult(shaOk: shaOk, sigOk: sigOk, hbsOk: hbsOk, slfOk: slfOk, isSlf: isSlf, errorMessage: errorMessage);
  }

  static Future<DdxValidationResult> validateDdx(
      Map<String,dynamic> ddx,
      DdxValidationEventListener? listener,
      TsrctApi tsrctApi,
      Map<String,dynamic> header,
      ValidationResult validationResult,
      ) async {
    bool ddxOk = false;
    bool reqOk = false;
    bool resOk = false;
    bool srcOk = false;
    bool tgtOk = false;
    bool itsOk = false;

    String uid = ddx["uid"];
    Map<String,dynamic> req = ddx["req"];
    Map<String,dynamic> res = ddx["res"];

    //first do a sanity check of the value so a bad ddx can be failed quickly
    Map<String,String> reqValMap = _parseDdxVal(req["val"]);
    Map<String,String> resValMap = _parseDdxVal(res["val"]);
    bool validationSigOk = reqValMap["sig"] == resValMap["sig"] && reqValMap["sig"] == header["sig"] && validationResult.sigOk;
    bool validationShaOk = reqValMap["sha"] == resValMap["sha"] && reqValMap["sha"] == header["sha"] && validationResult.shaOk;

    if(!validationShaOk || !validationSigOk) {
      var result = DdxValidationResult(uid: uid, ddxOk: ddxOk, reqOk: reqOk, resOk: resOk, srcOk: srcOk, tgtOk: tgtOk, itsOk: itsOk);
      listener?.handleDdxValidationResult(result);
      return result;
    }

    //sanity check successful, proceed with other items:

    listener?.handleDdxValidationEvent(DdxValidationEvent.ddxInfoRequested);
    TsrctDoc? ddxDoc = await getTsrctDocByUid(uid, tsrctApi);
    listener?.handleDdxValidationEvent(DdxValidationEvent.ddxInfoReceived);
    if(ddxDoc == null) {
      var result = DdxValidationResult(uid: uid, ddxOk: ddxOk, reqOk: reqOk, resOk: resOk, srcOk: srcOk, tgtOk: tgtOk, itsOk: itsOk);
      listener?.handleDdxValidationResult(result);
      return result;
    }
    ddxOk = ddxDoc.header["tgt"] == req["src"];
    if(!ddxOk) {
      var result = DdxValidationResult(uid: uid, ddxOk: ddxOk, reqOk: reqOk, resOk: resOk, srcOk: srcOk, tgtOk: tgtOk, itsOk: itsOk);
      listener?.handleDdxValidationResult(result);
      return result;
    }
    else {
      srcOk = true;
      tgtOk = true;
    }

    String reqKey = req["key"];
    listener?.handleDdxValidationEvent(DdxValidationEvent.reqKeyRequested);
    TsrctDoc? reqKeyDoc = await getTsrctDocByUid(reqKey, tsrctApi);
    listener?.handleDdxValidationEvent(DdxValidationEvent.reqKeyReceived);
    if(reqKeyDoc == null) {
      var result = DdxValidationResult(uid: uid, ddxOk: ddxOk, reqOk: reqOk, resOk: resOk, srcOk: srcOk, tgtOk: tgtOk, itsOk: itsOk);
      listener?.handleDdxValidationResult(result);
      return result;
    }

    pc.RSAPublicKey? reqPublicKey = publicKeyFromKeyTdoc(reqKeyDoc);
    Uint8List reqVal = convertStringToBytes(req["val"]); // Uint8List.fromList(utf8.encode(req["val"]));
    Uint8List reqSig = base64UrlDecode(req["sig"]);
    reqOk = validateSignature(reqPublicKey!, reqVal, reqSig);
    if(!reqOk) {
      var result = DdxValidationResult(uid: uid, ddxOk: ddxOk, reqOk: reqOk, resOk: resOk, srcOk: srcOk, tgtOk: tgtOk, itsOk: itsOk);
      listener?.handleDdxValidationResult(result);
      return result;
    }
    listener?.handleDdxValidationEvent(DdxValidationEvent.reqValidated);

    pc.RSAPublicKey? ddxPublicKey = publicKeyFromKeyTdoc(ddxDoc);
    Uint8List resVal = convertStringToBytes(res["val"]); // Uint8List.fromList(utf8.encode(res["val"]));
    Uint8List resSig = base64UrlDecode(res["sig"]);
    bool resShaOk = TsrctCommonOps.sha256Digest(resVal) == res["sha"];
    bool resSigOk = validateSignature(ddxPublicKey!, resVal, resSig);
    resOk = resShaOk && resSigOk;
    if(!resOk) {
      var result = DdxValidationResult(uid: uid, ddxOk: ddxOk, reqOk: reqOk, resOk: resOk, srcOk: srcOk, tgtOk: tgtOk, itsOk: itsOk);
      listener?.handleDdxValidationResult(result);
      return result;
    }
    listener?.handleDdxValidationEvent(DdxValidationEvent.resValidated);

    bool itsIsAppended = "${req['val']}&its=${res['its']}" == res['val'];
    int reqNce = req["nce"];
    int valNce = int.parse(reqValMap["nce"]!);
    DateTime resIts = DateTime.parse(res["its"]);
    int resNce = resIts.millisecondsSinceEpoch ~/ 1000;
    bool itsIsTimely = (reqNce == valNce) && ((reqNce - resNce).abs() <=10);
    itsOk = itsIsAppended && itsIsTimely;
    if(itsOk) {
      listener?.handleDdxValidationEvent(DdxValidationEvent.itsValidated);
    }

    var result = DdxValidationResult(uid: uid, ddxOk: ddxOk, reqOk: reqOk, resOk: resOk, srcOk: srcOk, tgtOk: tgtOk, itsOk: itsOk);
    listener?.handleDdxValidationResult(result);
    return result;
  }

  static Map<String,String> _parseDdxVal(String val) {
    Map<String,String> valMap = {};
    List<String> entires = val.split("&");
    for (String entry in entires) {
      List<String> pair = entry.split("=");
      valMap[pair[0]] = pair[1];
    }

    return valMap;
  }

  static Future<TsrctDoc?> getTsrctDocByUid(String uid, TsrctApi tsrctApi) async {
    ApiResponse response = await tsrctApi.getTdocByUid(uid);
    if(response.ok && response.tdoc != null) {
      TsrctDoc tsrctDoc = TsrctDoc.parse(response.tdoc!);
      return tsrctDoc;
    }
    return null;
  }

  static Map<String,dynamic> buildCommonHeader(Map<String,dynamic>? properties) {
    Map<String,dynamic> header = {
    };
    if(properties != null) {
      header.addAll(properties);
    }
    return header;
  }

  /// given a tsrct doc with a complete header
  /// appends the signature based on the signing key resource
  static Future<TsrctDoc> buildTsrctDoc(
      Map<String,dynamic> header,
      String bodyBase64,
      String sigResourceName,
      KeyActionsProvider keyActionsProvider,
  ) async {
    TsrctDoc tsrctDoc = TsrctDoc.init(header, bodyBase64);
    Uint8List signable = tsrctDoc.generateSignableBytes();
    String sha = TsrctCommonOps.sha256Digest(signable);
    String signature = await keyActionsProvider.signDigest(sigResourceName, base64UrlDecode(sha));
    tsrctDoc.hbsBase64 = signature;
    return tsrctDoc;
  }

  /// adds alg, its, len, nce, sig, sha,
  /// if includeslf is true, then slf is added and set to the value of sig
  static Future<TsrctDoc> buildSignedTsrctDoc(
      Map<String,dynamic> header,
      bool includeSlf,
      String bodyBase64,
      String sigResourceName,
      KeyActionsProvider keyActionsProvider,
  ) async {
    Uint8List bodyBase64Bytes = Uint8List.fromList(utf8.encode(bodyBase64));
    String sha = TsrctCommonOps.sha256Digest(bodyBase64Bytes);
    String sig = await keyActionsProvider.signDigest(sigResourceName, base64UrlDecode(sha));

    Map<String,dynamic> addedProperties = {
      "alg": "RS256",
      "sig": sig,
      "sha": sha,
      "its": getNowAsTdocDateFormat(),
      "len": bodyBase64.length,
      "nce": getNonce(),
    };
    header.addAll(addedProperties);
    if(includeSlf) {
      header["slf"] = sig;
    }
    TsrctDoc tsrctDoc =
      await buildTsrctDoc(
          header,
          bodyBase64,
          sigResourceName,
          keyActionsProvider
      );
    return tsrctDoc;
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

  @override
  String toString() {
    return 'ValidationResult{isSlf: $isSlf, slfOk: $slfOk, shaOk: $shaOk, sigOk: $sigOk, hbsOk: $hbsOk, errorMessage: $errorMessage}';
  }


}

class DdxValidationResult {
  final String uid;
  final bool ddxOk;
  final bool reqOk;
  final bool resOk;
  final bool srcOk;
  final bool tgtOk;
  final bool itsOk;

  final String? errorMessage;

  bool get ok => ddxOk && reqOk && resOk && srcOk && tgtOk && itsOk;

  const DdxValidationResult({
    required this.uid,
    required this.ddxOk,
    required this.reqOk,
    required this.resOk,
    required this.srcOk,
    required this.tgtOk,
    required this.itsOk,
    this.errorMessage,
  });

  Map<String,dynamic> toJson() {
    return {
      "reqOk": reqOk,
      "resOk": resOk,
      "srcOk": srcOk,
      "tgtOk": tgtOk,
      "itsOk": itsOk,
      "ok": ok,
      "errorMessage": errorMessage ?? "",
    };
  }
}

abstract class DdxValidationEventListener {
  void handleDdxValidationEvent(DdxValidationEvent event);
  void handleDdxValidationResult(DdxValidationResult result);
}

enum DdxValidationEvent {
  ddxInfoRequested,
  ddxInfoReceived,
  reqKeyRequested,
  reqKeyReceived,
  reqValidated,
  resValidated,
  itsValidated,
}

abstract class JwtProvider {
  String generateJwt(String actionName);
}