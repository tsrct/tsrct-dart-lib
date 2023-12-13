import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:tsrct_dart_lib/src/tsrct_operations.dart';

class TsrctApi {
  final String apiEndpoint;

  TsrctApi(this.apiEndpoint);

  Future<Map<String,dynamic>> getApiInfo() async {
    http.Response response = await http.get(Uri.parse("$apiEndpoint/"));
    Map<String,dynamic> responseMap = json.decode(response.body);
    return responseMap;
  }

  Future<Map<String,dynamic>> getChecksum(String tempId) async {
    http.Response response = await http.get(Uri.parse("$apiEndpoint/i/checksum/$tempId"));
    Map<String,dynamic> responseMap = json.decode(response.body);
    return responseMap;
  }

  Future<Map<String,dynamic>> getUidExists(String tempId) async {
    http.Response response = await http.get(Uri.parse("$apiEndpoint/i/exists/$tempId"));
    Map<String,dynamic> responseMap = json.decode(response.body);
    return responseMap;
  }

  Future<ApiResponse> getHeaderByUid(String uid) async {
    http.Response response = await http.get(Uri.parse("$apiEndpoint/$uid"));
    ApiResponse apiResponse = ApiResponse.parse(response.statusCode, ApiResponseType.json, "application/json", response.bodyBytes);
    return apiResponse;
  }

  Future<ApiResponse> getTdocByUid(String uid) async {
    http.Response response = await http.get(Uri.parse("$apiEndpoint/$uid/tdoc"));
    ApiResponse apiResponse = ApiResponse.parse(response.statusCode, ApiResponseType.tdoc, "text/plain", response.bodyBytes);
    return apiResponse;
  }

  Future<ApiResponse> getTags(String uid) async {
    http.Response response = await http.get(Uri.parse("$apiEndpoint/$uid/tags"));
    ApiResponse apiResponse = ApiResponse.parse(response.statusCode, ApiResponseType.json, "application/json", response.bodyBytes);
    return apiResponse;
  }

  /// given a list of comma delimited uids, get the ref package for each id
  /// these are the uids in the list of refs to be included in a header
  /// the information returned will be used to validate the content of the header ref entries
  Future<ApiResponse> getRefs(String idList) async {
    http.Response response = await http.get(Uri.parse("$apiEndpoint/d/ref?uids=$idList"));
    ApiResponse apiResponse = ApiResponse.parse(response.statusCode, ApiResponseType.json, "application/json", response.bodyBytes);
    return apiResponse;
  }

  /// given a specific uid, get the list of refs contained in the header
  Future<ApiResponse> getHeaderRefs(String uid) async {
    http.Response response = await http.get(Uri.parse("$apiEndpoint/d/header/ref?id=$uid"));
    ApiResponse apiResponse = ApiResponse.parse(response.statusCode, ApiResponseType.json, "application/json", response.bodyBytes);
    return apiResponse;
  }

  /// given a specific uid, get the full ref tree dag
  Future<ApiResponse> getRefDag(String uid) async {
    http.Response response = await http.get(Uri.parse("$apiEndpoint/$uid/dag"));
    ApiResponse apiResponse = ApiResponse.parse(response.statusCode, ApiResponseType.json, "application/json", response.bodyBytes);
    return apiResponse;
  }

  Future<ApiResponse> getDdxForTgt(String uid) async {
    http.Response response = await http.get(Uri.parse("$apiEndpoint/ddx/list/$uid"));
    ApiResponse apiResponse = ApiResponse.parse(response.statusCode, ApiResponseType.json, "application/json", response.bodyBytes);
    return apiResponse;
  }

  /// given a ddx uid, get the summary info for the item, incl src domain data
  Future<ApiResponse> getDdxInfoForUid(String uid) async {
    http.Response response = await http.get(Uri.parse("$apiEndpoint/ddx/info/$uid"));
    ApiResponse apiResponse = ApiResponse.parse(response.statusCode, ApiResponseType.json, "application/json", response.bodyBytes);
    return apiResponse;
  }

  Future<ApiResponse> getTdocsForSrc(String uid, String? cursor) async {
    http.Response response = await http.get(Uri.parse("$apiEndpoint/d/tdocs?src=$uid${cursor==null?'':'&cursor=$cursor'}"));
    ApiResponse apiResponse = ApiResponse.parse(response.statusCode, ApiResponseType.json, "application/json", response.bodyBytes);
    return apiResponse;
  }

  Future<ApiResponse> getDdxBadgesForTgt(JwtProvider jwtProvider, String? cursor) async {
    return await getJwtAction(jwtProvider, "/services/ddx/badges", cursor);
  }

  Future<ApiResponse> getJwtAction(
      JwtProvider jwtProvider,
      String action,
      String? cursor,
  ) async {
    String jwt = jwtProvider.generateJwt("GET:$action");
    http.Response response = await http.get(
      Uri.parse("$apiEndpoint$action${cursor==null?'':'?cursor=$cursor'}"),
      headers: {
          "x-tsrct-auth": jwt,
      },
    );
    ApiResponse apiResponse = ApiResponse.parse(response.statusCode, ApiResponseType.json, "application/json", response.bodyBytes);
    return apiResponse;
  }

  Future<ApiResponse> postTdoc(String tdoc) async {
    http.Response response = await http.post(
      Uri.parse("$apiEndpoint"),
      body: tdoc,
      encoding: utf8,
    );
    ApiResponse apiResponse = ApiResponse.parse(
        response.statusCode,
        ApiResponseType.json,
        "application/json",
        response.bodyBytes
    );
    return apiResponse;
  }

  Future<ApiResponse> postTdocToPath(String path, String tdoc) async {
    http.Response response = await http.post(
      Uri.parse("$apiEndpoint$path"),
      body: tdoc,
      headers: {
        "content-type": "text/plain",
      },
      encoding: utf8,
    );
    ApiResponse apiResponse = ApiResponse.parse(
        response.statusCode,
        ApiResponseType.json,
        "application/json",
        response.bodyBytes
    );
    return apiResponse;
  }

  /// post the given json to the provided path
  /// the path must begin with /, e.g. /path/to/endpoint
  Future<ApiResponse> postJson(String path, Map<String,dynamic> jsonToPost) async {
    http.Response response = await http.post(
        Uri.parse("$apiEndpoint$path"),
        body: jsonEncode(jsonToPost),
        encoding: utf8,
        headers: {
          "content-type": "application/json"
        }
    );
    ApiResponse apiResponse = ApiResponse.parse(
        response.statusCode,
        ApiResponseType.json,
        "application/json",
        response.bodyBytes
    );
    return apiResponse;
  }

}

class ApiResponse {
  late bool _ok;
  late int _status;
  late Map<String,dynamic>? _jsonResponse;
  late String? _tdoc;
  late String? _text;
  late Uint8List? _bytes;

  late ApiResponseType _type;
  late String _contentType;

  bool get ok => _ok;
  int get status => _status;
  ApiResponseType get type => _type;
  String get contentType => _contentType;

  Map<String,dynamic>? get jsonResponse => _jsonResponse;
  String? get tdoc => _tdoc;
  String? get text => _text;
  Uint8List? get bytes => _bytes;

  factory ApiResponse.parse(
      int statusCode,
      ApiResponseType type,
      String contentType,
      Uint8List bytes,
      ) {
    final ApiResponse response = ApiResponse._internal();
    response._status = statusCode;

    if(statusCode == 200) {
      response._ok = true;
      response._contentType = contentType;
      response._type = type;
      switch(type) {
        case ApiResponseType.json:
          String body = utf8.decode(bytes);
          response._jsonResponse = json.decode(body);
          break;
        case ApiResponseType.tdoc:
          String body = utf8.decode(bytes);
          response._tdoc = body;
          break;
        case ApiResponseType.text:
          String body = utf8.decode(bytes);
          response._text = body;
          break;
        case ApiResponseType.binary:
          response._bytes = bytes;
          break;
      }
    }
    else {
      String body = utf8.decode(bytes);
      response._contentType = "application/json";
      response._jsonResponse = json.decode(body);
      response._ok = response.jsonResponse!["status"] == "ok";
    }

    return response;
  }

  factory ApiResponse.parseTdoc(
      String tdoc,
      ) {
    final ApiResponse response = ApiResponse._internal();
    response._status = 200;
    response._ok = true;
    response._type = ApiResponseType.tdoc;
    response._contentType = "text/plain";
    response._tdoc = tdoc;

    return response;
  }

  ApiResponse._internal();
}

enum ApiResponseType {
  json,
  tdoc,
  text,
  binary,
}