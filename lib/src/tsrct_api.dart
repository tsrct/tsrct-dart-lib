import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

class TsrctApi {
  final String apiEndpoint;

  TsrctApi(this.apiEndpoint);

  Future<Map<String,dynamic>> getChecksum(String tempId) async {
    http.Response response = await http.get(Uri.parse("$apiEndpoint/i/checksum/$tempId"));
    Map<String,dynamic> responseMap = json.decode(response.body);
    return responseMap;
  }

  Future<Map<String,dynamic>> getTidExists(String tempId) async {
    http.Response response = await http.get(Uri.parse("$apiEndpoint/i/exists/$tempId"));
    Map<String,dynamic> responseMap = json.decode(response.body);
    return responseMap;
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
  /// these are the uids in the list of refs included in a header
  /// the information returned will be used to validate the content of the header ref entries
  Future<ApiResponse> getRefs(String idList) async {
    http.Response response = await http.get(Uri.parse("$apiEndpoint/d/ref?ids=$idList"));
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

  Future<ApiResponse> postTdoc(String tdoc) async {
    http.Response response =
    await http.post(
      Uri.parse("$apiEndpoint"),
      body: tdoc,
      encoding: utf8,
    );
    ApiResponse apiResponse = ApiResponse.parse(response.statusCode, ApiResponseType.json, "application/json", response.bodyBytes);
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