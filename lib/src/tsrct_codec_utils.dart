import 'dart:convert';
import 'dart:typed_data';


Uint8List base64UrlDecode(String input) {
  input = base64FixPadding(input);
  return base64Url.decode(input);
}

String base64UrlEncode(Uint8List bytes) {
  String base64Str = base64Url.encode(bytes);
  base64Str = base64Str.replaceAll('=', '');
  return base64Str;
}

/// padding fixing is important since tsrct uses unpadded base64
/// and dart standard libs insist on padding
String base64FixPadding(String input) {
  int gap = input.length % 4;
  switch(gap) {
    case 1:
      return input+"===";

    case 2:
      return input+"==";

    case 3:
      return input+"=";
  }
  return input;
}

String parseBase64ToString(String base64String) {
  Uint8List bytes = base64UrlDecode(base64String);
  return utf8.decode(bytes);
}

Map<String,dynamic> parseBase64ToJson(String base64String) {
  String jsonString = parseBase64ToString(base64String);
  Map<String,dynamic> jsonObject = json.decode(jsonString);
  return jsonObject;
}

String convertJsonToBase64(Map<String,dynamic> input) {
  String inputString = jsonEncode(input);
  return base64UrlEncode(Uint8List.fromList(inputString.codeUnits));
}
