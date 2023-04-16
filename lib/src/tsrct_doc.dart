import 'dart:typed_data';

import 'package:tsrct_dart_lib/src/tsrct_codec_utils.dart';

class TsrctDoc {
  late Map<String,dynamic> header;
  late String headerBase64;
  late String bodyBase64;
  late String hbsBase64;

  factory TsrctDoc.empty() {
    return TsrctDoc._internal();
  }

  /// this assumes a happy h.b.s format with no errors
  factory TsrctDoc.parse(String tdocString) {
    TsrctDoc doc = TsrctDoc._internal();
    List<String> segments = tdocString.split(".");
    doc.headerBase64 = segments[0];
    doc.header = parseBase64ToJson(segments[0]);
    doc.bodyBase64 = segments[1];
    doc.hbsBase64 = segments[2];

    return doc;
  }

  TsrctDoc._internal();

  Uint8List generateSignableBytes() {
    return Uint8List.fromList("$headerBase64.$bodyBase64".codeUnits);
  }

  String generateRawTdoc() {
    return "$headerBase64.$bodyBase64.$hbsBase64";
  }
}
