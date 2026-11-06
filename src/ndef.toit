// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

/**
A single NDEF (NFC Data Exchange Format) record.

See the NFC Forum NDEF Technical Specification for the wire format this
  is parsed from and encoded to.
*/
class NdefRecord:
  /** Empty record; no type, ID or payload. */
  static TNF-EMPTY ::= 0x00
  /** An NFC Forum well-known type (Record Type Definition), eg. Text or URI. */
  static TNF-WELL-KNOWN ::= 0x01
  /** A media type per RFC 2046 (MIME), eg. "text/plain". */
  static TNF-MEDIA-TYPE ::= 0x02
  /** An absolute URI per RFC 3986. */
  static TNF-ABSOLUTE-URI ::= 0x03
  /** An NFC Forum external type. */
  static TNF-EXTERNAL ::= 0x04
  /** The type is unknown; there is no type field. */
  static TNF-UNKNOWN ::= 0x05
  /** Only valid on a non-first chunk of a chunked record. */
  static TNF-UNCHANGED ::= 0x06
  static TNF-RESERVED ::= 0x07

  static TYPE-TEXT_ ::= #[0x54]  // 'T'
  static TYPE-URI_ ::= #[0x55]  // 'U'

  /**
  Maps a URI record's identifier code to its prefix. Only the common,
    well-established prefixes from the NFC Forum URI Record Type
    Definition are covered; an unrecognized code is left with an empty
    prefix (see $uri).
  */
  static URI-PREFIXES_ ::= {
    0x00: "",
    0x01: "http://www.",
    0x02: "https://www.",
    0x03: "http://",
    0x04: "https://",
    0x05: "tel:",
    0x06: "mailto:",
  }

  tnf/int
  type/ByteArray
  id/ByteArray
  payload/ByteArray

  constructor --.tnf/int --.type/ByteArray=#[] --.id/ByteArray=#[] --.payload/ByteArray=#[]:

  /**
  Constructs a well-known Text record.

  $language should be a short IANA language code, eg. "en" or "en-US".
  The text is always encoded as UTF-8, never UTF-16.
  */
  constructor.text text/string --language/string="en":
    tnf = TNF-WELL-KNOWN
    type = TYPE-TEXT_
    id = #[]
    language-bytes := language.to-byte-array
    if language-bytes.size > 0x3F: throw "INVALID_ARGUMENT"
    // Bit 7 (UTF-16 flag) stays 0: this is always UTF-8.
    status := language-bytes.size
    payload = #[status] + language-bytes + text.to-byte-array

  /**
  Constructs a well-known URI record.

  Picks the longest matching prefix from $URI-PREFIXES_ so the encoded
    payload is as small as possible.
  */
  constructor.uri uri/string:
    tnf = TNF-WELL-KNOWN
    type = TYPE-URI_
    id = #[]
    best-code := 0x00
    best-prefix := ""
    URI-PREFIXES_.do --keys: | code/int |
      prefix := URI-PREFIXES_[code]
      if prefix != "" and uri.starts-with prefix and prefix.size > best-prefix.size:
        best-code = code
        best-prefix = prefix
    payload = #[best-code] + uri[best-prefix.size..].to-byte-array

  /** Whether this is a well-known Text record; see $text. */
  is-text -> bool: return tnf == TNF-WELL-KNOWN and type == TYPE-TEXT_

  /**
  Decodes this record's payload as NDEF Text.

  Throws if this is not $is-text, or if the text is UTF-16 encoded (not
    supported).
  */
  text -> string:
    if not is-text: throw "Not a text record"
    status := payload[0]
    if status & 0x80 != 0: throw "UTF-16 text records are not supported"
    language-code-length := status & 0x3F
    return payload[1 + language-code-length ..].to-string

  /** Whether this is a well-known URI record; see $uri. */
  is-uri -> bool: return tnf == TNF-WELL-KNOWN and type == TYPE-URI_

  /**
  Decodes this record's payload as an NDEF URI.

  If the identifier code isn't one of the common ones in $URI-PREFIXES_,
    the field is returned without any prefix added.
  */
  uri -> string:
    if not is-uri: throw "Not a URI record"
    identifier-code := payload[0]
    prefix := URI-PREFIXES_.get identifier-code --if-absent=(: "")
    return prefix + payload[1..].to-string

  stringify -> string:
    if is-text: return "NdefRecord(Text, \"$text\")"
    if is-uri: return "NdefRecord(URI, \"$uri\")"
    return "NdefRecord(tnf=$tnf, type=$type, id=$id, payload.size=$payload.size)"

/**
An ordered sequence of $NdefRecord, as found inside an NDEF Message TLV
  (see `Tlv.find-ndef-message` in this package).
*/
class NdefMessage:
  records/List

  constructor .records/List:

  /**
  Parses $bytes as an NDEF message.

  Throws if a record is chunked (the continuation-fragment mechanism for
    very large payloads): that is not supported here.
  */
  static parse bytes/ByteArray -> NdefMessage:
    records := []
    index := 0
    first := true
    while index < bytes.size:
      header := bytes[index++]
      mb := header & 0x80 != 0
      me := header & 0x40 != 0
      cf := header & 0x20 != 0
      sr := header & 0x10 != 0
      il := header & 0x08 != 0
      tnf := header & 0x07

      if first and not mb: throw "First NDEF record must have the MB flag set"
      if not first and mb: throw "Only the first NDEF record may have the MB flag set"
      if cf or tnf == NdefRecord.TNF-UNCHANGED: throw "Chunked NDEF records are not supported"

      type-length := bytes[index++]
      payload-length/int := ?
      if sr:
        payload-length = bytes[index++]
      else:
        payload-length = (bytes[index] << 24) | (bytes[index + 1] << 16) |
            (bytes[index + 2] << 8) | bytes[index + 3]
        index += 4
      id-length := 0
      if il:
        id-length = bytes[index++]

      type := bytes[index .. index + type-length]
      index += type-length
      id := il ? bytes[index .. index + id-length] : #[]
      index += id-length
      payload := bytes[index .. index + payload-length]
      index += payload-length

      records.add (NdefRecord --tnf=tnf --type=type --id=id --payload=payload)

      first = false
      if me: break

    return NdefMessage records

  /** Encodes this message back to its wire format. */
  to-byte-array -> ByteArray:
    if records.is-empty: throw "INVALID_ARGUMENT"
    result := #[]
    records.size.repeat: | i |
      record := records[i]
      mb := i == 0
      me := i == records.size - 1
      sr := record.payload.size <= 0xFF
      il := record.id.size > 0

      header := record.tnf
      if mb: header |= 0x80
      if me: header |= 0x40
      if sr: header |= 0x10
      if il: header |= 0x08

      result += #[header, record.type.size]
      if sr:
        result += #[record.payload.size]
      else:
        size := record.payload.size
        result += #[(size >> 24) & 0xFF, (size >> 16) & 0xFF, (size >> 8) & 0xFF, size & 0xFF]
      if il:
        result += #[record.id.size]
      result += record.type
      if il: result += record.id
      result += record.payload
    return result

  stringify -> string:
    return "NdefMessage($records)"
