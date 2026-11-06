// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

/**
A minimal reader/writer for Flipper Zero's `.nfc` device file format.

Flipper's own format has evolved across firmware versions. This only
  handles the stable backbone common to MIFARE Classic and MIFARE
  Ultralight/NTAG dumps: the header fields ($device-type, $uid, $atqa,
  $sak) and the per-block/per-page hex dump lines ($blocks). Every other
  "Key: value" line (eg. counters, tearing flags, the originality
  signature) is kept verbatim in $extra-fields rather than being
  interpreted, and unrecognized lines are tolerated rather than
  rejected, so this stays usable across firmware versions that add
  fields it doesn't know about.
*/
class FlipperNfcFile:
  device-type/string
  uid/ByteArray
  atqa/ByteArray
  sak/int
  /** Block (MIFARE Classic) or page (Ultralight/NTAG) dumps, keyed by number. */
  blocks/Map
  /** Every other "Key: value" line, kept verbatim, in file order. */
  extra-fields/Map

  constructor .device-type --.uid --.atqa --.sak --blocks/Map=({:}) --extra-fields/Map=({:}):
    this.blocks = blocks
    this.extra-fields = extra-fields

  /** Parses a Flipper `.nfc` file's $text. */
  static parse text/string -> FlipperNfcFile:
    device-type/string? := null
    uid/ByteArray? := null
    atqa/ByteArray? := null
    sak/int? := null
    block-map := {:}
    extra-map := {:}

    lines := text.split "\n"
    lines.do: | line/string |
      trimmed := line.trim
      if trimmed.is-empty or trimmed.starts-with "#": continue.do

      colon := trimmed.index-of ":"
      if colon < 0: continue.do
      key := trimmed[..colon].trim
      value := trimmed[colon + 1 ..].trim

      if key == "Device type":
        device-type = value
      else if key == "UID":
        uid = parse-hex-bytes_ value
      else if key == "ATQA":
        atqa = parse-hex-bytes_ value
      else if key == "SAK":
        sak = int.parse value --radix=16
      else if key.starts-with "Block " or key.starts-with "Page ":
        space := key.index-of " "
        number := int.parse key[space + 1 ..]
        block-map[number] = parse-hex-bytes_ value
      else if key == "Filetype" or key == "Version":
        // Recognized, but not interesting to a caller; drop silently
        // instead of parking them in extra-fields.
        null
      else:
        extra-map[key] = value

    if not device-type or not uid or not atqa or sak == null:
      throw "Missing required field (Device type/UID/ATQA/SAK)"

    return FlipperNfcFile device-type --uid=uid --atqa=atqa --sak=sak --blocks=block-map --extra-fields=extra-map

  /** Encodes this file back to Flipper `.nfc` text. */
  stringify -> string:
    lines := []
    lines.add "Filetype: Flipper NFC device"
    lines.add "Version: 2"
    lines.add "Device type: $device-type"
    lines.add "UID: $(bytes-to-hex_ uid)"
    lines.add "ATQA: $(bytes-to-hex_ atqa)"
    lines.add "SAK: $(%02X sak)"
    extra-fields.do --keys: | key |
      lines.add "$key: $extra-fields[key]"

    is-page := device-type.contains "Ultralight" or device-type.contains "NTAG"
    label := is-page ? "Page" : "Block"
    keys := blocks.keys.sort
    keys.do: | number |
      lines.add "$label $number: $(bytes-to-hex_ blocks[number])"

    return lines.join "\n"

  static parse-hex-bytes_ value/string -> ByteArray:
    parts := value.split " "
    return ByteArray parts.size: int.parse parts[it] --radix=16

  static bytes-to-hex_ bytes/ByteArray -> string:
    result := ""
    bytes.size.repeat:
      if it > 0: result += " "
      result += "$(%02X bytes[it])"
    return result
