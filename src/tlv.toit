// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

/**
A TLV (Type-Length-Value) block, as used in the NFC Forum Type 2 Tag
  Operation specification to lay out data in a tag's memory (eg. MIFARE
  Ultralight/NTAG pages), right after the Capability Container.
*/
class Tlv:
  /** Padding; no length or value follows. */
  static NULL ::= 0x00
  static LOCK-CONTROL ::= 0x01
  static MEMORY-CONTROL ::= 0x02
  static NDEF-MESSAGE ::= 0x03
  static PROPRIETARY ::= 0xFD
  /** Marks the end of the TLV area; no length or value follows. */
  static TERMINATOR ::= 0xFE

  tag/int
  value/ByteArray

  constructor .tag .value/ByteArray=#[]:

  /**
  Parses a sequence of TLV blocks from $bytes, stopping at a Terminator
    TLV or the end of $bytes, whichever comes first.
  */
  static parse-all bytes/ByteArray -> List:
    result := []
    index := 0
    while index < bytes.size:
      tag := bytes[index++]
      if tag == TERMINATOR: break
      if tag == NULL: continue

      length/int := ?
      if bytes[index] == 0xFF:
        length = (bytes[index + 1] << 8) | bytes[index + 2]
        index += 3
      else:
        length = bytes[index]
        index += 1

      value := bytes[index .. index + length]
      index += length
      result.add (Tlv tag value)
    return result

  /**
  Finds the value of the first NDEF Message TLV in $bytes, or null if
    there isn't one.
  */
  static find-ndef-message bytes/ByteArray -> ByteArray?:
    (parse-all bytes).do: | tlv/Tlv |
      if tlv.tag == NDEF-MESSAGE: return tlv.value
    return null

  /** Encodes this TLV back to its wire format. */
  to-byte-array -> ByteArray:
    if tag == NULL or tag == TERMINATOR: return #[tag]
    if value.size < 0xFF:
      return #[tag, value.size] + value
    return #[tag, 0xFF, (value.size >> 8) & 0xFF, value.size & 0xFF] + value

  stringify -> string:
    return "Tlv(tag=$(%02x tag), value.size=$value.size)"
