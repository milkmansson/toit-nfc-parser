// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by a Zero-Clause BSD license that can
// be found in the TESTS_LICENSE file.

import expect show *
import crypto.crc show Crc
import nfc-parser.ndef show NdefRecord NdefMessage
import nfc-parser.tlv show Tlv
import nfc-parser.mad show Mad
import nfc-parser.flipper show FlipperNfcFile

main:
  test-ndef-text
  test-ndef-uri
  test-ndef-message-round-trip
  test-ndef-rejects-chunked
  test-tlv-round-trip
  test-tlv-find-ndef-message
  test-mad-crc-algorithm
  test-mad-round-trip
  test-mad-crc-rejects-corruption
  test-flipper-classic-round-trip
  test-flipper-ultralight-round-trip
  test-flipper-tolerates-unknown-fields

test-ndef-text:
  record := NdefRecord.text "hello" --language="en"
  expect record.is-text
  expect-equals "hello" record.text
  expect-not record.is-uri

test-ndef-uri:
  record := NdefRecord.uri "https://www.example.com/path"
  expect record.is-uri
  expect-equals "https://www.example.com/path" record.uri
  // Picked the "https://www." prefix (0x02), so only the remainder is stored.
  expect-equals 0x02 record.payload[0]
  expect-equals "example.com/path" record.payload[1..].to-string

  // An unrecognized scheme still round-trips, just with no prefix picked.
  ftp := NdefRecord.uri "ftp://example.com"
  expect-equals "ftp://example.com" ftp.uri

test-ndef-message-round-trip:
  message := NdefMessage [
    NdefRecord.text "hello world",
    NdefRecord.uri "https://example.com",
  ]
  bytes := message.to-byte-array
  parsed := NdefMessage.parse bytes
  expect-equals 2 parsed.records.size
  expect parsed.records[0].is-text
  expect-equals "hello world" parsed.records[0].text
  expect parsed.records[1].is-uri
  expect-equals "https://example.com" parsed.records[1].uri

  // A single record is its own begin and end.
  single := NdefMessage [NdefRecord.text "solo"]
  single-parsed := NdefMessage.parse single.to-byte-array
  expect-equals 1 single-parsed.records.size
  expect-equals "solo" single-parsed.records[0].text

test-ndef-rejects-chunked:
  // A record with the chunk flag (bit 5) set.
  chunked-header := 0x80 | 0x20 | 0x10 | NdefRecord.TNF-WELL-KNOWN
  bytes := #[chunked-header, 1, 4, 'T', 0x61, 0x61, 0x61, 0x61]
  expect-throw "Chunked NDEF records are not supported":
    NdefMessage.parse bytes

test-tlv-round-trip:
  tlvs := [
    Tlv Tlv.LOCK-CONTROL #[0x01, 0x02, 0x03],
    Tlv Tlv.NDEF-MESSAGE #[0xAA, 0xBB, 0xCC, 0xDD],
  ]
  bytes := #[]
  tlvs.do: bytes += it.to-byte-array
  bytes += #[Tlv.TERMINATOR]

  parsed := Tlv.parse-all bytes
  expect-equals 2 parsed.size
  expect-equals Tlv.LOCK-CONTROL parsed[0].tag
  expect-bytes-equal #[0x01, 0x02, 0x03] parsed[0].value
  expect-equals Tlv.NDEF-MESSAGE parsed[1].tag
  expect-bytes-equal #[0xAA, 0xBB, 0xCC, 0xDD] parsed[1].value

  // A long (>= 0xFF) TLV uses the 3-byte length form.
  long-value := ByteArray 300: it & 0xFF
  long-tlv := Tlv Tlv.PROPRIETARY long-value
  long-bytes := long-tlv.to-byte-array
  expect-equals 0xFF long-bytes[1]
  reparsed := Tlv.parse-all (long-bytes + #[Tlv.TERMINATOR])
  expect-equals 1 reparsed.size
  expect-bytes-equal long-value reparsed[0].value

test-tlv-find-ndef-message:
  message := NdefMessage [NdefRecord.text "tag contents"]
  tlv := Tlv Tlv.NDEF-MESSAGE message.to-byte-array
  memory := tlv.to-byte-array + #[Tlv.TERMINATOR]

  found := Tlv.find-ndef-message memory
  expect-not-null found
  parsed := NdefMessage.parse found
  expect-equals "tag contents" parsed.records[0].text

  expect-null (Tlv.find-ndef-message #[Tlv.TERMINATOR])

test-mad-crc-algorithm:
  // Self-check of the CRC-8/MIFARE-MAD parameters (poly 0x1D, init 0xC7,
  // no reflection, no xor-out) against the algorithm's published check
  // value: running it over ASCII "123456789" must give 0x99. This is
  // independent of anything MIFARE-specific; it just confirms the SDK's
  // Crc is configured the way the catalogued algorithm defines it.
  crc := Crc.big-endian 8 --polynomial=0x1D --initial-state=0xC7
  crc.add "123456789"
  expect-equals 0x99 crc.get-as-int

test-mad-round-trip:
  aids := List 15: 0
  aids[0] = 0x1234  // Sector 1.
  aids[7] = 0x0003  // Sector 8.
  aids[14] = 0x4004 // Sector 15.
  mad := Mad --is-multi-application --card-publisher-sector=3 --sector-aids=aids

  blocks := mad.to-blocks
  parsed := Mad.from-blocks blocks[0] blocks[1]

  expect parsed.is-multi-application
  expect-equals 3 parsed.card-publisher-sector
  expect-equals 0x1234 (parsed.aid --sector=1)
  expect-equals 0x0003 (parsed.aid --sector=8)
  expect-equals 0x4004 (parsed.aid --sector=15)
  expect (parsed.is-free --sector=2)
  expect-not (parsed.is-free --sector=1)
  expect-equals 0x12 (Mad.function-cluster-code 0x1234)
  expect-equals 0x34 (Mad.application-code 0x1234)

test-mad-crc-rejects-corruption:
  aids := List 15: 0
  mad := Mad --no-is-multi-application --card-publisher-sector=0 --sector-aids=aids
  blocks := mad.to-blocks
  corrupted := blocks[0].copy
  corrupted[1] = corrupted[1] ^ 0xFF // Flip the info byte without fixing the CRC.
  expect-throw "INVALID_CRC":
    Mad.from-blocks corrupted blocks[1]

test-flipper-classic-round-trip:
  file := FlipperNfcFile "Mifare Classic"
      --uid=#[0x04, 0x17, 0x99, 0xF2]
      --atqa=#[0x00, 0x04]
      --sak=0x08
      --blocks={ 0: #[0x04, 0x17, 0x99, 0xF2, 0x6B, 0x48, 0x04, 0x00, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69] }

  text := file.stringify
  parsed := FlipperNfcFile.parse text
  expect-equals "Mifare Classic" parsed.device-type
  expect-bytes-equal #[0x04, 0x17, 0x99, 0xF2] parsed.uid
  expect-bytes-equal #[0x00, 0x04] parsed.atqa
  expect-equals 0x08 parsed.sak
  expect-bytes-equal file.blocks[0] parsed.blocks[0]

test-flipper-ultralight-round-trip:
  file := FlipperNfcFile "Mifare Ultralight"
      --uid=#[0x04, 0x7D, 0x0B, 0xDA, 0xF2, 0x4D, 0x80]
      --atqa=#[0x00, 0x44]
      --sak=0x00
      --blocks={ 0: #[0x04, 0x7D, 0x0B, 0xDA], 1: #[0xF2, 0x4D, 0x80, 0x56] }

  parsed := FlipperNfcFile.parse file.stringify
  expect-equals "Mifare Ultralight" parsed.device-type
  expect-bytes-equal file.uid parsed.uid
  // Ultralight-family device type uses "Page", not "Block".
  expect (file.stringify.contains "Page 0:")
  expect-not (file.stringify.contains "Block 0:")

test-flipper-tolerates-unknown-fields:
  text := """
    Filetype: Flipper NFC device
    Version: 4
    Device type: Mifare Classic
    UID: 04 17 99 F2
    ATQA: 00 04
    SAK: 08
    A future field we don't know about: some value
    Block 0: 00 00 00 00

    # a comment
    """
  parsed := FlipperNfcFile.parse text
  expect-equals "Mifare Classic" parsed.device-type
  expect-equals "some value" parsed.extra-fields["A future field we don't know about"]
  expect-bytes-equal #[0x00, 0x00, 0x00, 0x00] parsed.blocks[0]
