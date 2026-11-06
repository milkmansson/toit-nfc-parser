# NFC Parser

Hardware-free parsing of NFC/RFID card data: NDEF, the Type 2 Tag TLV
layout, the MIFARE Application Directory, and Flipper Zero's `.nfc` file
format. Works entirely on byte dumps — no reader, no `toit-nfc` `Target`,
no hardware at all. Pairs with
[toit-mifare-classic](https://github.com/milkmansson/toit-mifare-classic)
and [toit-mifare-ultralight](https://github.com/milkmansson/toit-mifare-ultralight),
which produce the raw bytes this package makes sense of.

## What's here

- **`ndef`** — NDEF record and message parsing/encoding (`NdefRecord`,
  `NdefMessage`), per the NFC Forum NDEF Technical Specification. Well-known
  Text and URI records have dedicated constructors/decoders. Chunked
  records (the mechanism for splitting a payload too large for one record
  across several) are reassembled transparently when parsing; encoding
  never produces chunked output, since none of this package's own
  in-memory payloads need it.
- **`tlv`** — the TLV (Type-Length-Value) framing the NFC Forum Type 2
  Tag Operation spec uses to lay out a tag's memory (eg. MIFARE
  Ultralight/NTAG pages) after the Capability Container. `Tlv.find-ndef-message`
  is the convenience most callers want: hand it the tag's memory, get the
  NDEF Message TLV's bytes back.
- **`mad`** — the MIFARE Application Directory: `Mad` (MAD1, sector 0,
  sectors 1-15) and `Mad2` (the sector-16 extension 4K cards use to cover
  sectors 17-39). Says which "application" (by AID) owns each sector.
- **`flipper`** — reads and writes the stable backbone of Flipper Zero's
  `.nfc` device file format (device type, UID, ATQA, SAK, and the
  block/page hex dumps). Flipper's format has evolved across firmware
  versions, and has fields this package doesn't give typed accessors to
  (eg. "Mifare Classic type", "Data format version"); those are kept
  verbatim in `extra-fields` rather than being parsed or rejected, so a
  round-trip is always lossless and the package stays usable as the
  format keeps adding fields.

## On confidence

Everything here is checked by round-tripping (encode then decode, or vice
versa) rather than against real hardware, since none of this needs
hardware to begin with — except for one place worth calling out
explicitly: the MAD/MAD2 CRC (`CRC-8/MIFARE-MAD`: polynomial `0x1D`,
initial state `0xC7`, no reflection, no XOR-out) is self-checked against
that algorithm's own published test vector (running it over ASCII
`"123456789"` must give `0x99`), which confirms the SDK's `Crc` is
configured the way that catalogued algorithm is defined — but that's
independent of whether it's actually the checksum your MAD-using card
uses. Worth a sanity check against a real MAD dump when you get the
chance. The byte order for an AID's two fields (function cluster code is
the high byte, application code the low byte) was checked against the
authoritative NXP application note after finding a source that claims
the opposite byte order — the NXP note is what this package follows.

The Flipper format support is built from the publicly documented shape of
`.nfc` files and checked against the actual field set a real export has
for a MIFARE Classic card (`Device type`/`Mifare Classic type`/`Data
format version`, per the Flipper developer docs), not a live export from
a Flipper device itself; comparing it against one of your own exports
would be a good first test once you're back near your hardware.

---

Parts of this repository were developed with the help of [Claude Code](https://claude.com/claude-code).
