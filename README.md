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
  records (the mechanism for splitting a huge payload across several
  records) are deliberately rejected with a clear error rather than
  silently mis-parsed — that's real added complexity for a case that's
  rare in practice.
- **`tlv`** — the TLV (Type-Length-Value) framing the NFC Forum Type 2
  Tag Operation spec uses to lay out a tag's memory (eg. MIFARE
  Ultralight/NTAG pages) after the Capability Container. `Tlv.find-ndef-message`
  is the convenience most callers want: hand it the tag's memory, get the
  NDEF Message TLV's bytes back.
- **`mad`** — the MIFARE Application Directory (MAD1 only — the version
  in sector 0 of a 1K card, covering sectors 1-15). Says which "application"
  (by AID) owns each sector. MAD2 (the sector-16 extension 4K cards use to
  extend coverage to sectors 17-39) isn't implemented.
- **`flipper`** — reads and writes the stable backbone of Flipper Zero's
  `.nfc` device file format (device type, UID, ATQA, SAK, and the
  block/page hex dumps). Flipper's format has evolved across firmware
  versions; unrecognized fields are kept verbatim rather than rejected, so
  this stays usable as that keeps happening.

## On confidence

Everything here is checked by round-tripping (encode then decode, or vice
versa) rather than against real hardware, since none of this needs
hardware to begin with — except for one place worth calling out
explicitly: the MAD CRC (`CRC-8/MIFARE-MAD`: polynomial `0x1D`, initial
state `0xC7`, no reflection, no XOR-out) is self-checked against that
algorithm's own published test vector (running it over ASCII `"123456789"`
must give `0x99`), which confirms the SDK's `Crc` is configured the way
that catalogued algorithm is defined — but that's independent of whether
it's actually the checksum your MAD-using card uses. Worth a sanity check
against a real MAD dump when you get the chance.

The Flipper format support is built from the publicly documented shape of
`.nfc` files, not a live export from a Flipper device; comparing it
against one of your own exports would be a good first test once you're
back near your hardware.

---

Parts of this repository were developed with the help of [Claude Code](https://claude.com/claude-code).
