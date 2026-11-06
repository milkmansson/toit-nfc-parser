// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

import crypto.crc show Crc

/**
A MIFARE Application Directory, version 1 (MAD1): the directory, stored
  in sector 0 (blocks 1 and 2) of a MIFARE Classic 1K card, that says
  which "application" (by AID) owns each of the card's other sectors.

See NXP application note AN10787 for the layout this is parsed from.
A 4K card additionally has MAD2 (see $Mad2 below), a second directory in
  sector 16 covering the sectors a 1K card doesn't have.
*/
class Mad:
  static CARD-PUBLISHER-SECTOR-MASK_ ::= 0x3F

  /** Whether this card hosts more than one independent application. */
  is-multi-application/bool
  /** The sector holding card-holder information, if any (bits 0-5 of the info byte). */
  card-publisher-sector/int
  /**
  The AID for each sector 1 through 15 (index 0 of this list is sector 1).

  An AID of 0x0000 means the sector is free; 0x0001 means it's defect/
    reserved. Otherwise, the high byte is the function cluster code and
    the low byte is the application code (see $function-cluster-code,
    $application-code).
  */
  sector-aids/List

  constructor --.is-multi-application --.card-publisher-sector --.sector-aids:

  /**
  Parses the MAD from sector 0's $block1 and $block2 (16 bytes each).

  If $check-crc, verifies $block1's first byte against the CRC-8/MAD
    checksum of the rest of the MAD data; throws if it doesn't match.
  */
  constructor.from-blocks block1/ByteArray block2/ByteArray --check-crc/bool=true:
    if block1.size != 16 or block2.size != 16: throw "INVALID_ARGUMENT"
    if check-crc:
      expected := crc_ (block1[1..] + block2)
      if block1[0] != expected: throw "INVALID_CRC"

    info := block1[1]
    is-multi-application = info & 0x80 != 0
    card-publisher-sector = info & CARD-PUBLISHER-SECTOR-MASK_

    aids := []
    for i := 2; i < 16; i += 2:
      aids.add (block1[i] | (block1[i + 1] << 8))
    for i := 0; i < 16; i += 2:
      aids.add (block2[i] | (block2[i + 1] << 8))
    sector-aids = aids

  /** The AID for the given $sector (1 through 15). */
  aid --sector/int -> int:
    if not 1 <= sector <= 15: throw "INVALID_ARGUMENT"
    return sector-aids[sector - 1]

  /** Whether $sector is marked free (AID 0x0000). */
  is-free --sector/int -> bool:
    return (aid --sector=sector) == 0x0000

  /** The function cluster code (high byte) of the given $aid. */
  static function-cluster-code aid/int -> int: return (aid >> 8) & 0xFF

  /** The application code (low byte) of the given $aid. */
  static application-code aid/int -> int: return aid & 0xFF

  /** Encodes this MAD back to sector 0's block 1 and block 2. */
  to-blocks -> List:
    block1 := ByteArray 16
    block2 := ByteArray 16
    info := card-publisher-sector & CARD-PUBLISHER-SECTOR-MASK_
    if is-multi-application: info |= 0x80
    block1[1] = info
    for sector := 1; sector <= 7; sector++:
      aid := sector-aids[sector - 1]
      index := 2 + 2 * (sector - 1)
      block1[index] = aid & 0xFF
      block1[index + 1] = (aid >> 8) & 0xFF
    for sector := 8; sector <= 15; sector++:
      aid := sector-aids[sector - 1]
      index := 2 * (sector - 8)
      block2[index] = aid & 0xFF
      block2[index + 1] = (aid >> 8) & 0xFF
    block1[0] = crc_ (block1[1..] + block2)
    return [block1, block2]

  static crc_ data/ByteArray -> int:
    crc := Crc.big-endian 8 --polynomial=0x1D --initial-state=0xC7
    crc.add data
    return crc.get-as-int

  stringify -> string:
    return "Mad(multi-application=$is-multi-application, "
        + "card-publisher-sector=$card-publisher-sector, aids=$sector-aids)"

/**
MAD2: the second MIFARE Application Directory a 4K card has, stored in
  sector 16 (its 3 data blocks), covering sectors 17 through 39 — the
  sectors a 1K card (which only has MAD1) doesn't have. The
  multi-application flag and card-publisher-sector live only in MAD1;
  MAD2's equivalent byte is reserved (RFU), not a second copy of them.
*/
class Mad2:
  /** The AID for each sector 17 through 39 (index 0 of this list is sector 17). */
  sector-aids/List

  constructor --.sector-aids:

  /**
  Parses MAD2 from sector 16's $block0, $block1 and $block2 (16 bytes
    each).

  If $check-crc, verifies $block0's first byte against the CRC-8/MAD
    checksum of the rest of the MAD2 data; throws if it doesn't match.
  */
  constructor.from-blocks block0/ByteArray block1/ByteArray block2/ByteArray --check-crc/bool=true:
    if block0.size != 16 or block1.size != 16 or block2.size != 16: throw "INVALID_ARGUMENT"
    if check-crc:
      expected := Mad.crc_ (block0[1..] + block1 + block2)
      if block0[0] != expected: throw "INVALID_CRC"

    aids := []
    for i := 2; i < 16; i += 2:
      aids.add (block0[i] | (block0[i + 1] << 8))
    for i := 0; i < 16; i += 2:
      aids.add (block1[i] | (block1[i + 1] << 8))
    for i := 0; i < 16; i += 2:
      aids.add (block2[i] | (block2[i + 1] << 8))
    sector-aids = aids

  /** The AID for the given $sector (17 through 39). */
  aid --sector/int -> int:
    if not 17 <= sector <= 39: throw "INVALID_ARGUMENT"
    return sector-aids[sector - 17]

  /** Whether $sector is marked free (AID 0x0000). */
  is-free --sector/int -> bool:
    return (aid --sector=sector) == 0x0000

  /** Encodes this MAD2 back to sector 16's blocks 0, 1 and 2. */
  to-blocks -> List:
    block0 := ByteArray 16
    block1 := ByteArray 16
    block2 := ByteArray 16
    for sector := 17; sector <= 23; sector++:
      aid := sector-aids[sector - 17]
      index := 2 + 2 * (sector - 17)
      block0[index] = aid & 0xFF
      block0[index + 1] = (aid >> 8) & 0xFF
    for sector := 24; sector <= 31; sector++:
      aid := sector-aids[sector - 17]
      index := 2 * (sector - 24)
      block1[index] = aid & 0xFF
      block1[index + 1] = (aid >> 8) & 0xFF
    for sector := 32; sector <= 39; sector++:
      aid := sector-aids[sector - 17]
      index := 2 * (sector - 32)
      block2[index] = aid & 0xFF
      block2[index + 1] = (aid >> 8) & 0xFF
    block0[0] = Mad.crc_ (block0[1..] + block1 + block2)
    return [block0, block1, block2]

  stringify -> string:
    return "Mad2(aids=$sector-aids)"
