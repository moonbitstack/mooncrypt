// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Which CRC-32.
///
/// The two differ only in the polynomial, but they detect different faults: the
/// IEEE one is the one on Ethernet and in zip files, and the Castagnoli one has
/// better distance properties for the short blocks a filesystem or a storage
/// protocol writes.
pub(all) enum Kind {
  ///
  /// The IEEE 802.3 polynomial, `0x04C11DB7`, reflected. Ethernet, zip, PNG.
  Ieee
  ///
  /// The Castagnoli polynomial, `0x1EDC6F41`, reflected. iSCSI, ext4, Btrfs.
  Castagnoli
} derive(Eq, Debug)

///|
pub extend Kind with Eq::{equal, not_equal}

///|
pub extend Kind with Debug::{to_repr}

///|
/// The reflected polynomial this kind reduces with: the constant as published,
/// with its bits reversed, because that is the form a right-shifting loop wants.
fn Kind::polynomial(self : Kind) -> UInt32 {
  match self {
    Ieee => 0xEDB88320
    Castagnoli => 0x82F63B78
  }
}

///|
/// The checksum length in bytes.
pub fn Kind::size(self : Kind) -> Int32 {
  let _ = self
  4
}

///|
/// One byte at a time: that is the stride this machine works in, and it is what
/// [`@spec.Hash::block`] reports.
pub fn Kind::block(self : Kind) -> Int32 {
  let _ = self
  1
}

///|
/// The 256-entry table for a reflected polynomial.
///
/// Each entry is one byte run through the shift-and-xor eight times, which is
/// the whole algorithm without a table. Doing it once turns eight steps per byte
/// into one lookup.
fn make_table(poly : UInt32) -> FixedArray[UInt32] {
  let table : FixedArray[UInt32] = FixedArray::make(256, 0)
  for i in 0..<256 {
    let mut crc : UInt32 = i.reinterpret_as_uint()
    for _ in 0..<8 {
      crc = if (crc & 1) != 0 { (crc >> 1) ^ poly } else { crc >> 1 }
    }
    table[i] = crc
  }
  table
}

///|
let ieee_table : FixedArray[UInt32] = make_table(Kind::polynomial(Ieee))

///|
let castagnoli_table : FixedArray[UInt32] = make_table(
  Kind::polynomial(Castagnoli),
)

///|
/// A CRC-32 in progress.
///
/// The running value is kept complemented, as the reference implementation does,
/// so the final xor is one operation at the end rather than a correction at
/// every step.
pub struct Crc32 {
  kind : Kind
  table : FixedArray[UInt32]
  mut state : UInt32
}

///|
/// Start a CRC-32. The default is the IEEE polynomial, which is what "CRC-32"
/// means when nothing else is said.
pub fn Crc32::new(kind~ : Kind = Ieee) -> Crc32 {
  let all : UInt32 = 0xFFFF_FFFF
  {
    kind,
    table: match kind {
      Ieee => ieee_table
      Castagnoli => castagnoli_table
    },
    state: all,
  }
}

///|
/// Feed more bytes.
pub fn Crc32::update(self : Crc32, data : BytesView) -> Unit {
  let mut crc = self.state
  for i in 0..<data.length() {
    let at = ((crc ^ data[i].to_uint()) & 0xFF).reinterpret_as_int()
    crc = self.table[at] ^ (crc >> 8)
  }
  self.state = crc
}

///|
/// The checksum of everything fed so far, as the number the formats that write
/// it actually store.
pub fn Crc32::value(self : Crc32) -> UInt32 {
  let all : UInt32 = 0xFFFF_FFFF
  self.state ^ all
}

///|
/// The checksum as four bytes, most significant first.
///
/// A CRC is a number, not a string of bytes, and the formats that carry it
/// disagree about which end goes first: zlib and PNG write it little-endian,
/// many others big-endian. This returns the big-endian form because that is how
/// every other digest in mooncrypt is written, and a caller writing to a format
/// that says otherwise knows which format it is writing.
fn Crc32::bytes(self : Crc32) -> Bytes {
  let v = self.value()
  Bytes::from_array([
    (v >> 24).to_byte(),
    ((v >> 16) & 0xFF).to_byte(),
    ((v >> 8) & 0xFF).to_byte(),
    (v & 0xFF).to_byte(),
  ])
}

///|
/// The CRC-32 of a whole message.
pub fn crc32(data : BytesView, kind~ : Kind = Ieee) -> UInt32 {
  let state = Crc32::new(kind~)
  state.update(data)
  state.value()
}

///|
pub extend Crc32 with @spec.Hash::{write, finish, reset, size, block}

///|
pub impl @spec.Hash for Crc32 with fn write(self, data) {
  self.update(data)
}

///|
/// Four bytes, big-endian. See [`Crc32::value`] for the number itself.
pub impl @spec.Hash for Crc32 with fn finish(self) {
  self.bytes()
}

///|
pub impl @spec.Hash for Crc32 with fn reset(self) {
  let all : UInt32 = 0xFFFF_FFFF
  self.state = all
}

///|
pub impl @spec.Hash for Crc32 with fn size(self) {
  self.kind.size()
}

///|
pub impl @spec.Hash for Crc32 with fn block(self) {
  self.kind.block()
}
