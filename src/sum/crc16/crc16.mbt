// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Which CRC-16.
///
/// Named after the catalogue, which is the only way to be unambiguous: "CRC-16"
/// alone has meant at least four different functions in shipping protocols. The
/// check value of each is stated on its case so that a reader can tell them
/// apart at a glance.
pub(all) enum Kind {
  ///
  /// CRC-16/ARC, polynomial `0x8005`, initial `0x0000`, reflected. Check value
  /// `0xBB3D`. The one in old IBM protocols and in `lha`.
  Arc
  ///
  /// CRC-16/CCITT-FALSE, polynomial `0x1021`, initial `0xFFFF`, not reflected.
  /// Check value `0x29B1`. What a great many stack traces call "CRC-16 CCITT".
  CcittFalse
  ///
  /// CRC-16/XMODEM, polynomial `0x1021`, initial `0x0000`, not reflected. Check
  /// value `0x31C3`. The one in XMODEM, YMODEM and X.25's LAPB framing.
  Xmodem
  ///
  /// CRC-16/KERMIT, polynomial `0x1021`, initial `0x0000`, reflected. Check
  /// value `0x2189`. The one Kermit itself uses.
  Kermit
  ///
  /// CRC-16/X-25, polynomial `0x1021`, initial `0xFFFF`, reflected, and the
  /// answer is complemented. Check value `0x906E`. The one in the X.25 link
  /// layer and in many HDLC stacks.
  X25
  ///
  /// CRC-16/MODBUS, polynomial `0x8005`, initial `0xFFFF`, reflected. Check
  /// value `0x4B37`. The one on a Modbus serial line.
  Modbus
} derive(Eq, Debug)

///|
pub extend Kind with Eq::{equal, not_equal}

///|
pub extend Kind with Debug::{to_repr}

///|
/// The four choices a CRC catalogue records.
struct Params {
  ///
  /// The polynomial, in the orientation the shift loop wants: reversed when the
  /// CRC is reflected.
  poly : UInt32
  init : UInt32
  reflected : Bool
  xorout : UInt32
}

///|
fn Kind::params(self : Kind) -> Params {
  match self {
    // 0x8005 reversed is 0xA001; 0x1021 reversed is 0x8408.
    Arc => { poly: 0xA001, init: 0x0000, reflected: true, xorout: 0x0000, }
    CcittFalse =>
      { poly: 0x1021, init: 0xFFFF, reflected: false, xorout: 0x0000, }
    Xmodem => { poly: 0x1021, init: 0x0000, reflected: false, xorout: 0x0000, }
    Kermit => { poly: 0x8408, init: 0x0000, reflected: true, xorout: 0x0000, }
    X25 => { poly: 0x8408, init: 0xFFFF, reflected: true, xorout: 0xFFFF, }
    Modbus => { poly: 0xA001, init: 0xFFFF, reflected: true, xorout: 0x0000, }
  }
}

///|
/// The checksum length in bytes.
pub fn Kind::size(self : Kind) -> Int32 {
  let _ = self
  2
}

///|
/// One byte at a time, which is what [`@spec.Hash::block`] reports.
pub fn Kind::block(self : Kind) -> Int32 {
  let _ = self
  1
}

///|
/// The 256-entry table for one variant.
///
/// The two arms really are different machines: a reflected CRC shifts right and
/// xors into the low byte, a straight one shifts left and xors into the high
/// byte, and running one as the other produces a checksum that is wrong in a way
/// that looks plausible.
fn make_table(p : Params) -> FixedArray[UInt32] {
  let table : FixedArray[UInt32] = FixedArray::make(256, 0)
  for i in 0..<256 {
    let mut crc : UInt32 = if p.reflected {
      i.reinterpret_as_uint()
    } else {
      (i << 8).reinterpret_as_uint()
    }
    for _ in 0..<8 {
      crc = if p.reflected {
        if (crc & 1) != 0 {
          (crc >> 1) ^ p.poly
        } else {
          crc >> 1
        }
      } else if (crc & 0x8000) != 0 {
        ((crc << 1) ^ p.poly) & 0xFFFF
      } else {
        (crc << 1) & 0xFFFF
      }
    }
    table[i] = crc
  }
  table
}

///|
let arc_table : FixedArray[UInt32] = make_table(Kind::params(Arc))

///|
let ccitt_table : FixedArray[UInt32] = make_table(Kind::params(CcittFalse))

///|
let xmodem_table : FixedArray[UInt32] = make_table(Kind::params(Xmodem))

///|
let kermit_table : FixedArray[UInt32] = make_table(Kind::params(Kermit))

///|
let x25_table : FixedArray[UInt32] = make_table(Kind::params(X25))

///|
let modbus_table : FixedArray[UInt32] = make_table(Kind::params(Modbus))

///|
/// A CRC-16 in progress.
pub struct Crc16 {
  kind : Kind
  params : Params
  table : FixedArray[UInt32]
  mut state : UInt32
}

///|
/// Start a CRC-16. The default is CRC-16/ARC, the oldest of the six.
pub fn Crc16::new(kind~ : Kind = Arc) -> Crc16 {
  let params = kind.params()
  {
    kind,
    params,
    table: match kind {
      Arc => arc_table
      CcittFalse => ccitt_table
      Xmodem => xmodem_table
      Kermit => kermit_table
      X25 => x25_table
      Modbus => modbus_table
    },
    state: params.init,
  }
}

///|
/// Feed more bytes.
pub fn Crc16::update(self : Crc16, data : BytesView) -> Unit {
  let mut crc = self.state
  if self.params.reflected {
    for i in 0..<data.length() {
      let at = ((crc ^ data[i].to_uint()) & 0xFF).reinterpret_as_int()
      crc = self.table[at] ^ (crc >> 8)
    }
  } else {
    for i in 0..<data.length() {
      let at = (((crc >> 8) ^ data[i].to_uint()) & 0xFF).reinterpret_as_int()
      crc = self.table[at] ^ ((crc << 8) & 0xFFFF)
    }
  }
  self.state = crc
}

///|
/// The checksum of everything fed so far, as the number the formats that write
/// it store.
pub fn Crc16::value(self : Crc16) -> UInt32 {
  (self.state ^ self.params.xorout) & 0xFFFF
}

///|
/// The checksum as two bytes, most significant first. See [`Crc16::value`] for
/// the number, and [`@crc32`] for why this is the big-endian form.
fn Crc16::bytes(self : Crc16) -> Bytes {
  let v = self.value()
  Bytes::from_array([(v >> 8).to_byte(), (v & 0xFF).to_byte()])
}

///|
/// The CRC-16 of a whole message.
pub fn crc16(data : BytesView, kind~ : Kind = Arc) -> UInt32 {
  let state = Crc16::new(kind~)
  state.update(data)
  state.value()
}

///|
pub extend Crc16 with @spec.Hash::{write, finish, reset, size, block}

///|
pub impl @spec.Hash for Crc16 with fn write(self, data) {
  self.update(data)
}

///|
pub impl @spec.Hash for Crc16 with fn finish(self) {
  self.bytes()
}

///|
pub impl @spec.Hash for Crc16 with fn reset(self) {
  self.state = self.params.init
}

///|
pub impl @spec.Hash for Crc16 with fn size(self) {
  self.kind.size()
}

///|
pub impl @spec.Hash for Crc16 with fn block(self) {
  self.kind.block()
}
