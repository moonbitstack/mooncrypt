// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The byte layer a certificate and a key file are built on. The package name
// carries the prefix, so a writer is named after the X.690 type it produces and
// a reader after what it gives back.

///|
/// Encode a definite length (X.690 §8.1.3): the short form is the single byte for lengths under
/// 128; the long form is `0x80 | n` followed by the length in `n` big-endian bytes.
pub fn length_of(n : Int) -> Bytes {
  if n < 128 {
    let b = Buffer()
    b.write_byte(n.to_byte())
    b.to_bytes()
  } else {
    let digits = []
    let mut m = n
    while m > 0 {
      digits.push(m % 256)
      m = m / 256
    }
    let be = digits.rev()
    let buf = Buffer()
    buf.write_byte((0x80 | be.length()).to_byte())
    for d in be {
      buf.write_byte(d.to_byte())
    }
    buf.to_bytes()
  }
}

///|
/// A tag-length-value: the `tag` byte, the definite length of `value`, then `value`.
pub fn tlv(tag : Int, value : Bytes) -> Bytes {
  let buf = Buffer()
  buf.write_byte(tag.to_byte())
  buf.write_bytes(length_of(value.length())[:])
  buf.write_bytes(value[:])
  buf.to_bytes()
}

///|
/// A DER INTEGER (tag 0x02) from a big-endian magnitude: strip redundant leading zero bytes,
/// then prepend one 0x00 if the top bit is set, so the value stays non-negative (X.690 §8.3).
pub fn integer(magnitude : Bytes) -> Bytes {
  if magnitude.length() == 0 {
    return tlv(0x02, b"\x00")
  }
  let mut start = 0
  while start < magnitude.length() - 1 && magnitude[start] == b'\x00' {
    start = start + 1
  }
  let stripped = magnitude[start:magnitude.length()].to_owned()
  let value = if (stripped[0].to_int() & 0x80) != 0 {
    let buf = Buffer()
    buf.write_byte(b'\x00')
    buf.write_bytes(stripped[:])
    buf.to_bytes()
  } else {
    stripped
  }
  tlv(0x02, value)
}

///|
/// A DER OBJECT IDENTIFIER (tag 0x06) from its arcs (X.690 §8.19): the first byte encodes
/// `40·arc1 + arc2`, and each later arc is base-128 big-endian with the high bit set on every
/// byte but the last.
pub fn oid(arcs : Array[Int]) -> Bytes {
  let body = Buffer()
  body.write_byte((40 * arcs[0] + arcs[1]).to_byte())
  for i = 2; i < arcs.length(); i = i + 1 {
    let v = arcs[i]
    let digits = []
    let mut n = v
    if n == 0 {
      digits.push(0)
    }
    while n > 0 {
      digits.push(n % 128)
      n = n / 128
    }
    let be = digits.rev()
    for j = 0; j < be.length(); j = j + 1 {
      let last = j == be.length() - 1
      body.write_byte((if last { be[j] } else { be[j] | 0x80 }).to_byte())
    }
  }
  tlv(0x06, body.to_bytes())
}

///|
/// A DER BIT STRING (tag 0x03) with no unused trailing bits: a leading 0x00 count then `content`.
pub fn bit_string(content : Bytes) -> Bytes {
  let buf = Buffer()
  buf.write_byte(b'\x00')
  buf.write_bytes(content[:])
  tlv(0x03, buf.to_bytes())
}

///|
/// A DER OCTET STRING (tag 0x04).
pub fn octet_string(content : Bytes) -> Bytes {
  tlv(0x04, content)
}

///|
/// A DER SEQUENCE (tag 0x30): the concatenated `elements`.
pub fn sequence(elements : Array[Bytes]) -> Bytes {
  let buf = Buffer()
  for e in elements {
    buf.write_bytes(e[:])
  }
  tlv(0x30, buf.to_bytes())
}

///|
/// A DER SET (tag 0x31): the concatenated `elements`.
pub fn set_of(elements : Array[Bytes]) -> Bytes {
  let buf = Buffer()
  for e in elements {
    buf.write_bytes(e[:])
  }
  tlv(0x31, buf.to_bytes())
}

///|
/// A DER NULL (tag 0x05, empty).
pub fn null() -> Bytes {
  tlv(0x05, b"")
}

///|
/// A DER UTF8String (tag 0x0c).
pub fn utf8_string(s : String) -> Bytes {
  tlv(0x0c, @utf8.encode(s))
}

///|
/// A DER UTCTime (tag 0x17), the `YYMMDDHHMMSSZ` form X.509 validity uses before 2050.
pub fn utc_time(s : String) -> Bytes {
  tlv(0x17, @utf8.encode(s))
}

///|
/// A context-specific constructed value `[tag_num]` wrapping `content` (tag `0xA0 | tag_num`) —
/// the EXPLICIT tagging X.509 uses for the certificate version and extensions.
pub fn explicit(tag_num : Int, content : Bytes) -> Bytes {
  tlv(0xa0 | tag_num, content)
}

// The decoder below reads bytes a peer chose. Every length is measured against what is actually
// left in the buffer before a single content byte is touched, and the arithmetic that does the
// measuring runs in 64 bits: a 32-bit `offset + length` wraps negative for a length near 2^31,
// and a wrapped comparison lets the element be read past the end of the buffer. The parser is
// also DER-strict rather than BER-tolerant — indefinite lengths, non-minimal lengths and
// non-minimal INTEGERs are refused — because a certificate that admits two encodings admits two
// readings of the same identity.

///|
/// A refused encoding. `Malformed` is a hostile or corrupt certificate; `Unsupported` is
/// well-formed DER this parser deliberately does not read, and the two are separated so a
/// caller can log an interop gap without calling it an attack.
pub suberror Refused {
  Malformed(String)
  Unsupported(String)
} derive(Eq)

///|
/// DER errors print as the fault they are, so a rejected certificate names its own reason.
pub impl Show for Refused with fn output(self, logger) {
  match self {
    Malformed(m) => logger.write_string("Malformed(" + m + ")")
    Unsupported(m) => logger.write_string("Unsupported(" + m + ")")
  }
}

///|
/// One decoded element: the tag byte, the contents, and `raw` — tag, length and contents
/// together. `raw` is what a signature covers and how far to step to reach the next element.
pub struct Tlv {
  tag : Int
  value : BytesView
  raw : BytesView
}

///|
/// A decoded BIT STRING: the content bytes and how many low bits of the last byte are padding.
pub struct Bits {
  bytes : Bytes
  unused : Int
} derive(Eq, Debug)

///|
/// Whether bit `i` is set, counting from the most significant bit of the first byte — the
/// numbering X.509 uses for keyUsage. Bits inside the padding, or past the end, read as unset.
pub fn Bits::get(self : Bits, i : Int) -> Bool {
  if i < 0 || i >= self.bytes.length() * 8 - self.unused {
    return false
  }
  (self.bytes[i / 8].to_int() & (0x80 >> (i % 8))) != 0
}

///|
/// Read the element at the head of `input`. Raises rather than reading past the end: the length
/// is checked against the bytes that remain, in 64-bit arithmetic so a length near 2^31 cannot
/// wrap the check.
pub fn read(input : BytesView) -> Tlv raise Refused {
  if input.length() < 2 {
    raise Malformed("truncated header")
  }
  let tag = input[0].to_int()
  if (tag & 0x1f) == 0x1f {
    raise Unsupported("multi-byte tag")
  }
  let first = input[1].to_int()
  let mut off = 2
  let mut len = 0L
  if first >= 0x80 {
    let octets = first & 0x7f
    if octets == 0 {
      raise Malformed("indefinite length")
    }
    if octets > 4 {
      raise Malformed("length over four octets")
    }
    if input.length() < 2 + octets {
      raise Malformed("truncated length")
    }
    if input[2] == b'\x00' {
      raise Malformed("non-minimal length")
    }
    for i in 0..<octets {
      len = len * 256L + input[2 + i].to_int64()
    }
    if len < 128L {
      raise Malformed("non-minimal length")
    }
    off = 2 + octets
  } else {
    len = first.to_int64()
  }
  if len > (input.length() - off).to_int64() {
    raise Malformed("length exceeds input")
  }
  let end = off + len.to_int()
  { tag, value: input[off:end], raw: input[0:end], }
}

///|
/// Read the one element that is the whole of `input`. Bytes after it are an error — a
/// certificate with a payload glued to its end is two documents, and the second one is not
/// covered by the signature over the first.
pub fn only(input : BytesView) -> Tlv raise Refused {
  let t = read(input)
  if t.raw.length() != input.length() {
    raise Malformed("trailing bytes")
  }
  t
}

///|
/// Whether `tag` is the context-specific `[n]` of an IMPLICIT or EXPLICIT field.
pub fn context(tag : Int, n : Int) -> Bool {
  (tag & 0xc0) == 0x80 && (tag & 0x1f) == n
}

///|
/// The elements a constructed value holds, in encoding order.
pub fn Tlv::items(self : Tlv) -> Array[Tlv] raise Refused {
  if (self.tag & 0x20) == 0 {
    raise Malformed("primitive value has no elements")
  }
  let out = []
  let mut rest = self.value
  while rest.length() > 0 {
    let t = read(rest)
    out.push(t)
    rest = rest[t.raw.length():]
  }
  out
}

///|
/// A BOOLEAN. DER admits only 0x00 and 0xFF, so any other octet is refused.
pub fn Tlv::bool(self : Tlv) -> Bool raise Refused {
  if self.tag != 0x01 {
    raise Malformed("not a BOOLEAN")
  }
  if self.value.length() != 1 {
    raise Malformed("BOOLEAN is not one octet")
  }
  match self.value[0] {
    b'\x00' => false
    b'\xff' => true
    _ => raise Malformed("non-DER BOOLEAN octet")
  }
}

///|
/// An INTEGER, two's complement as X.690 §8.3 defines it.
pub fn Tlv::int(self : Tlv) -> BigInt raise Refused {
  if self.tag != 0x02 {
    raise Malformed("not an INTEGER")
  }
  let v = self.value
  if v.length() == 0 {
    raise Malformed("empty INTEGER")
  }
  if v.length() > 1 {
    let redundant_zero = v[0] == b'\x00' && (v[1].to_int() & 0x80) == 0
    let redundant_ones = v[0] == b'\xff' && (v[1].to_int() & 0x80) != 0
    if redundant_zero || redundant_ones {
      raise Malformed("non-minimal INTEGER")
    }
  }
  let m = BigInt::from_octets(v)
  if (v[0].to_int() & 0x80) != 0 {
    m - ((1 : BigInt) << (8 * v.length()))
  } else {
    m
  }
}

///|
/// An OCTET STRING's contents.
pub fn Tlv::octets(self : Tlv) -> BytesView raise Refused {
  if self.tag != 0x04 {
    raise Malformed("not an OCTET STRING")
  }
  self.value
}

///|
/// A BIT STRING.
pub fn Tlv::bits(self : Tlv) -> Bits raise Refused {
  if self.tag != 0x03 {
    raise Malformed("not a BIT STRING")
  }
  if self.value.length() == 0 {
    raise Malformed("BIT STRING without its unused-bit count")
  }
  let unused = self.value[0].to_int()
  if unused > 7 || (unused > 0 && self.value.length() == 1) {
    raise Malformed("bad unused-bit count")
  }
  { bytes: self.value[1:].to_owned(), unused, }
}

///|
/// An OBJECT IDENTIFIER in dotted-decimal form. The first octet packs two arcs (X.690 §8.19.4);
/// the rest are base-128, high bit set on every byte but an arc's last.
pub fn Tlv::oid(self : Tlv) -> String raise Refused {
  if self.tag != 0x06 {
    raise Malformed("not an OBJECT IDENTIFIER")
  }
  let v = self.value
  if v.length() == 0 {
    raise Malformed("empty OBJECT IDENTIFIER")
  }
  if (v[v.length() - 1].to_int() & 0x80) != 0 {
    raise Malformed("OID ends mid-arc")
  }
  let arcs : Array[Int64] = []
  let mut acc = 0L
  let mut fresh = true
  for i in 0..<v.length() {
    let b = v[i].to_int()
    if fresh && b == 0x80 {
      raise Malformed("non-minimal OID arc")
    }
    // Capped so a long run of continuation octets cannot overflow the accumulator itself.
    if acc > 0x1ffffffL {
      raise Unsupported("OID arc over 32 bits")
    }
    acc = acc * 128L + (b & 0x7f).to_int64()
    fresh = false
    if (b & 0x80) == 0 {
      arcs.push(acc)
      acc = 0L
      fresh = true
    }
  }
  let head = arcs[0]
  let first = if head < 40L { 0L } else if head < 80L { 1L } else { 2L }
  let out = StringBuilder::StringBuilder()
  out.write_string(first.to_string())
  out.write_string(".")
  out.write_string((head - first * 40L).to_string())
  for i in 1..<arcs.length() {
    out.write_string(".")
    out.write_string(arcs[i].to_string())
  }
  out.to_string()
}

///|
/// Octets of one of the ASCII string types as text. Taken on its own because a subjectAltName
/// tags its entries with the field number, not the string type, so the octets arrive with nothing
/// left to dispatch on.
fn ascii(v : BytesView) -> String raise Refused {
  for i in 0..<v.length() {
    if v[i].to_int() >= 0x80 {
      raise Malformed("non-ASCII octet in an ASCII string type")
    }
  }
  @utf8.decode_lossy(v)
}

///|
/// A DirectoryString or IA5String as text — the string types an X.509 Name and a SAN entry are
/// written in. UniversalString is refused: it is UTF-32 and no certificate in practice uses it.
pub fn Tlv::text(self : Tlv) -> String raise Refused {
  let v = self.value
  match self.tag {
    0x0c => @utf8.decode_lossy(v)
    // PrintableString, IA5String, NumericString, VisibleString: ASCII alphabets, so a high bit
    // is a smuggled byte rather than a character.
    0x13 | 0x16 | 0x12 | 0x1a => ascii(v)
    // TeletexString, read as Latin-1: what the certificates that still emit it mean by it.
    0x14 => {
      let chars = []
      for i in 0..<v.length() {
        chars.push(v[i].to_int().unsafe_to_char())
      }
      String::from_array(chars[:])
    }
    0x1e => {
      if v.length() % 2 != 0 {
        raise Malformed("odd-length BMPString")
      }
      let chars = []
      for i = 0; i < v.length(); i = i + 2 {
        let unit = (v[i].to_int() << 8) | v[i + 1].to_int()
        if unit >= 0xd800 && unit <= 0xdfff {
          raise Malformed("surrogate in BMPString")
        }
        chars.push(unit.unsafe_to_char())
      }
      String::from_array(chars[:])
    }
    0x1c => raise Unsupported("UniversalString")
    _ => raise Malformed("not a string type")
  }
}

///|
/// Read `n` ASCII digits at `off`.
fn digits(v : BytesView, off : Int, n : Int) -> Int raise Refused {
  let mut acc = 0
  for i in 0..<n {
    let c = v[off + i].to_int()
    if c < 0x30 || c > 0x39 {
      raise Malformed("non-digit in a time")
    }
    acc = acc * 10 + (c - 0x30)
  }
  acc
}

///|
/// Days from 1970-01-01 to a proleptic Gregorian date, by the shift-the-year-to-March identity
/// that makes the leap day the last of the year.
fn days(y : Int, m : Int, d : Int) -> Int64 {
  let y = if m <= 2 { y - 1 } else { y }
  let era = (if y >= 0 { y } else { y - 399 }) / 400
  let yoe = y - era * 400
  let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1
  let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
  era.to_int64() * 146097L + (doe - 719468).to_int64()
}

///|
/// Days in a month of a proleptic Gregorian year.
fn month_days(y : Int, m : Int) -> Int {
  match m {
    1 | 3 | 5 | 7 | 8 | 10 | 12 => 31
    4 | 6 | 9 | 11 => 30
    _ => if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) { 29 } else { 28 }
  }
}

///|
/// A UTCTime or GeneralizedTime as seconds since the Unix epoch. RFC 5280 §4.1.2.5 pins both to
/// the seconds-and-`Z` form, and a two-digit year to 1950..2049, so the other shapes X.690
/// allows are refused rather than guessed at.
pub fn Tlv::time(self : Tlv) -> Int64 raise Refused {
  let v = self.value
  let (year, off) = match self.tag {
    0x17 => {
      if v.length() != 13 {
        raise Malformed("UTCTime is not YYMMDDHHMMSSZ")
      }
      let yy = digits(v, 0, 2)
      (if yy >= 50 { 1900 + yy } else { 2000 + yy }, 2)
    }
    0x18 => {
      if v.length() != 15 {
        raise Malformed("GeneralizedTime is not YYYYMMDDHHMMSSZ")
      }
      (digits(v, 0, 4), 4)
    }
    _ => raise Malformed("not a time")
  }
  if v[v.length() - 1] != b'Z' {
    raise Malformed("time is not UTC")
  }
  let month = digits(v, off, 2)
  let day = digits(v, off + 2, 2)
  let hour = digits(v, off + 4, 2)
  let minute = digits(v, off + 6, 2)
  let second = digits(v, off + 8, 2)
  if month < 1 ||
    month > 12 ||
    day < 1 ||
    day > month_days(year, month) ||
    hour > 23 ||
    minute > 59 ||
    second > 59 {
    raise Malformed("time out of range")
  }
  days(year, month, day) * 86400L +
  (hour * 3600 + minute * 60 + second).to_int64()
}

///|
pub extend Bits with Debug::{to_repr}

///|
pub extend Bits with Eq::{not_equal, equal}

///|
pub extend Refused with Eq::{not_equal, equal}

///|
pub extend Refused with Show::{to_string, output}
