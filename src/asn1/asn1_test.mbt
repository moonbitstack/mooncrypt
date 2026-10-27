// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// ASN.1 DER encoding (X.690), byte-exact against the standard's rules.

///|
test "der: length uses the short form under 128 and the long form above (X.690 §8.1.3)" {
  assert_eq(@asn1.length_of(0), b"\x00")
  assert_eq(@asn1.length_of(127), b"\x7f")
  assert_eq(@asn1.length_of(128), b"\x81\x80")
  assert_eq(@asn1.length_of(255), b"\x81\xff")
  assert_eq(@asn1.length_of(256), b"\x82\x01\x00")
  assert_eq(@asn1.length_of(300), b"\x82\x01\x2c")
}

///|
test "der: INTEGER strips leading zeros and keeps the sign bit clear (X.690 §8.3)" {
  assert_eq(@asn1.integer(b""), b"\x02\x01\x00")
  assert_eq(@asn1.integer(b"\x2a"), b"\x02\x01\x2a")
  assert_eq(@asn1.integer(b"\x00\x00\x2a"), b"\x02\x01\x2a") // redundant zeros stripped
  assert_eq(@asn1.integer(b"\x80"), b"\x02\x02\x00\x80") // sign bit → prepend 0x00
  assert_eq(@asn1.integer(b"\x01\x00"), b"\x02\x02\x01\x00")
}

///|
test "der: OBJECT IDENTIFIER packs the first two arcs and base-128s the rest (X.690 §8.19)" {
  // 1.2.840.113549.1.1.1 (rsaEncryption): 2a 86 48 86 f7 0d 01 01 01.
  assert_eq(
    @asn1.oid([1, 2, 840, 113549, 1, 1, 1]),
    b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01",
  )
  // 1.2.840.10045.4.3.2 (ecdsa-with-SHA256): 2a 86 48 ce 3d 04 03 02.
  assert_eq(
    @asn1.oid([1, 2, 840, 10045, 4, 3, 2]),
    b"\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02",
  )
}

///|
test "der: BIT STRING, NULL, and SEQUENCE compose canonically" {
  assert_eq(@asn1.bit_string(b"\xde\xad"), b"\x03\x03\x00\xde\xad")
  assert_eq(@asn1.null(), b"\x05\x00")
  assert_eq(@asn1.octet_string(b"\xca\xfe"), b"\x04\x02\xca\xfe")
  // SEQUENCE { INTEGER 1, NULL }.
  assert_eq(
    @asn1.sequence([@asn1.integer(b"\x01"), @asn1.null()]),
    b"\x30\x05\x02\x01\x01\x05\x00",
  )
  // A context [0] EXPLICIT wrapping INTEGER 2 (the X.509 version field).
  assert_eq(@asn1.explicit(0, @asn1.integer(b"\x02")), b"\xa0\x03\x02\x01\x02")
}

///|
/// Why a decode was refused, or `"accepted"` — so a negative case can assert on the reason the
/// parser gave and not merely on the fact that it said no.
fn refusal(f : () -> Unit raise @asn1.Refused) -> String {
  try f() catch {
    @asn1.Malformed(m) => "Malformed: " + m
    @asn1.Unsupported(m) => "Unsupported: " + m
  } noraise {
    _ => "accepted"
  }
}

///|
test "der: an element splits into its contents and the bytes a signature covers" {
  let t = @asn1.read(b"\x30\x05\x02\x01\x2a\x05\x00\xff"[:])
  assert_eq(t.tag, 0x30)
  assert_eq(t.value.to_owned(), b"\x02\x01\x2a\x05\x00")
  assert_eq(t.raw.to_owned(), b"\x30\x05\x02\x01\x2a\x05\x00") // the trailing 0xff is the next element's
  let items = t.items()
  assert_eq(items.length(), 2)
  assert_eq(items[0].int(), 42)
  assert_eq(items[1].tag, 0x05)
  assert_eq(
    refusal(() => @asn1.read(b"\x02\x01\x2a"[:]).items() |> ignore),
    "Malformed: primitive value has no elements",
  )
}

///|
test "der: the long form reads its length from as many octets as it claims (X.690 §8.1.3)" {
  let long = Buffer()
  long.write_bytes(b"\x04\x81\x80"[:])
  long.write_bytes(Bytes::make(128, b'\x41')[:])
  assert_eq(@asn1.read(long.to_bytes()[:]).octets().length(), 128)
}

///|
test "der: every length is measured against the bytes that are actually there" {
  // 2^31-1 and 2^32-1: on a 32-bit `offset + length` the bounds check wraps negative, and a
  // wrapped comparison lets the element be read off the end of the buffer.
  assert_eq(
    refusal(() => @asn1.read(b"\x04\x84\x7f\xff\xff\xff\x41"[:]) |> ignore),
    "Malformed: length exceeds input",
  )
  assert_eq(
    refusal(() => @asn1.read(b"\x04\x84\xff\xff\xff\xff\x41"[:]) |> ignore),
    "Malformed: length exceeds input",
  )
  assert_eq(
    refusal(() => @asn1.read(b"\x04\x05\x41\x41"[:]) |> ignore),
    "Malformed: length exceeds input",
  )
  assert_eq(
    refusal(() => @asn1.read(b"\x04"[:]) |> ignore),
    "Malformed: truncated header",
  )
  assert_eq(
    refusal(() => @asn1.read(b"\x04\x82\x01"[:]) |> ignore),
    "Malformed: truncated length",
  )
  assert_eq(
    refusal(() => @asn1.read(b"\x30\x80\x05\x00\x00\x00"[:]) |> ignore),
    "Malformed: indefinite length",
  )
  assert_eq(
    refusal(() => @asn1.read(b"\x04\x81\x7f"[:]) |> ignore),
    "Malformed: non-minimal length",
  )
  assert_eq(
    refusal(() => @asn1.read(b"\x04\x82\x00\x80"[:]) |> ignore),
    "Malformed: non-minimal length",
  )
  assert_eq(
    refusal(() => @asn1.read(b"\x04\x85\x01\x00\x00\x00\x00"[:]) |> ignore),
    "Malformed: length over four octets",
  )
  assert_eq(
    refusal(() => @asn1.read(b"\x1f\x81\x01\x00"[:]) |> ignore),
    "Unsupported: multi-byte tag",
  )
}

///|
test "der: one element is the whole input, and a payload glued to its end is refused" {
  assert_eq(@asn1.only(b"\x05\x00"[:]).tag, 0x05)
  assert_eq(
    refusal(() => @asn1.only(b"\x05\x00\x00"[:]) |> ignore),
    "Malformed: trailing bytes",
  )
}

///|
test "der: INTEGER is two's complement and must be minimal (X.690 §8.3)" {
  assert_eq(@asn1.read(b"\x02\x01\x2a"[:]).int(), 42)
  assert_eq(@asn1.read(b"\x02\x02\x00\x80"[:]).int(), 128)
  assert_eq(@asn1.read(b"\x02\x01\xff"[:]).int(), -1)
  assert_eq(@asn1.read(b"\x02\x02\xfe\x00"[:]).int(), -512)
  assert_eq(
    refusal(() => @asn1.read(b"\x02\x02\x00\x2a"[:]).int() |> ignore),
    "Malformed: non-minimal INTEGER",
  )
  assert_eq(
    refusal(() => @asn1.read(b"\x02\x02\xff\x80"[:]).int() |> ignore),
    "Malformed: non-minimal INTEGER",
  )
  assert_eq(
    refusal(() => @asn1.read(b"\x02\x00"[:]).int() |> ignore),
    "Malformed: empty INTEGER",
  )
}

///|
test "der: BOOLEAN admits only the two octets DER defines (X.690 §11.1)" {
  assert_eq(@asn1.read(b"\x01\x01\xff"[:]).bool(), true)
  assert_eq(@asn1.read(b"\x01\x01\x00"[:]).bool(), false)
  assert_eq(
    refusal(() => @asn1.read(b"\x01\x01\x01"[:]).bool() |> ignore),
    "Malformed: non-DER BOOLEAN octet",
  )
}

///|
test "der: OBJECT IDENTIFIER round-trips the arcs the encoder packed (X.690 §8.19)" {
  assert_eq(
    @asn1.read(@asn1.oid([1, 2, 840, 113549, 1, 1, 1])[:]).oid(),
    "1.2.840.113549.1.1.1",
  )
  assert_eq(
    @asn1.read(@asn1.oid([1, 2, 840, 10045, 4, 3, 2])[:]).oid(),
    "1.2.840.10045.4.3.2",
  )
  assert_eq(@asn1.read(@asn1.oid([2, 5, 29, 17])[:]).oid(), "2.5.29.17")
  assert_eq(@asn1.read(b"\x06\x01\x00"[:]).oid(), "0.0")
  assert_eq(
    refusal(() => @asn1.read(b"\x06\x02\x2a\x80"[:]).oid() |> ignore),
    "Malformed: OID ends mid-arc",
  )
  assert_eq(
    refusal(() => @asn1.read(b"\x06\x03\x2a\x80\x01"[:]).oid() |> ignore),
    "Malformed: non-minimal OID arc",
  )
}

///|
test "der: BIT STRING keeps its unused-bit count, and bits number from the top (keyUsage)" {
  let bits = @asn1.read(b"\x03\x02\x05\xa0"[:]).bits() // 101 and five bits of padding
  assert_eq(bits.bytes, b"\xa0")
  assert_eq(bits.unused, 5)
  assert_eq(bits.get(0), true)
  assert_eq(bits.get(1), false)
  assert_eq(bits.get(2), true)
  assert_eq(bits.get(3), false) // inside the padding
  assert_eq(bits.get(233), false)
  assert_eq(
    refusal(() => @asn1.read(b"\x03\x00"[:]).bits() |> ignore),
    "Malformed: BIT STRING without its unused-bit count",
  )
  assert_eq(
    refusal(() => @asn1.read(b"\x03\x01\x08"[:]).bits() |> ignore),
    "Malformed: bad unused-bit count",
  )
}

///|
test "der: times are the seconds-and-Z form RFC 5280 §4.1.2.5 pins them to" {
  assert_eq(@asn1.read(@asn1.utc_time("700101000000Z")[:]).time(), 0L)
  assert_eq(@asn1.read(@asn1.utc_time("500101000000Z")[:]).time(), -631152000L)
  assert_eq(@asn1.read(@asn1.utc_time("491231235959Z")[:]).time(), 2524607999L)
  assert_eq(@asn1.read(@asn1.utc_time("240229000000Z")[:]).time(), 1709164800L)
  assert_eq(
    @asn1.read(@asn1.tlv(0x18, @utf8.encode("20260830071247Z"))[:]).time(),
    1788073967L,
  )
  assert_eq(
    refusal(() => {
      @asn1.read(@asn1.utc_time("230229000000Z")[:]).time() |> ignore
    }),
    "Malformed: time out of range",
  )
  assert_eq(
    refusal(() => @asn1.read(@asn1.utc_time("2601011200Z")[:]).time() |> ignore),
    "Malformed: UTCTime is not YYMMDDHHMMSSZ",
  )
  assert_eq(
    refusal(() => {
      @asn1.read(@asn1.utc_time("260101120000+")[:]).time() |> ignore
    }),
    "Malformed: time is not UTC",
  )
  assert_eq(
    refusal(() => {
      @asn1.read(@asn1.utc_time("2601a1120000Z")[:]).time() |> ignore
    }),
    "Malformed: non-digit in a time",
  )
}

///|
test "der: the string types a Name and a SAN are written in" {
  assert_eq(@asn1.read(@asn1.utf8_string("hé€")[:]).text(), "hé€")
  assert_eq(@asn1.read(@asn1.tlv(0x13, b"localhost")[:]).text(), "localhost")
  assert_eq(@asn1.read(@asn1.tlv(0x14, b"\xe9")[:]).text(), "é") // TeletexString as Latin-1
  assert_eq(@asn1.read(@asn1.tlv(0x1e, b"\x00\x41\x00\x42")[:]).text(), "AB") // BMPString
  assert_eq(
    refusal(() => @asn1.read(@asn1.tlv(0x13, b"\xff")[:]).text() |> ignore),
    "Malformed: non-ASCII octet in an ASCII string type",
  )
  assert_eq(
    refusal(() => @asn1.read(@asn1.tlv(0x1e, b"\xd8\x00")[:]).text() |> ignore),
    "Malformed: surrogate in BMPString",
  )
  assert_eq(
    refusal(() => @asn1.read(@asn1.tlv(0x1c, b"\x00")[:]).text() |> ignore),
    "Unsupported: UniversalString",
  )
  assert_eq(
    refusal(() => @asn1.read(b"\x02\x01\x2a"[:]).text() |> ignore),
    "Malformed: not a string type",
  )
}
