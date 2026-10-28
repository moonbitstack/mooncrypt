// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// How many digits a code carries.
///
/// An enumeration rather than a number because the value is a modulus, not a
/// quantity: six digits means "modulo one million, printed with leading zeroes".
/// RFC 4226 §5.3 fixes the range at six to eight; nine is here because a
/// nine-digit code still fits the 31-bit value dynamic truncation produces, and
/// because banks use them.
pub(all) enum Digits {
  Six
  Seven
  Eight
  Nine
}

///|
/// How many digits a code of this kind has.
pub fn Digits::count(self : Digits) -> Int32 {
  match self {
    Six => 6
    Seven => 7
    Eight => 8
    Nine => 9
  }
}

///|
/// The modulus a code of this kind is reduced by: ten to the digit count.
fn Digits::radix(self : Digits) -> UInt32 {
  match self {
    Six => 1_000_000
    Seven => 10_000_000
    Eight => 100_000_000
    Nine => 1_000_000_000
  }
}

///|
/// Thirty seconds: the time step TOTP is defined over (RFC 6238 §5.2).
///
/// A different step is legal and some systems use one, which is why every
/// time-based function here takes it — but it is not a tuning knob, because a
/// step that disagrees with the verifier's produces codes that never match.
pub let default_step : UInt64 = 30UL

///|
/// A one-time password generator: a shared secret and a code length.
///
/// The secret is the only thing that has to be kept, and it is shared out of band
/// — the QR code an authenticator app scans is nothing but this key and a label.
pub struct Otp {
  key : Bytes
  digits : Digits
}

///|
/// Key a generator.
///
/// The secret is taken as given: RFC 4226 leaves its length to the application,
/// and the 20-byte recommendation is a recommendation because the security is the
/// HMAC's, not the code's.
pub fn Otp::new(key : BytesView, digits~ : Digits = Six) -> Otp {
  { key: key.to_owned(), digits, }
}

///|
/// The counter-based code of RFC 4226 §5.3, keyed with SHA-1 as that standard
/// specifies.
pub fn Otp::hotp(self : Otp, counter : UInt64) -> String {
  self.hotp_with(counter, fn() -> &@spec.Hash { @sha1.Hasher::new() })
}

///|
/// The counter-based code of RFC 4226 §5.3 over any hash.
///
/// RFC 6238 extends HOTP by allowing SHA-256 and SHA-512, and appendix B of that
/// RFC gives a table for each — which is why this takes a factory rather than
/// hard-coding SHA-1.
pub fn Otp::hotp_with(
  self : Otp,
  counter : UInt64,
  hash : () -> &@spec.Hash,
) -> String {
  let msg : Array[Byte] = []
  for i in 0..<8 {
    let shift = (7 - i) * 8
    msg.push(((counter >> shift) & 0xFFUL).to_int().to_byte())
  }
  let digest = @hmac.mac(self.key[:], Bytes::from_array(msg)[:], hash)
  // Dynamic truncation. The offset is the low nibble of the last byte of the
  // digest — the nineteenth byte of a SHA-1 digest, which is what RFC 4226
  // spells out, and the last byte of any digest, which is the same rule. The top
  // bit of the four bytes read from there is cleared so the number is positive
  // however the language signs its integers.
  let at = digest[digest.length() - 1].to_int() & 0xF
  let value = ((digest[at].to_int().reinterpret_as_uint() & 0x7F) << 24) |
    (digest[at + 1].to_int().reinterpret_as_uint() << 16) |
    (digest[at + 2].to_int().reinterpret_as_uint() << 8) |
    digest[at + 3].to_int().reinterpret_as_uint()
  pad(value % self.digits.radix(), self.digits.count())
}

///|
/// The time-based code of RFC 6238, keyed with SHA-1.
///
/// `unix_time` is seconds since 1970, taken as an argument rather than read from
/// a clock: the package then has no opinion about time and can be tested against
/// a fixed table.
pub fn Otp::totp(
  self : Otp,
  unix_time : UInt64,
  step~ : UInt64 = 30UL,
) -> String {
  self.totp_with(unix_time, fn() -> &@spec.Hash { @sha1.Hasher::new() }, step~)
}

///|
/// The time-based code of RFC 6238 over any hash.
pub fn Otp::totp_with(
  self : Otp,
  unix_time : UInt64,
  hash : () -> &@spec.Hash,
  step~ : UInt64 = 30UL,
) -> String {
  self.hotp_with(unix_time / step, hash)
}

///|
/// Whether `code` is the counter-based code for `counter`, or for one of the
/// `ahead` counters after it.
///
/// The look-ahead is the HOTP resynchronisation of RFC 4226 §7.4: a token that
/// has been pressed more times than the server counted is ahead of it, and
/// accepting a few steps forward is what lets the two catch up. It is a small
/// number for a reason — every step tried is another guess an attacker gets.
pub fn Otp::confirm_at(
  self : Otp,
  code : StringView,
  counter : UInt64,
  ahead~ : Int32 = 0,
) -> Bool {
  for i in 0..<(ahead + 1) {
    if same(code, self.hotp(counter + i.to_uint64())) {
      return true
    }
  }
  false
}

///|
/// Whether `code` is the time-based code for `unix_time`, or for one of the
/// `skew` steps on either side of it.
///
/// Both directions are checked because the clock that produced the code and the
/// clock that checks it are different clocks, and either may be the fast one.
pub fn Otp::confirm(
  self : Otp,
  code : StringView,
  unix_time : UInt64,
  skew~ : Int32 = 1,
  step~ : UInt64 = 30UL,
) -> Bool {
  let counter = unix_time / step
  for i in 0..<(skew + 1) {
    if same(code, self.hotp(counter + i.to_uint64())) {
      return true
    }
    // Only behind the counter when there is a step behind it to try: the first
    // step after the epoch has nothing before it.
    if i > 0 &&
      counter >= i.to_uint64() &&
      same(code, self.hotp(counter - i.to_uint64())) {
      return true
    }
  }
  false
}

///|
/// The counter-based code of RFC 4226 for a six-digit code, the shape the
/// standard's own examples have.
pub fn hotp(key : BytesView, counter : UInt64) -> String {
  Otp::new(key).hotp(counter)
}

///|
/// The time-based code of RFC 6238 for a six-digit code.
pub fn totp(
  key : BytesView,
  unix_time : UInt64,
  step~ : UInt64 = 30UL,
) -> String {
  Otp::new(key).totp(unix_time, step~)
}

///|
/// Print `value` as exactly `width` decimal digits, zero-padded on the left.
///
/// The padding is the point: a code that happens to be small is still six
/// characters on the user's screen, and a verifier that compared unpadded
/// numbers would accept `042` for `42` in some systems and not in others.
fn pad(value : UInt32, width : Int32) -> String {
  let text = value.to_string()
  let out = StringBuilder::StringBuilder()
  for _ in 0..<(width - text.length()) {
    out.write_string("0")
  }
  out.write_string(text)
  out.to_string()
}

///|
/// Whether two codes are the same, in time that does not depend on where they
/// first differ.
///
/// A code is six characters and an attacker gets to try; a comparison that
/// returned early would tell them how many leading digits they had right, which
/// is the whole search. [`@spec.eq`] does the same job on bytes, so both sides
/// are encoded and handed to it rather than compared as strings.
fn same(code : StringView, expected : String) -> Bool {
  @spec.eq(@utf8.encode(code), @utf8.encode(expected))
}
