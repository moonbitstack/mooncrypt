// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The published tables from both RFCs, transcribed by
// `scripts/gen_otp_vectors.py`, which recomputes every row from the definition
// and refuses to emit unless it reproduces the standard.

///|
/// The shared secret of RFC 4226 appendix D: the ASCII digits 1 to 0, twice.
let hotp_secret : Bytes = @utf8.encode("12345678901234567890")

///|
/// One row of the counter-based table.
struct HotpCase {
  counter : UInt64
  expected : String
} derive(Debug)

///|
/// One row of the time-based table, naming the hash because RFC 6238 gives a
/// separate seed and a separate column for each.
struct TotpCase {
  hash : String
  time : UInt64
  expected : String
} derive(Debug)

///|
/// RFC 4226 appendix D.
let hotp_cases : Array[HotpCase] = [
  { counter: 0UL, expected: "755224", },
  { counter: 1UL, expected: "287082", },
  { counter: 2UL, expected: "359152", },
  { counter: 3UL, expected: "969429", },
  { counter: 4UL, expected: "338314", },
  { counter: 5UL, expected: "254676", },
  { counter: 6UL, expected: "287922", },
  { counter: 7UL, expected: "162583", },
  { counter: 8UL, expected: "399871", },
  { counter: 9UL, expected: "520489", },
]

///|
/// RFC 6238 appendix B.
let totp_cases : Array[TotpCase] = [
  { hash: "sha1", time: 59UL, expected: "94287082", },
  { hash: "sha1", time: 1111111109UL, expected: "07081804", },
  { hash: "sha1", time: 1111111111UL, expected: "14050471", },
  { hash: "sha1", time: 1234567890UL, expected: "89005924", },
  { hash: "sha1", time: 2000000000UL, expected: "69279037", },
  { hash: "sha1", time: 20000000000UL, expected: "65353130", },
  { hash: "sha256", time: 59UL, expected: "46119246", },
  { hash: "sha256", time: 1111111109UL, expected: "68084774", },
  { hash: "sha256", time: 1111111111UL, expected: "67062674", },
  { hash: "sha256", time: 1234567890UL, expected: "91819424", },
  { hash: "sha256", time: 2000000000UL, expected: "90698825", },
  { hash: "sha256", time: 20000000000UL, expected: "77737706", },
  { hash: "sha512", time: 59UL, expected: "90693936", },
  { hash: "sha512", time: 1111111109UL, expected: "25091201", },
  { hash: "sha512", time: 1111111111UL, expected: "99943326", },
  { hash: "sha512", time: 1234567890UL, expected: "93441116", },
  { hash: "sha512", time: 2000000000UL, expected: "38618901", },
  { hash: "sha512", time: 20000000000UL, expected: "47863826", },
]

///|
/// The seed of RFC 6238 appendix B for a named hash.
///
/// The three are different lengths on purpose — 20, 32 and 64 bytes — because the
/// point of the table is that the digest length is what changes, not the seed.
fn seed_for(name : String) -> Bytes {
  match name {
    "sha1" => @utf8.encode("12345678901234567890")
    "sha256" => @utf8.encode("12345678901234567890123456789012")
    _ =>
      @utf8.encode(
        "1234567890123456789012345678901234567890123456789012345678901234",
      )
  }
}

///|
/// A hash factory for a named hash.
fn hash_for(name : String) -> () -> &@spec.Hash {
  match name {
    "sha1" => fn() -> &@spec.Hash { @sha1.Hasher::new() }
    "sha256" => fn() -> &@spec.Hash { @sha2.Hasher::new() }
    _ => fn() -> &@spec.Hash { @sha2.Hasher::new(kind=Sha512) }
  }
}

///|
/// Every counter-based code in RFC 4226 appendix D.
test "hotp reproduces rfc 4226 appendix d" {
  let otp = @otp.Otp::new(hotp_secret[:])
  for case in hotp_cases {
    assert_eq(otp.hotp(case.counter), case.expected)
  }
}

///|
/// Every time-based code in RFC 6238 appendix B, which is the same table three
/// times over with a different hash each.
test "totp reproduces rfc 6238 appendix b" {
  for case in totp_cases {
    let otp = @otp.Otp::new(seed_for(case.hash)[:], digits=Eight)
    let code = otp.totp_with(case.time, hash_for(case.hash))
    assert_eq(code, case.expected)
  }
}

///|
/// The one-shot forms agree with the keyed ones, and a time is a counter divided
/// by the step.
test "one-shot forms agree with the keyed ones" {
  assert_eq(@otp.hotp(hotp_secret[:], 0), "755224")
  // 59 seconds is step 1, whose code is the second row of the table.
  assert_eq(@otp.totp(hotp_secret[:], 59), "287082")
  assert_eq(@otp.totp(hotp_secret[:], 60), "359152")
}

///|
/// A code is always as wide as asked for, even when the number underneath it is
/// small — the leading zero in `07081804` is part of the code.
test "a code keeps its width" {
  let otp = @otp.Otp::new(hotp_secret[:], digits=Eight)
  // The third row of the time-based table is 07081804: eight characters, and
  // the first of them a zero that a printed number would have dropped.
  assert_eq(
    otp.totp_with(1111111109UL, fn() -> &@spec.Hash { @sha1.Hasher::new() }),
    "07081804",
  )
  for case in hotp_cases {
    assert_eq(otp.hotp(case.counter).length(), 8)
  }
  let six = @otp.Otp::new(hotp_secret[:])
  for case in hotp_cases {
    assert_eq(six.hotp(case.counter).length(), 6)
  }
}

///|
/// Six, seven, eight and nine digits are truncations of the same number, so each
/// is the previous one without its leading digit once the modulus allows it.
test "the digit count is a modulus" {
  let counter = 0UL
  let six = @otp.Otp::new(hotp_secret[:], digits=Six).hotp(counter)
  let seven = @otp.Otp::new(hotp_secret[:], digits=Seven).hotp(counter)
  let eight = @otp.Otp::new(hotp_secret[:], digits=Eight).hotp(counter)
  let nine = @otp.Otp::new(hotp_secret[:], digits=Nine).hotp(counter)
  assert_eq(six.length(), 6)
  assert_eq(seven.length(), 7)
  assert_eq(eight.length(), 8)
  assert_eq(nine.length(), 9)
  assert_eq(six, "755224")
  assert_eq(six, eight[2:].to_owned())
  assert_eq(six, nine[3:].to_owned())
}

///|
/// A code is accepted at its own time and at a step either side of it, and not
/// two steps away.
test "totp confirmation has a window of one step by default" {
  let otp = @otp.Otp::new(hotp_secret[:])
  let now = 1234567890UL
  let code = otp.totp(now)
  assert_true(otp.confirm(code, now))
  assert_true(otp.confirm(code, now + 30))
  assert_true(otp.confirm(code, now - 30))
  assert_false(otp.confirm(code, now + 60))
  assert_false(otp.confirm(code, now - 60))
  // A wider window reaches further, and a narrower one does not.
  assert_true(otp.confirm(code, now + 60, skew=2))
  assert_false(otp.confirm(code, now + 30, skew=0))
}

///|
/// A wrong code is refused, including one that differs in a single digit.
test "totp refuses the wrong code" {
  let otp = @otp.Otp::new(hotp_secret[:])
  let now = 1234567890UL
  let code = otp.totp(now)
  assert_false(otp.confirm("000000", now))
  let flipped = (if code[0:1] == "9" { "8" } else { "9" }) + code[1:].to_owned()
  assert_false(otp.confirm(flipped, now))
  // And a code of the wrong length is not a code.
  assert_false(otp.confirm(code + "0", now))
  assert_false(otp.confirm("", now))
}

///|
/// The resynchronisation of RFC 4226 §7.4: a token that has been pressed ahead
/// is accepted within the look-ahead and refused beyond it.
test "hotp resynchronisation" {
  let otp = @otp.Otp::new(hotp_secret[:])
  let code = otp.hotp(5)
  assert_true(otp.confirm_at(code, 5))
  assert_false(otp.confirm_at(code, 4))
  assert_true(otp.confirm_at(code, 4, ahead=1))
  assert_true(otp.confirm_at(code, 3, ahead=2))
  assert_false(otp.confirm_at(code, 3, ahead=1))
}

///|
/// Two secrets that share a prefix produce unrelated codes, which is what stops
/// the counter from being guessed from a code.
test "a different secret gives a different code" {
  let a = @otp.Otp::new(@utf8.encode("12345678901234567890")[:])
  let b = @otp.Otp::new(@utf8.encode("12345678901234567891")[:])
  assert_eq(a.hotp(0), "755224")
  assert_true(a.hotp(0) != b.hotp(0))
}
