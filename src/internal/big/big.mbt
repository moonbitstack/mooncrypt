// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A constant written in hex. The digits are a literal in this module's source, so a failure
/// to parse them is a typo here, not bad input.
pub fn hex(digits : String) -> BigInt {
  @string.parse_bigint(digits, radix=16) catch {
    _ => abort("not a hex constant: " + digits)
  }
}
