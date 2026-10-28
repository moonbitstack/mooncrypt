// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The string bcrypt encrypts, over and over, to turn its key schedule into a
/// digest. It is 24 bytes — three Blowfish blocks — and the words have no
/// meaning; what matters is that they are fixed and that the answer changes
/// unpredictably with every bit of the key.
let magic : Bytes = b"OrpheanBeholderScryDoubt"

///|
/// The alphabet bcrypt's base64 uses. Deliberately not RFC 4648's: this is the
/// ordering crypt(3) has always used, and a hash written with the wrong one
/// would still look valid.
let alphabet : Bytes = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

///|
/// The cheapest cost the format allows.
pub let min_cost : Int32 = 4

///|
/// The dearest cost the format allows. A cost of 31 is expressible and would
/// take a machine a lifetime, which is the point of allowing it.
pub let max_cost : Int32 = 31

///|
/// Twelve rounds of key setup: about a quarter of a second on the machine this
/// was written on, which is the usual compromise between logging in and
/// guessing.
pub let default_cost : Int32 = 12

///|
/// The most password bytes the format can use. Anything past it cannot affect
/// the result, so it is refused rather than silently ignored — a caller who
/// truncates their own password knows they did.
pub let max_password : Int32 = 72

///|
/// The salt is always sixteen bytes; the format has no way to say otherwise.
pub let salt_size : Int32 = 16

///|
/// How long a complete hash string is: `$2b$`, two digits of cost, `$`, then
/// twenty-two characters of salt and thirty-one of hash.
let encoded_size : Int32 = 60

///|
/// The EksBlowfish schedule, the magic string encrypted sixty-four times under
/// it, and the result.
///
/// The output is 24 bytes. The text format stores only the first 23, which is a
/// quirk of how crypt(3) laid the characters out — the twenty-fourth byte has
/// no room in the 31 characters that follow the salt.
fn raw(
  password : BytesView,
  salt : BytesView,
  cost : Int32,
) -> Bytes raise @spec.Broken {
  guard password.length() <= max_password else {
    raise @spec.Broken::Size(want=max_password, got=password.length())
  }
  guard salt.length() == salt_size else {
    raise @spec.Broken::Size(want=salt_size, got=salt.length())
  }
  guard cost >= min_cost && cost <= max_cost else {
    raise @spec.Broken::Size(want=max_cost, got=cost)
  }
  // The terminator is part of the historical definition: bcrypt hashes the
  // C string, terminator included, so a password is never a prefix of another.
  let key : Array[Byte] = []
  for i in 0..<password.length() {
    key.push(password[i])
  }
  key.push(b'\x00')
  let cipher = @blowfish.Cipher::new_eks(salt, Bytes::from_array(key)[:], cost)
  let mut state = magic
  for _ in 0..<64 {
    let next : Array[Byte] = []
    for block in 0..<3 {
      let encrypted = cipher.encrypt(state[block * 8:block * 8 + 8])
      for i in 0..<8 {
        next.push(encrypted[i])
      }
    }
    state = Bytes::from_array(next)
  }
  cipher.wipe()
  state
}

///|
/// Encode bytes with bcrypt's base64: six bits at a time from the most
/// significant end, the custom alphabet, and no padding.
fn b64_encode(data : BytesView) -> String {
  let out : Array[Byte] = []
  let mut bits = 0U
  let mut held = 0
  for i in 0..<data.length() {
    bits = (bits << 8) | data[i].to_int().reinterpret_as_uint()
    held = held + 8
    while held >= 6 {
      held = held - 6
      out.push(alphabet[((bits >> held) & 0x3F).reinterpret_as_int()])
    }
  }
  if held > 0 {
    out.push(alphabet[((bits << (6 - held)) & 0x3F).reinterpret_as_int()])
  }
  @utf8.decode_lossy(Bytes::from_array(out))
}

///|
/// The six bits one character of bcrypt's base64 stands for.
fn b64_value(c : Byte) -> UInt32? {
  let v = c.to_int()
  match v {
    0x2E => Some(0U) // .
    0x2F => Some(1U) // /
    0x41 => Some(2U) // A: 'A' to 'Z' are 2..27
    0x5A => Some(27U)
    0x61 => Some(28U) // a: 'a' to 'z' are 28..53
    0x7A => Some(53U)
    0x30 => Some(54U) // 0: '0' to '9' are 54..63
    0x39 => Some(63U)
    _ =>
      if v >= 0x41 && v <= 0x5A {
        Some((v - 0x41 + 2).reinterpret_as_uint())
      } else if v >= 0x61 && v <= 0x7A {
        Some((v - 0x61 + 28).reinterpret_as_uint())
      } else if v >= 0x30 && v <= 0x39 {
        Some((v - 0x30 + 54).reinterpret_as_uint())
      } else {
        None
      }
  }
}

///|
/// Decode bcrypt's base64, dropping the bits that do not fill a byte. Returns
/// `None` if a character is not in the alphabet, or if the leftover bits are not
/// zero — a salt with a non-canonical last character is not the salt it looks
/// like, and silently ignoring that would let two strings verify against the
/// same hash.
fn b64_decode(text : BytesView) -> Bytes? {
  let out : Array[Byte] = []
  let mut bits = 0U
  let mut held = 0
  for i in 0..<text.length() {
    let value = match b64_value(text[i]) {
      Some(v) => v
      None => return None
    }
    bits = (bits << 6) | value
    held = held + 6
    if held >= 8 {
      held = held - 8
      out.push(((bits >> held) & 0xFFU).to_byte())
    }
  }
  if held > 0 && (bits & ((1U << held) - 1U)) != 0U {
    return None
  }
  Some(Bytes::from_array(out))
}

///|
/// Hash a password with a caller-supplied salt.
///
/// The salt is sixteen raw bytes; the format only stores its base64 form, so
/// callers usually let [`parse`] hand it back from a stored hash instead of
/// making one. The result is the 24-byte output of the scheme, of which the
/// text format keeps 23.
///
/// Raises rather than truncating if the password is longer than [`max_password`]
/// bytes, because a password that silently becomes a prefix of itself is a
/// password that can be confused with another.
pub fn hash(
  password : BytesView,
  salt : BytesView,
  cost~ : Int32 = default_cost,
) -> Bytes raise @spec.Broken {
  raw(password, salt, cost)
}

///|
/// The fifty-three characters that follow the `$2b$NN$` header: the salt and
/// the hash, both in bcrypt's base64.
///
/// Kept separate from the header because verification compares only this part.
/// A hash written by PHP starts with `$2y$` and one written years ago starts
/// with `$2a$`; both are the same digest, so comparing the header would reject
/// them for a reason that has nothing to do with the password.
fn body(salt : BytesView, digest : BytesView) -> String {
  let out : Array[Byte] = []
  let salt_text = b64_encode(salt)
  for i in 0..<salt_text.length() {
    out.push(salt_text[i].to_int().to_byte())
  }
  // Thirty-one characters hold twenty-three bytes; the last byte of the scheme's
  // output has nowhere to go and is dropped.
  let digest_text = b64_encode(digest[0:23])
  for i in 0..<digest_text.length() {
    out.push(digest_text[i].to_int().to_byte())
  }
  @utf8.decode_lossy(Bytes::from_array(out))
}

///|
/// Format a password and salt as a `$2b$` hash string.
///
/// This is what gets written to a database. The cost travels inside it, so
/// raising [`default_cost`] later leaves existing hashes verifiable.
pub fn encode(
  password : BytesView,
  salt : BytesView,
  cost~ : Int32 = default_cost,
) -> String raise @spec.Broken {
  let digest = raw(password, salt, cost)
  let out : Array[Byte] = []
  for c in b"$2b$" {
    out.push(c)
  }
  out.push((0x30 + cost / 10).to_byte())
  out.push((0x30 + cost % 10).to_byte())
  out.push(b'$')
  let rest = body(salt, digest)
  let rest_bytes = @utf8.encode(rest)
  for i in 0..<rest_bytes.length() {
    out.push(rest_bytes[i])
  }
  @utf8.decode_lossy(Bytes::from_array(out))
}

///|
/// Read the cost and the salt out of a stored hash.
///
/// Returns `None` for anything that is not a well-formed `$2a$`, `$2b$`,
/// `$2x$` or `$2y$` string. The three prefixes are the same function here: the
/// differences between them are historical bugs in other implementations that
/// only showed up for passwords with the high bit set or longer than 72 bytes.
pub fn parse(text : String) -> (Int32, Bytes)? {
  let bytes = @utf8.encode(text)
  if bytes.length() != encoded_size {
    return None
  }
  if bytes[0] != b'$' ||
    bytes[1] != b'2' ||
    bytes[3] != b'$' ||
    bytes[6] != b'$' {
    return None
  }
  let variant = bytes[2].to_int()
  if variant != 0x61 && variant != 0x62 && variant != 0x78 && variant != 0x79 {
    return None
  }
  let high = bytes[4].to_int()
  let low = bytes[5].to_int()
  if high < 0x30 || high > 0x39 || low < 0x30 || low > 0x39 {
    return None
  }
  let cost = (high - 0x30) * 10 + (low - 0x30)
  if cost < min_cost || cost > max_cost {
    return None
  }
  match b64_decode(bytes[7:29]) {
    Some(salt) if salt.length() == salt_size => Some((cost, salt))
    _ => None
  }
}

///|
/// Check a password against a stored hash.
///
/// Never raises: a malformed string is simply a wrong password, because a
/// caller who has to handle the difference between "this row is corrupt" and
/// "this password is wrong" can call [`parse`] first and get it there.
///
/// The comparison is constant time, so the time it takes says nothing about how
/// much of the stored hash the password got right.
pub fn verify(password : BytesView, text : String) -> Bool {
  match parse(text) {
    None => false
    Some((cost, salt)) => {
      let digest = try raw(password, salt, cost) catch {
        _ => return false
      } noraise {
        value => value
      }
      // Compare the salt and hash characters only, so a hash stored under an
      // older prefix still verifies.
      let expected = @utf8.encode(text)
      @spec.eq(@utf8.encode(body(salt, digest))[:], expected[7:])
    }
  }
}
