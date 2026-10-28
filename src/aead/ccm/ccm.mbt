// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The default tag length in bytes.
pub let tag : Int32 = 16

///|
/// The block every block cipher here has to be.
let width : Int32 = 16

///|
/// CCM over any 128-bit block cipher.
///
/// The tag length is fixed when the context is made because it goes into the
/// first byte of the MAC input: a 12-byte tag and a 16-byte tag are not the same
/// computation truncated, they are different computations. It is also why CCM
/// cannot be used with a tag shorter than four bytes — the encoding has no way
/// to say so.
pub struct Ccm {
  ///
  /// The block cipher underneath.
  cipher : &@spec.Block
  ///
  /// How many bytes of the MAC to keep.
  tag : Int32
}

///|
/// Whether a tag length is one CCM can express. SP 800-38C §5.1: an even number
/// of bytes from four to sixteen, because the field in the first byte is
/// `(M - 2) / 2` and has three bits.
fn tag_allowed(size : Int32) -> Bool {
  size >= 4 && size <= 16 && size % 2 == 0
}

///|
/// Wrap a block cipher in CCM.
///
/// The cipher must have a sixteen-byte block. Everything else — the key — is the
/// cipher's business.
pub fn Ccm::new(
  cipher : &@spec.Block,
  tag~ : Int32 = tag,
) -> Ccm raise @spec.Broken {
  guard cipher.block() == width else {
    raise @spec.Broken::Size(want=width, got=cipher.block())
  }
  guard tag_allowed(tag) else { raise @spec.Broken::Size(want=16, got=tag) }
  { cipher, tag, }
}

///|
/// The tag length in bytes.
pub fn Ccm::size(self : Ccm) -> Int32 {
  self.tag
}

///|
/// The largest message this nonce length can carry, which is what the length
/// field in the counter blocks has room for.
fn limit(nonce : Int32) -> UInt64 {
  let bytes = 15 - nonce
  if bytes >= 8 {
    0xFFFF_FFFF_FFFF_FFFFUL
  } else {
    (1UL << (8 * bytes)) - 1UL
  }
}

///|
/// Write `value` into the last `bytes` bytes of `out`, big-endian.
fn put_be(
  out : FixedArray[Byte],
  at : Int32,
  bytes : Int32,
  value : UInt64,
) -> Unit {
  for i in 0..<bytes {
    let shift = (bytes - 1 - i) * 8
    out[at + i] = ((value >> shift) & 0xFFUL).to_byte()
  }
}

///|
/// Fold one block into the CBC-MAC chain.
fn absorb(
  chain : FixedArray[Byte],
  cipher : &@spec.Block,
  block : FixedArray[Byte],
) -> Unit {
  for i in 0..<width {
    chain[i] = chain[i] ^ block[i]
  }
  let out = cipher.encrypt(Bytes::from_array(chain))
  for i in 0..<width {
    chain[i] = out[i]
  }
}

///|
/// Fold a byte string into the chain as zero-padded blocks.
///
/// Zero padding rather than PKCS#7, because CCM has already committed to the
/// length in the first block: padding that could be stripped would make two
/// different messages produce the same MAC input.
fn absorb_bytes(
  chain : FixedArray[Byte],
  cipher : &@spec.Block,
  data : BytesView,
) -> Unit {
  if data.length() == 0 {
    return
  }
  let buffer : FixedArray[Byte] = FixedArray::make(width, b'\x00')
  let mut filled = 0
  for i in 0..<data.length() {
    buffer[filled] = data[i]
    filled = filled + 1
    if filled == width {
      absorb(chain, cipher, buffer)
      for k in 0..<width {
        buffer[k] = b'\x00'
      }
      filled = 0
    }
  }
  if filled > 0 {
    absorb(chain, cipher, buffer)
  }
}

///|
/// The associated data, prefixed with something that says how long it is.
///
/// Without the prefix, a header of `00 01` followed by one byte of message and a
/// header of `00` followed by two bytes would produce the same block sequence,
/// and the tag would not distinguish them. Three encodings cover every length:
/// two bytes below 0xff00, six above it, and ten above four gibibytes.
fn aad_header(aad : BytesView) -> Bytes {
  let out : Array[Byte] = []
  let n = aad.length()
  if n < 0xFF00 {
    out.push(((n >> 8) & 0xFF).to_byte())
    out.push((n & 0xFF).to_byte())
  } else if n.to_uint64() <= 0xFFFF_FFFFUL {
    out.push(b'\xFF')
    out.push(b'\xFE')
    let big = n.to_uint64()
    for i in 0..<4 {
      out.push(((big >> (24 - 8 * i)) & 0xFFUL).to_byte())
    }
  } else {
    out.push(b'\xFF')
    out.push(b'\xFF')
    let big = n.to_uint64()
    for i in 0..<8 {
      out.push(((big >> (56 - 8 * i)) & 0xFFUL).to_byte())
    }
  }
  for i in 0..<n {
    out.push(aad[i])
  }
  Bytes::from_array(out)
}

///|
/// The CBC-MAC over the formatted header, the associated data and the plaintext,
/// RFC 3610 §2.2.
///
/// The associated data is length-prefixed before it is authenticated, and is
/// padded to a block boundary on its own, separately from the plaintext — the
/// two are distinct fields and must not run into one another.
fn Ccm::mac(
  self : Ccm,
  nonce : BytesView,
  plain : BytesView,
  aad : BytesView,
) -> Bytes {
  let l = 15 - nonce.length()
  let b0 : FixedArray[Byte] = FixedArray::make(width, b'\x00')
  let adata = if aad.length() > 0 { 0x40 } else { 0x00 }
  b0[0] = (adata | (((self.tag - 2) / 2) << 3) | (l - 1)).to_byte()
  for i in 0..<nonce.length() {
    b0[1 + i] = nonce[i]
  }
  put_be(b0, 1 + nonce.length(), l, plain.length().to_uint64())
  let chain : FixedArray[Byte] = FixedArray::make(width, b'\x00')
  absorb(chain, self.cipher, b0)
  if aad.length() > 0 {
    absorb_bytes(chain, self.cipher, aad_header(aad)[:])
  }
  absorb_bytes(chain, self.cipher, plain)
  let kept : Array[Byte] = []
  for i in 0..<self.tag {
    kept.push(chain[i])
  }
  Bytes::from_array(kept)
}

///|
/// The keystream block for counter `value`: the flag byte, the nonce, then the
/// counter in as many bytes as the message length needed.
fn counter_block(nonce : BytesView, value : UInt64) -> Bytes {
  let l = 15 - nonce.length()
  let out : FixedArray[Byte] = FixedArray::make(width, b'\x00')
  out[0] = (l - 1).to_byte()
  for i in 0..<nonce.length() {
    out[1 + i] = nonce[i]
  }
  put_be(out, 1 + nonce.length(), l, value)
  Bytes::from_array(out)
}

///|
/// XOR a byte string with the keystream starting at counter 1, applying it in
/// place to whatever is handed in. The same call encrypts and decrypts.
fn Ccm::stream(self : Ccm, nonce : BytesView, data : BytesView) -> Bytes {
  let out : FixedArray[Byte] = FixedArray::make(data.length(), b'\x00')
  let mut at = 0
  let mut value = 1UL
  while at < data.length() {
    let block = self.cipher.encrypt(counter_block(nonce, value))
    let take = if data.length() - at < width {
      data.length() - at
    } else {
      width
    }
    for i in 0..<take {
      out[at + i] = data[at + i] ^ block[i]
    }
    at = at + take
    value = value + 1UL
  }
  Bytes::from_array(out)
}

///|
/// Encrypt and authenticate.
///
/// The result is the ciphertext followed by the tag; the tag length comes from
/// the context. The nonce may be 7 to 13 bytes, and shorter is not better: the
/// number of messages that are safe under one key is bounded by the nonce space,
/// so 13 bytes — the longest that leaves room for a two-byte counter — is what
/// the standard recommends.
pub fn Ccm::seal(
  self : Ccm,
  nonce~ : BytesView,
  plain~ : BytesView,
  aad~ : BytesView = b""[:],
) -> Bytes {
  guard nonce.length() >= 7 && nonce.length() <= 13 else {
    abort("ccm: a nonce is 7 to 13 bytes, not \{nonce.length()}")
  }
  guard plain.length().to_uint64() <= limit(nonce.length()) else {
    abort(
      "ccm: a \{nonce.length()}-byte nonce can carry at most \{limit(nonce.length())} bytes",
    )
  }
  let t = self.mac(nonce, plain, aad)
  let mask = self.cipher.encrypt(counter_block(nonce, 0UL))
  let sealed_tag : FixedArray[Byte] = FixedArray::make(self.tag, b'\x00')
  for i in 0..<self.tag {
    sealed_tag[i] = t[i] ^ mask[i]
  }
  self.stream(nonce, plain) + Bytes::from_array(sealed_tag)
}

///|
/// Authenticate and decrypt.
///
/// Raises [`@spec.Broken::Tag`] if the tag does not match. The tag is checked
/// before the plaintext is returned, and the comparison is constant time, so a
/// caller learns only that the message was wrong and not which part of it.
pub fn Ccm::open(
  self : Ccm,
  nonce~ : BytesView,
  cipher~ : BytesView,
  aad~ : BytesView = b""[:],
) -> Bytes raise @spec.Broken {
  guard nonce.length() >= 7 && nonce.length() <= 13 else {
    raise @spec.Broken::Size(want=13, got=nonce.length())
  }
  guard cipher.length() >= self.tag else {
    raise @spec.Broken::Size(want=self.tag, got=cipher.length())
  }
  let body = cipher[0:cipher.length() - self.tag]
  let given = cipher[cipher.length() - self.tag:]
  let plain = self.stream(nonce, body)
  let t = self.mac(nonce, plain, aad)
  let mask = self.cipher.encrypt(counter_block(nonce, 0UL))
  let expected : FixedArray[Byte] = FixedArray::make(self.tag, b'\x00')
  for i in 0..<self.tag {
    expected[i] = t[i] ^ mask[i]
  }
  guard @spec.eq(Bytes::from_array(expected)[:], given) else {
    raise @spec.Broken::Tag
  }
  plain
}

///|
/// Encrypt and authenticate in one call, with a context that lives just long
/// enough.
pub fn seal(
  cipher : &@spec.Block,
  nonce : BytesView,
  plain : BytesView,
  aad~ : BytesView = b""[:],
  tag~ : Int32 = tag,
) -> Bytes raise @spec.Broken {
  Ccm::new(cipher, tag~).seal(nonce~, plain~, aad~)
}

///|
/// Authenticate and decrypt in one call.
pub fn open(
  cipher : &@spec.Block,
  nonce : BytesView,
  box : BytesView,
  aad~ : BytesView = b""[:],
  tag~ : Int32 = tag,
) -> Bytes raise @spec.Broken {
  Ccm::new(cipher, tag~).open(nonce~, cipher=box, aad~)
}

///|
pub impl @spec.Aead for Ccm with fn seal(self, nonce~, plain~, aad~) {
  self.seal(nonce~, plain~, aad~)
}

///|
pub impl @spec.Aead for Ccm with fn open(self, nonce~, cipher~, aad~) {
  self.open(nonce~, cipher~, aad~)
}
