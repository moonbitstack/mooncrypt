// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Cipher Block Chaining: each block is XORed with the ciphertext of the one
/// before it, so the same plaintext block at two positions encrypts differently
/// and a change anywhere propagates to everything after it.
///
/// The chaining state carries across calls, so a message can be encrypted in
/// pieces as long as every piece is a whole number of blocks. Use [`pad`] and
/// [`unpad`] when the message is not.
pub struct Cbc {
  ///
  /// The block cipher this runs over. Any width works; the chaining vector is
  /// whatever length the cipher says it is.
  cipher : &@spec.Block
  ///
  /// The vector [`reset`](#reset) goes back to, kept so a context can be reused
  /// without the caller holding on to it.
  start : FixedArray[Byte]
  ///
  /// The running value: the last ciphertext block when encrypting, the previous
  /// ciphertext block when decrypting.
  chain : FixedArray[Byte]
}

///|
/// Start a CBC context.
///
/// The initialisation vector does not have to be secret, but it must not repeat
/// under the same key: two messages that begin with the same blocks would then
/// begin with the same ciphertext, which is the one thing CBC exists to avoid.
pub fn Cbc::new(
  cipher : &@spec.Block,
  iv : BytesView,
) -> Cbc raise @spec.Broken {
  guard iv.length() == cipher.block() else {
    raise @spec.Broken::Size(want=cipher.block(), got=iv.length())
  }
  let start : FixedArray[Byte] = FixedArray::make(iv.length(), b'\x00')
  let chain : FixedArray[Byte] = FixedArray::make(iv.length(), b'\x00')
  for i in 0..<iv.length() {
    start[i] = iv[i]
    chain[i] = iv[i]
  }
  { cipher, start, chain, }
}

///|
/// Encrypt a whole number of blocks, continuing the chain from where the last
/// call left off.
pub fn Cbc::encrypt(self : Cbc, plain : BytesView) -> Bytes {
  let size = self.cipher.block()
  guard plain.length() % size == 0 else {
    abort(
      "cbc: the input must be a whole number of \{size}-byte blocks, not \{plain.length()} bytes",
    )
  }
  let out : Array[Byte] = []
  for at in 0..<(plain.length() / size) {
    let off = at * size
    for i in 0..<size {
      self.chain[i] = self.chain[i] ^ plain[off + i]
    }
    let chained = self.cipher.encrypt(Bytes::from_array(self.chain))
    for i in 0..<size {
      self.chain[i] = chained[i]
      out.push(chained[i])
    }
  }
  Bytes::from_array(out)
}

///|
/// Decrypt a whole number of blocks, continuing the chain from where the last
/// call left off.
pub fn Cbc::decrypt(self : Cbc, cipher : BytesView) -> Bytes {
  let size = self.cipher.block()
  guard cipher.length() % size == 0 else {
    abort(
      "cbc: the input must be a whole number of \{size}-byte blocks, not \{cipher.length()} bytes",
    )
  }
  let out : Array[Byte] = []
  for at in 0..<(cipher.length() / size) {
    let off = at * size
    let opened = self.cipher.decrypt(cipher[off:off + size])
    for i in 0..<size {
      out.push(opened[i] ^ self.chain[i])
      self.chain[i] = cipher[off + i]
    }
  }
  Bytes::from_array(out)
}

///|
/// Put the chaining value back to the initialisation vector, so the context can
/// be used again for another message.
pub fn Cbc::reset(self : Cbc) -> Unit {
  for i in 0..<self.chain.length() {
    self.chain[i] = self.start[i]
  }
}

///|
/// The block length in bytes.
pub fn Cbc::block(self : Cbc) -> Int32 {
  self.cipher.block()
}

///|
/// Counter mode: the cipher encrypts a counter that goes up by one per block,
/// and the result is the keystream. Encryption and decryption are the same
/// operation, no padding is needed, and blocks can be processed in parallel —
/// which is why it is the mode inside GCM.
///
/// It authenticates nothing on its own, and reusing a counter value under the
/// same key reuses the keystream, which reveals the XOR of the two plaintexts.
pub struct Ctr {
  ///
  /// The block cipher this runs over.
  cipher : &@spec.Block
  ///
  /// The counter block [`reset`](#reset) goes back to.
  start : FixedArray[Byte]
  ///
  /// The counter block that will be encrypted next.
  counter : FixedArray[Byte]
  ///
  /// The current keystream block, and how much of it has been used. Keeping the
  /// unused rest lets a caller encrypt byte by byte without throwing away
  /// keystream, which would be a way to reuse it.
  stream : FixedArray[Byte]
  mut used : Int32
}

///|
/// Start a counter-mode context.
///
/// The nonce is the whole initial counter block, so for a 128-bit block cipher
/// it is sixteen bytes. It must never repeat under the same key.
pub fn Ctr::new(
  cipher : &@spec.Block,
  nonce : BytesView,
) -> Ctr raise @spec.Broken {
  guard nonce.length() == cipher.block() else {
    raise @spec.Broken::Size(want=cipher.block(), got=nonce.length())
  }
  let start : FixedArray[Byte] = FixedArray::make(nonce.length(), b'\x00')
  let counter : FixedArray[Byte] = FixedArray::make(nonce.length(), b'\x00')
  for i in 0..<nonce.length() {
    start[i] = nonce[i]
    counter[i] = nonce[i]
  }
  {
    cipher,
    start,
    counter,
    stream: FixedArray::make(nonce.length(), b'\x00'),
    used: nonce.length(),
  }
}

///|
/// Add one to the counter block, as a big-endian integer of the whole width.
///
/// SP 800-38A leaves the split between the fixed part and the counter to the
/// application; incrementing all the bits is the choice that never wraps early.
/// A message long enough to wrap a 128-bit counter would be 2¹³² bytes.
fn bump(block : FixedArray[Byte]) -> Unit {
  let mut i = block.length() - 1
  while i >= 0 {
    if block[i] == b'\xFF' {
      block[i] = b'\x00'
      i = i - 1
    } else {
      block[i] = (block[i].to_int() + 1).to_byte()
      return
    }
  }
}

///|
/// XOR a byte string with the keystream, continuing from wherever the last call
/// stopped. Encrypting and decrypting are the same call.
pub fn Ctr::apply(self : Ctr, data : BytesView) -> Bytes {
  let size = self.cipher.block()
  let out : FixedArray[Byte] = FixedArray::make(data.length(), b'\x00')
  for i in 0..<data.length() {
    if self.used == size {
      let fresh = self.cipher.encrypt(Bytes::from_array(self.counter))
      for k in 0..<size {
        self.stream[k] = fresh[k]
      }
      self.used = 0
      bump(self.counter)
    }
    out[i] = data[i] ^ self.stream[self.used]
    self.used = self.used + 1
  }
  Bytes::from_array(out)
}

///|
/// Put the counter back to the initial block and forget the leftover keystream,
/// so the context can encrypt another message from the same nonce.
pub fn Ctr::reset(self : Ctr) -> Unit {
  for i in 0..<self.counter.length() {
    self.counter[i] = self.start[i]
  }
  self.used = self.counter.length()
}

///|
/// The block length in bytes.
pub fn Ctr::block(self : Ctr) -> Int32 {
  self.cipher.block()
}

///|
/// PKCS#7 padding: append `n` bytes each holding the value `n`, where `n` is
/// whatever brings the length up to a multiple of the block size.
///
/// A message that is already a whole number of blocks gains a whole extra block
/// of padding, which is what makes the padding removable without guessing: the
/// last byte always says how much to take off.
pub fn pad(size : Int32, data : BytesView) -> Bytes {
  guard size >= 1 && size <= 255 else {
    abort("mode: a block size that fits in a byte is 1 to 255, not \{size}")
  }
  let extra = size - data.length() % size
  let out : Array[Byte] = []
  for i in 0..<data.length() {
    out.push(data[i])
  }
  for _ in 0..<extra {
    out.push(extra.to_byte())
  }
  Bytes::from_array(out)
}

///|
/// Strip PKCS#7 padding, raising [`@spec.Broken::Tag`] if it is not there.
///
/// The error is deliberately the same one an AEAD gives for a bad tag: whether
/// the padding was wrong or the key was, a caller that reacts differently to the
/// two has built a padding oracle, and that is a complete break of CBC. Treat
/// every failure as "the ciphertext is wrong" and nothing else.
pub fn unpad(size : Int32, data : BytesView) -> Bytes raise @spec.Broken {
  guard size >= 1 && size <= 255 else {
    abort("mode: a block size that fits in a byte is 1 to 255, not \{size}")
  }
  guard data.length() > 0 && data.length() % size == 0 else {
    raise @spec.Broken::Size(want=size, got=data.length())
  }
  let extra = data[data.length() - 1].to_int()
  guard extra >= 1 && extra <= size && extra <= data.length() else {
    raise @spec.Broken::Tag
  }
  for i in 1..<extra {
    guard data[data.length() - 1 - i].to_int() == extra else {
      raise @spec.Broken::Tag
    }
  }
  let kept : Array[Byte] = []
  for i in 0..<(data.length() - extra) {
    kept.push(data[i])
  }
  Bytes::from_array(kept)
}
