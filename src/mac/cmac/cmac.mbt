// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The constant that reduces a doubled block back into the field, for the two
/// block sizes that have ciphers worth using with this mode.
///
/// Doubling is a left shift, and a shift that carries off the top has to be
/// folded back in. Which bits that means depends on the block width, because the
/// reduction polynomial is x^b + x^7 + x^2 + x + 1 for both 128- and 64-bit
/// blocks — so the constant is 0x87 for sixteen bytes and 0x1b for eight.
fn reduction(size : Int32) -> Int32 {
  match size {
    16 => 0x87
    8 => 0x1B
    _ => abort("cmac: a block is 8 or 16 bytes for this mode, not \{size}")
  }
}

///|
/// Double a block in GF(2^b): shift left by one bit, and fold the bit that falls
/// off the top back in with [`reduction`].
fn double(size : Int32, block : FixedArray[Byte]) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(size, b'\x00')
  let mut carry = 0
  for step in 0..<size {
    let i = size - 1 - step
    let v = block[i].to_int()
    out[i] = (((v << 1) & 0xFF) | carry).to_byte()
    carry = (v >> 7) & 1
  }
  if (block[0].to_int() & 0x80) != 0 {
    out[size - 1] = (out[size - 1].to_int() ^ reduction(size)).to_byte()
  }
  out
}

///|
/// CMAC over any block cipher, as a state you feed and then read.
///
/// The two subkeys are computed once, when the context is made, from a single
/// encryption of the zero block — that is the whole of the setup.
pub struct Cmac {
  ///
  /// The block cipher this authenticates with.
  cipher : &@spec.Block
  ///
  /// The subkey used when the message ends exactly on a block boundary.
  k1 : FixedArray[Byte]
  ///
  /// The subkey used when the last block had to be padded.
  k2 : FixedArray[Byte]
  ///
  /// The CBC chain so far.
  chain : FixedArray[Byte]
  ///
  /// The block being filled. It is held back rather than chained immediately,
  /// because whether it is the last block is not known until the message ends,
  /// and the last block is treated differently.
  pending : FixedArray[Byte]
  ///
  /// How many bytes of `pending` are spoken for.
  mut held : Int32
  ///
  /// How many bytes of the cipher output to keep.
  tag : Int32
}

///|
/// Start a CMAC context over a block cipher.
///
/// `tag` is the length of the tag to produce. SP 800-38B allows any prefix of
/// the full block, but each bit given up halves the forgery resistance, so the
/// default is the whole block and shorter values are a deliberate trade.
pub fn Cmac::new(
  cipher : &@spec.Block,
  tag~ : Int32 = 16,
) -> Cmac raise @spec.Broken {
  let size = cipher.block()
  let _ = reduction(size)
  guard tag >= 1 && tag <= size else {
    raise @spec.Broken::Size(want=size, got=tag)
  }
  let zero : FixedArray[Byte] = FixedArray::make(size, b'\x00')
  let l = cipher.encrypt(Bytes::from_array(zero))
  let lbytes : FixedArray[Byte] = FixedArray::make(size, b'\x00')
  for i in 0..<size {
    lbytes[i] = l[i]
  }
  let k1 = double(size, lbytes)
  let k2 = double(size, k1)
  {
    cipher,
    k1,
    k2,
    chain: FixedArray::make(size, b'\x00'),
    pending: FixedArray::make(size, b'\x00'),
    held: 0,
    tag,
  }
}

///|
/// Fold a full block into the chain. Only called for blocks that are known not
/// to be the last.
fn absorb(state : Cmac, block : FixedArray[Byte]) -> Unit {
  let size = state.cipher.block()
  let mixed : FixedArray[Byte] = FixedArray::make(size, b'\x00')
  for i in 0..<size {
    mixed[i] = state.chain[i] ^ block[i]
  }
  let out = state.cipher.encrypt(Bytes::from_array(mixed))
  for i in 0..<size {
    state.chain[i] = out[i]
  }
}

///|
/// Feed more message. Any length is fine; the last block is held back until
/// [`finish`](#finish) says which subkey it takes.
pub fn Cmac::write(self : Cmac, data : BytesView) -> Unit {
  let size = self.cipher.block()
  for i in 0..<data.length() {
    if self.held == size {
      let full : FixedArray[Byte] = FixedArray::make(size, b'\x00')
      for k in 0..<size {
        full[k] = self.pending[k]
      }
      absorb(self, full)
      self.held = 0
    }
    self.pending[self.held] = data[i]
    self.held = self.held + 1
  }
}

///|
/// The tag for everything written so far. The state is left as it was, so more
/// message can be added and the tag read again — which is what makes a MAC
/// usable for a running transcript.
pub fn Cmac::finish(self : Cmac) -> Bytes {
  let size = self.cipher.block()
  let last : FixedArray[Byte] = FixedArray::make(size, b'\x00')
  if self.held == size {
    // A complete final block takes the first subkey.
    for i in 0..<size {
      last[i] = self.pending[i] ^ self.k1[i]
    }
  } else {
    // Anything shorter is padded with 0x80 and zeroes and takes the second.
    for i in 0..<self.held {
      last[i] = self.pending[i]
    }
    last[self.held] = b'\x80'
    for i in 0..<size {
      last[i] = last[i] ^ self.k2[i]
    }
  }
  let mixed : FixedArray[Byte] = FixedArray::make(size, b'\x00')
  for i in 0..<size {
    mixed[i] = self.chain[i] ^ last[i]
  }
  let out = self.cipher.encrypt(Bytes::from_array(mixed))
  let kept : Array[Byte] = []
  for i in 0..<self.tag {
    kept.push(out[i])
  }
  Bytes::from_array(kept)
}

///|
/// Put the context back to the state a newly made one is in, keeping the
/// subkeys.
pub fn Cmac::reset(self : Cmac) -> Unit {
  for i in 0..<self.chain.length() {
    self.chain[i] = b'\x00'
    self.pending[i] = b'\x00'
  }
  self.held = 0
}

///|
/// The tag length in bytes.
pub fn Cmac::size(self : Cmac) -> Int32 {
  self.tag
}

///|
/// Overwrite the subkeys and the chain.
pub fn Cmac::wipe(self : Cmac) -> Unit {
  for i in 0..<self.chain.length() {
    self.chain[i] = b'\x00'
    self.pending[i] = b'\x00'
    self.k1[i] = b'\x00'
    self.k2[i] = b'\x00'
  }
  self.held = 0
}

///|
/// The tag of a message, in one call.
pub fn mac(
  cipher : &@spec.Block,
  message : BytesView,
  tag~ : Int32 = 16,
) -> Bytes raise @spec.Broken {
  let state = Cmac::new(cipher, tag~)
  state.write(message)
  state.finish()
}

///|
pub impl @spec.Mac for Cmac with fn write(self, data) {
  self.write(data)
}

///|
pub impl @spec.Mac for Cmac with fn finish(self) {
  self.finish()
}

///|
pub impl @spec.Mac for Cmac with fn size(self) {
  self.size()
}
