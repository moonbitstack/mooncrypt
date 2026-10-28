// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The chaining value a fresh hasher starts from — BLAKE2s's initial vector,
/// reused as nothing more than a constant.
let iv : FixedArray[UInt32] = [
  0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU, 0x510E527FU, 0x9B05688CU, 0x1F83D9ABU,
  0x5BE0CD19U,
]

///|
/// How a block's words are reordered between rounds.
let permutation : FixedArray[Int32] = [
  2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
]

///|
/// The first block of a chunk, which is compressed differently from the rest.
let chunk_start : UInt32 = 1

///|
let chunk_end : UInt32 = 2

///|
/// A node with two children rather than a run of message.
let parent : UInt32 = 4

///|
/// The final compression, whose output is read rather than chained.
let root : UInt32 = 8

///|
let keyed : UInt32 = 16

///|
let derive_context : UInt32 = 32

///|
let derive_material : UInt32 = 64

///|
/// The digest length in bytes, which is what [`@spec.Hash`] reports.
pub let size : Int32 = 32

///|
/// The block length in bytes.
pub let block : Int32 = 64

///|
/// The chunk length in bytes — the unit the tree is built from.
pub let chunk : Int32 = 1024

///|
fn rotr(x : UInt32, n : Int32) -> UInt32 {
  (x >> n) | (x << (32 - n))
}

///|
fn g(
  s : FixedArray[UInt32],
  a : Int32,
  b : Int32,
  c : Int32,
  d : Int32,
  x : UInt32,
  y : UInt32,
) -> Unit {
  s[a] = s[a] + s[b] + x
  s[d] = rotr(s[d] ^ s[a], 16)
  s[c] = s[c] + s[d]
  s[b] = rotr(s[b] ^ s[c], 12)
  s[a] = s[a] + s[b] + y
  s[d] = rotr(s[d] ^ s[a], 8)
  s[c] = s[c] + s[d]
  s[b] = rotr(s[b] ^ s[c], 7)
}

///|
fn round(s : FixedArray[UInt32], m : FixedArray[UInt32]) -> Unit {
  g(s, 0, 4, 8, 12, m[0], m[1])
  g(s, 1, 5, 9, 13, m[2], m[3])
  g(s, 2, 6, 10, 14, m[4], m[5])
  g(s, 3, 7, 11, 15, m[6], m[7])
  g(s, 0, 5, 10, 15, m[8], m[9])
  g(s, 1, 6, 11, 12, m[10], m[11])
  g(s, 2, 7, 8, 13, m[12], m[13])
  g(s, 3, 4, 9, 14, m[14], m[15])
}

///|
/// A view copied into an array of its own, which is what the word readers take.
fn as_array(v : BytesView) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(v.length(), b'\x00')
  for i in 0..<v.length() {
    out[i] = v[i]
  }
  out
}

///|
fn word(s : FixedArray[Byte], i : Int32) -> UInt32 {
  let mut v = 0U
  for b in 0..<4 {
    v = v | (s[i * 4 + b].to_int().reinterpret_as_uint() << (b * 8))
  }
  v
}

///|
/// The block's sixteen words, little-endian.
fn words(buf : FixedArray[Byte]) -> FixedArray[UInt32] {
  let out : FixedArray[UInt32] = FixedArray::make(16, 0U)
  for i in 0..<16 {
    out[i] = word(buf, i)
  }
  out
}

///|
/// The compression function: ten state words of chaining value and constants,
/// four of counter, one of length, one of flags, then seven rounds.
fn compress(
  cv : FixedArray[UInt32],
  m : FixedArray[UInt32],
  counter : UInt64,
  len : UInt32,
  flags : UInt32,
) -> FixedArray[UInt32] {
  let s : FixedArray[UInt32] = FixedArray::make(16, 0U)
  for i in 0..<8 {
    s[i] = cv[i]
  }
  for i in 0..<4 {
    s[i + 8] = iv[i]
  }
  s[12] = counter.to_uint()
  s[13] = (counter >> 32).to_uint()
  s[14] = len
  s[15] = flags
  let block = words_dup(m)
  for _ in 0..<7 {
    round(s, block)
    let next = words_dup(block)
    for i in 0..<16 {
      block[i] = next[permutation[i]]
    }
  }
  for i in 0..<8 {
    s[i] = s[i] ^ s[i + 8]
    s[i + 8] = s[i + 8] ^ cv[i]
  }
  s
}

///|
fn words_dup(m : FixedArray[UInt32]) -> FixedArray[UInt32] {
  let out : FixedArray[UInt32] = FixedArray::make(16, 0U)
  for i in 0..<16 {
    out[i] = m[i]
  }
  out
}

///|
/// The first eight words of a compression, which is what a tree node passes up.
fn first8(s : FixedArray[UInt32]) -> FixedArray[UInt32] {
  let out : FixedArray[UInt32] = FixedArray::make(8, 0U)
  for i in 0..<8 {
    out[i] = s[i]
  }
  out
}

///|
/// A block that has been filled and is waiting to be chained or read.
priv struct Output {
  cv : FixedArray[UInt32]
  m : FixedArray[UInt32]
  counter : UInt64
  len : UInt32
  flags : UInt32
}

///|
fn Output::chaining_value(self : Output) -> FixedArray[UInt32] {
  first8(compress(self.cv, self.m, self.counter, self.len, self.flags))
}

///|
/// Read `len` bytes of the root output. The output block counter replaces the
/// chunk counter, which is what lets the latter be reused instead of widened.
fn Output::read(self : Output, len : Int32) -> Bytes {
  let out : Array[Byte] = []
  let mut counter = 0UL
  while out.length() < len {
    let s = compress(self.cv, self.m, counter, self.len, self.flags | root)
    for i in 0..<16 {
      for b in 0..<4 {
        out.push(((s[i] >> (b * 8)) & 0xFFU).to_byte())
      }
    }
    counter += 1
  }
  Bytes::from_array(out[0:len].to_owned())
}

///|
/// One chunk in progress: the chaining value so far, the block being filled,
/// and how much of the chunk has been compressed.
priv struct Chunk {
  mut cv : FixedArray[UInt32]
  counter : UInt64
  buf : FixedArray[Byte]
  mut len : Int32
  mut blocks : Int32
  flags : UInt32
}

///|
fn Chunk::new(
  cv : FixedArray[UInt32],
  counter : UInt64,
  flags : UInt32,
) -> Chunk {
  {
    cv: first8(cv),
    counter,
    buf: FixedArray::make(64, b'\x00'),
    len: 0,
    blocks: 0,
    flags,
  }
}

///|
fn Chunk::filled(self : Chunk) -> Int32 {
  self.blocks * 64 + self.len
}

///|
/// The flag that marks the first block of a chunk. It is not a property of the
/// hasher, because it is true of exactly one block per chunk.
fn Chunk::start_flag(self : Chunk) -> UInt32 {
  if self.blocks == 0 {
    chunk_start
  } else {
    0
  }
}

///|
fn Chunk::write(self : Chunk, msg : BytesView) -> Unit {
  let mut at = 0
  while at < msg.length() {
    if self.len == 64 {
      let block_words = words(self.buf)
      self.cv = first8(
        compress(
          self.cv,
          block_words,
          self.counter,
          64U,
          self.flags | self.start_flag(),
        ),
      )
      self.blocks += 1
      for i in 0..<64 {
        self.buf[i] = b'\x00'
      }
      self.len = 0
    }
    let room = 64 - self.len
    let left = msg.length() - at
    let take = if room < left { room } else { left }
    for i in 0..<take {
      self.buf[self.len + i] = msg[at + i]
    }
    self.len += take
    at += take
  }
}

///|
fn Chunk::output(self : Chunk) -> Output {
  {
    cv: self.cv,
    m: words(self.buf),
    counter: self.counter,
    len: self.len.reinterpret_as_uint(),
    flags: self.flags | self.start_flag() | chunk_end,
  }
}

///|
/// A BLAKE3 computation in progress.
struct Hasher {
  key : FixedArray[UInt32]
  flags : UInt32
  mut part : Chunk
  stack : Array[FixedArray[UInt32]]
}

///|
fn fresh(key : FixedArray[UInt32], flags : UInt32) -> Hasher {
  { key: first8(key), flags, part: Chunk::new(key, 0UL, flags), stack: [], }
}

///|
/// A plain BLAKE3 hasher.
pub fn Hasher::new() -> Hasher {
  fresh(iv, 0U)
}

///|
/// A keyed hasher, which is a MAC: the key stands in for the initial vector, so
/// a keyed hash has no relation to the unkeyed one.
pub fn Hasher::keyed(key : BytesView) -> Hasher raise @spec.Broken {
  guard key.length() == 32 else {
    raise @spec.Broken::Size(want=32, got=key.length())
  }
  let kw : FixedArray[UInt32] = FixedArray::make(8, 0U)
  for i in 0..<8 {
    kw[i] = word(as_array(key), i)
  }
  fresh(kw, keyed)
}

///|
/// Key derivation mode: the context string is hashed first, and its digest
/// becomes the key, so two contexts give two unrelated functions.
pub fn Hasher::derive_key(context : BytesView) -> Hasher {
  let ctx = run(context, 32, iv, derive_context)
  let kw : FixedArray[UInt32] = FixedArray::make(8, 0U)
  for i in 0..<8 {
    kw[i] = word(as_array(ctx), i)
  }
  fresh(kw, derive_material)
}

///|
/// Absorb more message.
fn Hasher::feed(self : Hasher, msg : BytesView) -> Unit {
  let mut at = 0
  while at < msg.length() {
    if self.part.filled() == 1024 {
      let cv = self.part.output().chaining_value()
      let total = self.part.counter + 1UL
      self.add(cv, total)
      self.part = Chunk::new(self.key, total, self.flags)
    }
    let room = 1024 - self.part.filled()
    let left = msg.length() - at
    let take = if room < left { room } else { left }
    self.part.write(msg[at:at + take])
    at += take
  }
}

///|
/// Fold a finished subtree into the stack: every time the count of chunks is
/// even, the two halves of that subtree are complete and become one node.
fn Hasher::add(self : Hasher, cv : FixedArray[UInt32], total : UInt64) -> Unit {
  let mut node = cv
  let mut n = total
  while (n & 1UL) == 0UL {
    guard self.stack.length() > 0 else {
      abort("blake3: a subtree with no left half")
    }
    let left = self.stack[self.stack.length() - 1]
    let _ = self.stack.pop()
    node = parent_cv(self.key, left, node, self.flags)
    n = n >> 1
  }
  self.stack.push(node)
}

///|
fn parent_cv(
  key : FixedArray[UInt32],
  left : FixedArray[UInt32],
  right : FixedArray[UInt32],
  flags : UInt32,
) -> FixedArray[UInt32] {
  let m : FixedArray[UInt32] = FixedArray::make(16, 0U)
  for i in 0..<8 {
    m[i] = left[i]
    m[i + 8] = right[i]
  }
  first8(compress(key, m, 0UL, 64U, flags | parent))
}

///|
/// Read `len` bytes of output from everything written so far, without
/// disturbing the state: a caller may read and then keep writing.
pub fn Hasher::read(self : Hasher, len : Int32) -> Bytes {
  let mut out = self.part.output()
  let mut i = self.stack.length()
  while i > 0 {
    i -= 1
    out = {
      cv: self.key,
      m: join(self.stack[i], out.chaining_value()),
      counter: 0UL,
      len: 64U,
      flags: self.flags | parent,
    }
  }
  out.read(len)
}

///|
fn join(
  left : FixedArray[UInt32],
  right : FixedArray[UInt32],
) -> FixedArray[UInt32] {
  let m : FixedArray[UInt32] = FixedArray::make(16, 0U)
  for i in 0..<8 {
    m[i] = left[i]
    m[i + 8] = right[i]
  }
  m
}

///|
pub extend Hasher with @spec.Hash::{block, finish, reset, size, write}

///|
pub impl @spec.Hash for Hasher with fn write(self : Hasher, msg : BytesView) -> Unit {
  self.feed(msg)
}

///|
pub impl @spec.Hash for Hasher with fn finish(self : Hasher) -> Bytes {
  self.read(32)
}

///|
/// A keyed or deriving hasher cannot be reset to a bare state without losing
/// what makes it that hasher, so this keeps the key and the flags.
pub impl @spec.Hash for Hasher with fn reset(self : Hasher) -> Unit {
  self.part = Chunk::new(self.key, 0UL, self.flags)
  while self.stack.length() > 0 {
    let _ = self.stack.pop()
  }
}

///|
pub impl @spec.Hash for Hasher with fn size(_self : Hasher) -> Int32 {
  32
}

///|
pub impl @spec.Hash for Hasher with fn block(_self : Hasher) -> Int32 {
  64
}

///|
/// Hash one whole message, read to `len` bytes.
pub fn blake3(msg : BytesView, len~ : Int32 = 32) -> Bytes {
  let h = fresh(iv, 0U)
  h.feed(msg)
  h.read(len)
}

///|
/// Hash one whole message to 32 bytes.
pub fn hash(msg : BytesView) -> Bytes {
  blake3(msg)
}

///|
/// One whole message through a key that has already been reduced to words,
/// under flags that set the mode.
fn run(
  msg : BytesView,
  len : Int32,
  key : FixedArray[UInt32],
  flags : UInt32,
) -> Bytes {
  let h = fresh(key, flags)
  h.feed(msg)
  h.read(len)
}

///|
/// Keyed hash of one whole message, read to `len` bytes.
pub fn keyed_hash(
  key : BytesView,
  msg : BytesView,
  len~ : Int32 = 32,
) -> Bytes raise @spec.Broken {
  let h = Hasher::keyed(key)
  h.feed(msg)
  h.read(len)
}

///|
/// Derive `len` bytes of key material for `context` from `material`.
pub fn derive_key(
  context : BytesView,
  material : BytesView,
  len~ : Int32 = 32,
) -> Bytes {
  let h = Hasher::derive_key(context)
  h.feed(material)
  h.read(len)
}
