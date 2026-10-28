// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The three numbers a scrypt derivation is defined by.
///
/// `n` is the number of blocks the inner loop keeps, so the memory it takes is
/// `128 * r * n` bytes; `r` is the block size divided by 128; and `p` is how
/// many of those passes run in parallel, which multiplies the time but not the
/// memory. Doubling `n` doubles both, which is why it is the knob to turn.
pub(all) struct Params {
  n : Int32
  r : Int32
  p : Int32
} derive(Eq, Debug)

///|
pub extend Params with Eq::{equal, not_equal}

///|
pub extend Params with Debug::{to_repr}

///|
/// The smallest `n` RFC 7914 allows: it must be a power of two above one.
pub let min_n : Int32 = 2

///|
/// A preset for logging in: 16 MiB of memory, one pass. Fast enough to answer a
/// request, slow enough that a guess costs a real machine a real fraction of a
/// second.
pub let interactive : Params = { n: 16384, r: 8, p: 1, }

///|
/// A preset for storing a password that will not be asked for often: 1 GiB of
/// memory. Anything that must run on a small device cannot afford it.
pub let sensitive : Params = { n: 1 << 20, r: 8, p: 1, }

///|
/// Check the three numbers before a derivation spends memory on them.
///
/// The RFC's own limits: `n` a power of two greater than one, `r` and `p`
/// positive, and `128 * r * p` below 2³⁰ so that the block counter cannot
/// overflow.
pub fn Params::new(
  n~ : Int32 = 16384,
  r~ : Int32 = 8,
  p~ : Int32 = 1,
) -> Params {
  guard n >= min_n && (n & (n - 1)) == 0 else {
    abort("scrypt: n must be a power of two above one, not \{n}")
  }
  guard r > 0 && p > 0 else { abort("scrypt: r and p must be positive") }
  guard r * p < (1 << 30) / 128 else {
    abort("scrypt: 128 * r * p must stay below 2^30")
  }
  { n, r, p, }
}

///|
fn rotl(x : UInt32, n : Int32) -> UInt32 {
  (x << n) | (x >> (32 - n))
}

///|
/// The Salsa20/8 core (RFC 7914 §3): twenty operations of add-xor-rotate,
/// arranged as four double rounds, over sixteen words in place.
fn salsa8(b : FixedArray[UInt32]) -> Unit {
  let x : FixedArray[UInt32] = FixedArray::make(16, 0U)
  for i in 0..<16 {
    x[i] = b[i]
  }
  for _ in 0..<4 {
    // Column round.
    x[4] = x[4] ^ rotl(x[0] + x[12], 7)
    x[8] = x[8] ^ rotl(x[4] + x[0], 9)
    x[12] = x[12] ^ rotl(x[8] + x[4], 13)
    x[0] = x[0] ^ rotl(x[12] + x[8], 18)
    x[9] = x[9] ^ rotl(x[5] + x[1], 7)
    x[13] = x[13] ^ rotl(x[9] + x[5], 9)
    x[1] = x[1] ^ rotl(x[13] + x[9], 13)
    x[5] = x[5] ^ rotl(x[1] + x[13], 18)
    x[14] = x[14] ^ rotl(x[10] + x[6], 7)
    x[2] = x[2] ^ rotl(x[14] + x[10], 9)
    x[6] = x[6] ^ rotl(x[2] + x[14], 13)
    x[10] = x[10] ^ rotl(x[6] + x[2], 18)
    x[3] = x[3] ^ rotl(x[15] + x[11], 7)
    x[7] = x[7] ^ rotl(x[3] + x[15], 9)
    x[11] = x[11] ^ rotl(x[7] + x[3], 13)
    x[15] = x[15] ^ rotl(x[11] + x[7], 18)
    // Row round.
    x[1] = x[1] ^ rotl(x[0] + x[3], 7)
    x[2] = x[2] ^ rotl(x[1] + x[0], 9)
    x[3] = x[3] ^ rotl(x[2] + x[1], 13)
    x[0] = x[0] ^ rotl(x[3] + x[2], 18)
    x[6] = x[6] ^ rotl(x[5] + x[4], 7)
    x[7] = x[7] ^ rotl(x[6] + x[5], 9)
    x[4] = x[4] ^ rotl(x[7] + x[6], 13)
    x[5] = x[5] ^ rotl(x[4] + x[7], 18)
    x[11] = x[11] ^ rotl(x[10] + x[9], 7)
    x[8] = x[8] ^ rotl(x[11] + x[10], 9)
    x[9] = x[9] ^ rotl(x[8] + x[11], 13)
    x[10] = x[10] ^ rotl(x[9] + x[8], 18)
    x[12] = x[12] ^ rotl(x[15] + x[14], 7)
    x[13] = x[13] ^ rotl(x[12] + x[15], 9)
    x[14] = x[14] ^ rotl(x[13] + x[12], 13)
    x[15] = x[15] ^ rotl(x[14] + x[13], 18)
  }
  for i in 0..<16 {
    b[i] = b[i] + x[i]
  }
}

///|
/// Read sixteen little-endian words from a 64-byte block.
fn load(x : FixedArray[UInt32], src : FixedArray[Byte], off : Int32) -> Unit {
  for i in 0..<16 {
    let j = off + i * 4
    x[i] = src[j].to_int().reinterpret_as_uint() |
      (src[j + 1].to_int().reinterpret_as_uint() << 8) |
      (src[j + 2].to_int().reinterpret_as_uint() << 16) |
      (src[j + 3].to_int().reinterpret_as_uint() << 24)
  }
}

///|
fn store(dst : FixedArray[Byte], off : Int32, x : FixedArray[UInt32]) -> Unit {
  for i in 0..<16 {
    let j = off + i * 4
    dst[j] = (x[i] & 0xFFU).to_byte()
    dst[j + 1] = ((x[i] >> 8) & 0xFFU).to_byte()
    dst[j + 2] = ((x[i] >> 16) & 0xFFU).to_byte()
    dst[j + 3] = ((x[i] >> 24) & 0xFFU).to_byte()
  }
}

///|
/// `BlockMix` (RFC 7914 §4): chain the 2r blocks through the Salsa core, then
/// interleave the even and odd results — which is what spreads one block's
/// influence across the whole block from the next step on.
fn block_mix(
  input : FixedArray[Byte],
  output : FixedArray[Byte],
  r : Int32,
) -> Unit {
  let x : FixedArray[UInt32] = FixedArray::make(16, 0U)
  let t : FixedArray[UInt32] = FixedArray::make(16, 0U)
  // X = B[2r-1]
  load(x, input, (2 * r - 1) * 64)
  for i in 0..<(2 * r) {
    load(t, input, i * 64)
    for k in 0..<16 {
      x[k] = x[k] ^ t[k]
    }
    salsa8(x)
    // Even results go to the first half, odd to the second.
    let at = if i % 2 == 0 { i / 2 } else { r + (i - 1) / 2 }
    store(output, at * 64, x)
  }
}

///|
/// `Integerify`: the last 64-byte block read as a little-endian number, which
/// picks where in the buffer the next mix reads from.
fn integerify(b : FixedArray[Byte], r : Int32, n : Int32) -> Int32 {
  let at = (2 * r - 1) * 64
  let mut v = 0UL
  for i = 7; i >= 0; i = i - 1 {
    v = (v << 8) | b[at + i].to_int().to_uint64()
  }
  (v % n.to_uint64()).to_int()
}

///|
/// `ROMix` (RFC 7914 §5): fill `n` blocks, then walk them in a password-chosen
/// order. The walk is what makes the buffer unavoidable: every step needs a
/// block that could be anywhere in it.
fn romix(block : FixedArray[Byte], n : Int32, r : Int32) -> Unit {
  let size = 128 * r
  let x : FixedArray[Byte] = FixedArray::make(size, b'\x00')
  let y : FixedArray[Byte] = FixedArray::make(size, b'\x00')
  for i in 0..<size {
    x[i] = block[i]
  }
  let v : FixedArray[Byte] = FixedArray::make(n * size, b'\x00')
  for i in 0..<n {
    for k in 0..<size {
      v[i * size + k] = x[k]
    }
    block_mix(x, y, r)
    for k in 0..<size {
      x[k] = y[k]
    }
  }
  for _ in 0..<n {
    let j = integerify(x, r, n)
    for k in 0..<size {
      x[k] = x[k] ^ v[j * size + k]
    }
    block_mix(x, y, r)
    for k in 0..<size {
      x[k] = y[k]
    }
  }
  for k in 0..<size {
    block[k] = x[k]
  }
}

///|
/// Derive `len` bytes from a password and a salt (RFC 7914 §6).
///
/// `n`, `r` and `p` are the cost. The memory is `128 * r * n` bytes, so the
/// default preset's 16 MiB is deliberate rather than incidental: it is what
/// makes a hardware attack cost memory as well as time.
pub fn key(
  password : BytesView,
  salt : BytesView,
  params~ : Params = interactive,
  len~ : Int32 = 32,
) -> Bytes {
  let cost = Params::new(n=params.n, r=params.r, p=params.p)
  let size = 128 * cost.r
  let b = @pbkdf2.key(
    password,
    salt,
    fn() { @sha2.Hasher::new() },
    rounds=1,
    len=size * cost.p,
  )
  let blocks : FixedArray[Byte] = FixedArray::make(size * cost.p, b'\x00')
  for i in 0..<blocks.length() {
    blocks[i] = b[i]
  }
  for i in 0..<cost.p {
    let one : FixedArray[Byte] = FixedArray::make(size, b'\x00')
    for k in 0..<size {
      one[k] = blocks[i * size + k]
    }
    romix(one, cost.n, cost.r)
    for k in 0..<size {
      blocks[i * size + k] = one[k]
    }
  }
  let mixed = Bytes::from_array(blocks)
  @pbkdf2.key(password, mixed[:], fn() { @sha2.Hasher::new() }, rounds=1, len~)
}
