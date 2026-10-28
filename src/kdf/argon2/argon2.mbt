// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A 1024-byte block is 128 words, and everything below counts in those.
let words_per_block : Int32 = 128

///|
/// A pass over the memory is cut into four slices so that lanes can be filled
/// in parallel without ever looking at a block another lane has not written
/// yet. The number is part of the design, not a tunable.
let sync_points : Int32 = 4

///|
/// RFC 9106 §3.2: each lane needs at least two blocks per slice, so eight.
let min_memory_per_lane : Int32 = 8

///|
/// The version byte that goes into the initial hash. Version 0x13 — 19 — is
/// the only one RFC 9106 describes, and the only one where a block in a second
/// pass is mixed into the existing block instead of replacing it.
let version : Int32 = 19

///|
/// Which of the three functions to run. They differ only in where the index of
/// the reference block comes from.
pub(all) enum Kind {
  ///
  /// Addresses are read out of the last block written. Fastest, and the only
  /// choice that is safe against a GPU attacker only if the machine is not
  /// shared: the address sequence is a function of the password.
  Argon2d
  ///
  /// Addresses are generated from a counter, so the sequence depends on the
  /// lane and the pass number rather than on the data. Immune to cache-timing
  /// side channels, at the cost of two passes' worth of address computation.
  Argon2i
  ///
  /// Pass number zero, slices zero and one, are data-independent; everything
  /// after that is data-dependent. RFC 9106 §4 recommends this as the default
  /// because it costs almost nothing and closes the cheap attacks.
  Argon2id
} derive(Eq, Debug)

///|
pub extend Kind with Eq::{equal, not_equal}

///|
pub extend Kind with Debug::{to_repr}

///|
/// The number the function is identified by inside the initial hash.
pub fn Kind::code(self : Kind) -> Int32 {
  match self {
    Argon2d => 0
    Argon2i => 1
    Argon2id => 2
  }
}

///|
/// The spelling the RFC uses, for error messages and parameter records.
pub fn Kind::name(self : Kind) -> String {
  match self {
    Argon2d => "Argon2d"
    Argon2i => "Argon2i"
    Argon2id => "Argon2id"
  }
}

///|
/// The three numbers a derivation is defined by.
///
/// `memory` is in kibibytes, and it is what the function is really about: the
/// derivation allocates that much and reads it back in a password-dependent
/// order, so an attacker who cannot afford the memory cannot compute the hash
/// cheaply at all. `passes` multiplies the time without changing the memory.
/// `lanes` is how many independent chains are kept; it is the only knob that
/// helps when the work runs on a GPU, and each lane needs eight blocks.
///
/// The tag length is not here: it is an argument to the derivation, because two
/// calls that differ only in how long an output they want are still the same
/// function with the same cost.
pub(all) struct Params {
  memory : Int32
  passes : Int32
  lanes : Int32
} derive(Eq, Debug)

///|
pub extend Params with Eq::{equal, not_equal}

///|
pub extend Params with Debug::{to_repr}

///|
/// The first option RFC 9106 §4 recommends: 2 GiB, one pass, four lanes. Big
/// enough that a dedicated attacker has to buy the memory, and one pass keeps
/// the wall-clock time at a single sweep.
pub let recommended : Params = { memory: 2097152, passes: 1, lanes: 4, }

///|
/// The second option: 64 MiB, three passes, four lanes. A tenth of the memory
/// and about the same time, for the case where 2 GiB per login is not
/// affordable.
pub let interactive : Params = { memory: 65536, passes: 3, lanes: 4, }

///|
/// The smallest derivation that is still Argon2: 8 KiB, one pass, one lane. It
/// exists so that tests and protocol fixtures can name a size rather than
/// invent one, and it is not a safe way to store a password.
pub let minimum : Params = { memory: 8, passes: 1, lanes: 1, }

///|
/// Check the three numbers before a derivation allocates anything.
///
/// `memory` has to leave room for eight blocks per lane, which is the point
/// below which the reference block rule in §3.4.1 stops working; `lanes` has to
/// be at least one and small enough that the lane number fits in the address
/// computation; and `passes` has to be at least one, since zero passes would
/// leave the memory untouched.
pub fn Params::new(
  memory~ : Int32 = 65536,
  passes~ : Int32 = 3,
  lanes~ : Int32 = 4,
) -> Params {
  guard lanes >= 1 else {
    abort("argon2: lanes must be at least 1, not \{lanes}")
  }
  guard passes >= 1 else {
    abort("argon2: passes must be at least 1, not \{passes}")
  }
  guard memory >= min_memory_per_lane * lanes else {
    abort(
      "argon2: memory must be at least \{min_memory_per_lane * lanes} KiB for \{lanes} lanes, not \{memory}",
    )
  }
  { memory, passes, lanes, }
}

///|
/// How many bytes a derivation with these parameters will actually allocate:
/// the memory is rounded down to a whole number of blocks per slice, and each
/// block is 1 KiB.
pub fn Params::memory_bytes(self : Params) -> Int32 {
  let cost = Params::new(
    memory=self.memory,
    passes=self.passes,
    lanes=self.lanes,
  )
  4 * cost.lanes * (cost.memory / (4 * cost.lanes)) * 1024
}

///|
/// A little-endian 32-bit field, which is how every length and constant in the
/// initial hash is written.
fn le32(x : Int32) -> Bytes {
  let v = x.to_uint64()
  Bytes::from_array([
    (v & 0xFFUL).to_byte(),
    ((v >> 8) & 0xFFUL).to_byte(),
    ((v >> 16) & 0xFFUL).to_byte(),
    ((v >> 24) & 0xFFUL).to_byte(),
  ])
}

///|
/// Concatenate any number of byte strings, which the initial hash needs in
/// order and the test vectors are easier to read with.
fn concat(parts : Array[BytesView]) -> Bytes {
  let out : Array[Byte] = []
  for part in parts {
    for i in 0..<part.length() {
      out.push(part[i])
    }
  }
  Bytes::from_array(out)
}

///|
/// `LE32(len) || input` — the first thing H' does to its argument.
fn with_length_prefix(len : Int32, input : BytesView) -> Bytes {
  concat([le32(len), input])
}

///|
/// The variable-length hash H', RFC 9106 §3.3.
///
/// BLAKE2b is only defined for outputs up to 64 bytes, but Argon2 needs 1024
/// whenever it seeds a block, so the short case is BLAKE2b itself and the long
/// case is a chain: each round hashes the previous 64-byte digest and appends
/// its first 32 bytes, and the last round widens to whatever is still missing.
/// Every block seed and the final tag go through here, so its exact shape is
/// part of the standard rather than an implementation choice.
fn h_prime(input : BytesView, len : Int32) -> Bytes {
  let seed = with_length_prefix(len, input)
  if len <= 64 {
    return @blake2.hash(seed, kind=@blake2.Blake2b, len~)
  }
  // Two 64-byte digests are consumed per 64 bytes of output, so the number of
  // full-length rounds is `ceil(len / 32) - 2` and the remainder is what the
  // final, shorter hash has to cover.
  let rounds = (len + 31) / 32 - 2
  let out : Array[Byte] = []
  let mut v = @blake2.hash(seed, kind=@blake2.Blake2b, len=64)
  for round in 0..<rounds {
    if round > 0 {
      v = @blake2.hash(v, kind=@blake2.Blake2b, len=64)
    }
    for i in 0..<32 {
      out.push(v[i])
    }
  }
  let tail = @blake2.hash(v, kind=@blake2.Blake2b, len=len - 32 * rounds)
  for i in 0..<tail.length() {
    out.push(tail[i])
  }
  Bytes::from_array(out)
}

///|
/// The 1024-byte block that seeds one lane of the memory, RFC 9106 §3.2 steps 3
/// and 4: `H'(H_0 || LE32(column) || LE32(lane), 1024)`.
fn seed_block(h0 : BytesView, column : Int32, lane : Int32) -> Bytes {
  h_prime(concat([h0, le32(column), le32(lane)]), 1024)
}

///|
/// The two scratch blocks the compression function needs, allocated once.
///
/// They are passed in rather than made per block because a real derivation
/// calls the compression function hundreds of thousands of times, and two
/// allocations of a kilobyte each would cost more than the arithmetic does.
priv struct Scratch {
  ///
  /// `X XOR Y`, then the permutation applied to it in place.
  mixed : FixedArray[UInt64]
  ///
  /// `X XOR Y` — or `X XOR Y XOR old` — held back so the result can be folded
  /// into it once the permutation has run.
  held : FixedArray[UInt64]
}

///|
/// `a + b + 2 * low32(a) * low32(b)`, the multiplication that makes Argon2's
/// permutation BLAKE2's rather than a plain ARX round.
fn blamka(a : UInt64, b : UInt64) -> UInt64 {
  let low = (a & 0xFFFF_FFFFUL) * (b & 0xFFFF_FFFFUL)
  a + b + (low << 1)
}

///|
/// Rotate right, which for these widths is what BLAKE2's sigma schedule uses.
fn rotr64(x : UInt64, n : Int32) -> UInt64 {
  (x >> n) | (x << (64 - n))
}

///|
/// One BLAKE2b G function without a message word, on four words of `v`.
fn gb(
  v : FixedArray[UInt64],
  a : Int32,
  b : Int32,
  c : Int32,
  d : Int32,
) -> Unit {
  v[a] = blamka(v[a], v[b])
  v[d] = rotr64(v[d] ^ v[a], 32)
  v[c] = blamka(v[c], v[d])
  v[b] = rotr64(v[b] ^ v[c], 24)
  v[a] = blamka(v[a], v[b])
  v[d] = rotr64(v[d] ^ v[a], 16)
  v[c] = blamka(v[c], v[d])
  v[b] = rotr64(v[b] ^ v[c], 63)
}

///|
/// The permutation P applied to sixteen consecutive words starting at `base` —
/// the row pass over the 8×16 matrix a block is.
fn round_rows(v : FixedArray[UInt64], base : Int32) -> Unit {
  gb(v, base, base + 4, base + 8, base + 12)
  gb(v, base + 1, base + 5, base + 9, base + 13)
  gb(v, base + 2, base + 6, base + 10, base + 14)
  gb(v, base + 3, base + 7, base + 11, base + 15)
  gb(v, base, base + 5, base + 10, base + 15)
  gb(v, base + 1, base + 6, base + 11, base + 12)
  gb(v, base + 2, base + 7, base + 8, base + 13)
  gb(v, base + 3, base + 4, base + 9, base + 14)
}

///|
/// The word of the 8×16 matrix that position `p` of column `i` refers to. A
/// block read as eight rows of sixteen words, taken a pair of words at a time
/// down the rows, is the sixteen-word column the permutation runs over.
fn column_word(i : Int32, p : Int32) -> Int32 {
  2 * i + 16 * (p >> 1) + (p & 1)
}

///|
/// The permutation P applied to one column of the 8×16 matrix.
fn round_column(v : FixedArray[UInt64], i : Int32) -> Unit {
  gb(
    v,
    column_word(i, 0),
    column_word(i, 4),
    column_word(i, 8),
    column_word(i, 12),
  )
  gb(
    v,
    column_word(i, 1),
    column_word(i, 5),
    column_word(i, 9),
    column_word(i, 13),
  )
  gb(
    v,
    column_word(i, 2),
    column_word(i, 6),
    column_word(i, 10),
    column_word(i, 14),
  )
  gb(
    v,
    column_word(i, 3),
    column_word(i, 7),
    column_word(i, 11),
    column_word(i, 15),
  )
  gb(
    v,
    column_word(i, 0),
    column_word(i, 5),
    column_word(i, 10),
    column_word(i, 15),
  )
  gb(
    v,
    column_word(i, 1),
    column_word(i, 6),
    column_word(i, 11),
    column_word(i, 12),
  )
  gb(
    v,
    column_word(i, 2),
    column_word(i, 7),
    column_word(i, 8),
    column_word(i, 13),
  )
  gb(
    v,
    column_word(i, 3),
    column_word(i, 4),
    column_word(i, 9),
    column_word(i, 14),
  )
}

///|
/// The compression function G, RFC 9106 §3.5, written straight into the block
/// matrix.
///
/// `prev`, `reference` and `target` are block indices; `target` may be the same
/// block as `reference`, which happens when the data-independent addressing
/// hashes an address block into itself. That is safe because the two inputs are
/// read into scratch before anything is written.
///
/// `with_xor` is the version 19 rule: after the first pass a block is mixed
/// into what is already there instead of replacing it, so no information from
/// earlier passes is thrown away.
fn compress(
  mem : FixedArray[UInt64],
  prev : Int32,
  reference : Int32,
  target : Int32,
  with_xor : Bool,
  scratch : Scratch,
) -> Unit {
  let p = prev * words_per_block
  let r = reference * words_per_block
  let t = target * words_per_block
  let mixed = scratch.mixed
  let held = scratch.held
  for i in 0..<words_per_block {
    let x = mem[p + i] ^ mem[r + i]
    mixed[i] = x
    held[i] = if with_xor { x ^ mem[t + i] } else { x }
  }
  for row in 0..<8 {
    round_rows(mixed, row * 16)
  }
  for column in 0..<8 {
    round_column(mixed, column)
  }
  for i in 0..<words_per_block {
    mem[t + i] = mixed[i] ^ held[i]
  }
}

///|
/// Copy a 1024-byte block into the matrix as 128 little-endian words.
fn put_block(
  mem : FixedArray[UInt64],
  index : Int32,
  bytes : BytesView,
) -> Unit {
  let base = index * words_per_block
  for i in 0..<words_per_block {
    let mut w = 0UL
    for b in 0..<8 {
      w = w | (bytes[i * 8 + b].to_uint64() << (b * 8))
    }
    mem[base + i] = w
  }
}

///|
/// Read 128 words back out as the 1024 bytes H' wants.
fn words_to_bytes(words : FixedArray[UInt64]) -> Bytes {
  let out : Array[Byte] = []
  for i in 0..<words.length() {
    for b in 0..<8 {
      out.push(((words[i] >> (b * 8)) & 0xFFUL).to_byte())
    }
  }
  Bytes::from_array(out)
}

///|
/// Reset the block the data-independent addressing hashes: the six fields that
/// identify this segment, and a counter that climbs once per address block.
fn set_address_input(
  mem : FixedArray[UInt64],
  at : Int32,
  pass : Int32,
  lane : Int32,
  slice : Int32,
  blocks : Int32,
  passes : Int32,
  kind : Kind,
) -> Unit {
  let base = at * words_per_block
  for i in 0..<words_per_block {
    mem[base + i] = 0UL
  }
  mem[base] = pass.to_uint64()
  mem[base + 1] = lane.to_uint64()
  mem[base + 2] = slice.to_uint64()
  mem[base + 3] = blocks.to_uint64()
  mem[base + 4] = passes.to_uint64()
  mem[base + 5] = kind.code().to_uint64()
}

///|
/// Produce the next block of 128 addresses for the data-independent variants.
///
/// Two compressions against an all-zero block turn the counter block into
/// something with the avalanche properties of the permutation, which is where
/// the randomness that replaces "read the last block written" comes from.
fn next_addresses(
  mem : FixedArray[UInt64],
  zero_at : Int32,
  input_at : Int32,
  address_at : Int32,
  scratch : Scratch,
) -> Unit {
  let counter = input_at * words_per_block + 6
  mem[counter] = mem[counter] + 1UL
  compress(mem, zero_at, input_at, address_at, false, scratch)
  compress(mem, zero_at, address_at, address_at, false, scratch)
}

///|
/// The 64-byte initial hash H_0, RFC 9106 §3.2 step 1.
///
/// Every parameter goes in, including the lengths of the four variable-length
/// inputs, so a password that happens to equal a salt cannot produce the same
/// digest as a salt that equals a password. An absent secret or associated data
/// still contributes its length field — a zero — which is what keeps the
/// encoding unambiguous.
fn initial_digest(
  password : BytesView,
  salt : BytesView,
  secret : BytesView,
  ad : BytesView,
  kind : Kind,
  params : Params,
  len : Int32,
) -> Bytes {
  let h = @blake2.Hasher::new(kind=@blake2.Blake2b, len=64)
  h.write(le32(params.lanes))
  h.write(le32(len))
  h.write(le32(params.memory))
  h.write(le32(params.passes))
  h.write(le32(version))
  h.write(le32(kind.code()))
  let blobs : Array[BytesView] = [password, salt, secret, ad]
  for blob in blobs {
    h.write(le32(blob.length()))
    h.write(blob)
  }
  h.finish()
}

///|
/// Derive a key with Argon2.
///
/// `secret` is a pepper: a value kept outside the database, so that a stolen
/// table is useless without it. `ad` is associated data, which binds the output
/// to a context such as a user name. Both are optional and both change the
/// result, which is why the RFC gives them their own length fields.
///
/// `len` is the tag length; anything from 4 bytes up is allowed, and the default
/// matches what a password hash is normally stored as. `params` sets the cost,
/// and `kind` picks the variant — leave both alone unless you know why not.
///
/// ```moonbit nocheck
/// let tag = @argon2.key(
///   password,
///   salt,
///   kind=@argon2.Argon2id,
///   params=@argon2.interactive,
/// )
/// ```
pub fn key(
  password : BytesView,
  salt : BytesView,
  secret~ : BytesView = b"",
  ad~ : BytesView = b"",
  kind~ : Kind = Argon2id,
  params~ : Params = interactive,
  len~ : Int32 = 32,
) -> Bytes {
  guard len >= 4 else {
    abort("argon2: tag length must be at least 4 bytes, not \{len}")
  }
  let cost = Params::new(
    memory=params.memory,
    passes=params.passes,
    lanes=params.lanes,
  )
  let h0 = initial_digest(password, salt, secret, ad, kind, cost, len)
  // The memory has to be a whole number of blocks per lane, and each lane a
  // whole number of slices, so the requested size is rounded down here and the
  // rounding is part of what the initial hash above committed to.
  let blocks = 4 * cost.lanes * (cost.memory / (4 * cost.lanes))
  let column_count = blocks / cost.lanes
  let segment = column_count / sync_points
  // Three blocks past the matrix: an all-zero block, the counter block, and the
  // address block. Keeping them in the same array lets the compression function
  // serve all of them instead of needing a second code path over plain arrays.
  let zero_at = blocks
  let input_at = blocks + 1
  let address_at = blocks + 2
  let mem : FixedArray[UInt64] = FixedArray::make(
    (blocks + 3) * words_per_block,
    0UL,
  )
  let scratch : Scratch = {
    mixed: FixedArray::make(words_per_block, 0UL),
    held: FixedArray::make(words_per_block, 0UL),
  }
  for lane in 0..<cost.lanes {
    for column in 0..<2 {
      put_block(mem, lane * column_count + column, seed_block(h0, column, lane))
    }
  }
  for pass in 0..<cost.passes {
    for slice in 0..<sync_points {
      for lane in 0..<cost.lanes {
        let independent = match kind {
          Argon2i => true
          Argon2d => false
          Argon2id => pass == 0 && slice < 2
        }
        if independent {
          set_address_input(
            mem,
            input_at,
            pass,
            lane,
            slice,
            blocks,
            cost.passes,
            kind,
          )
        }
        // The first two blocks of the first slice are already seeded, so the
        // loop starts past them and the address counter has already been
        // consumed once by the time it does.
        let start = if pass == 0 && slice == 0 { 2 } else { 0 }
        if pass == 0 && slice == 0 && independent {
          next_addresses(mem, zero_at, input_at, address_at, scratch)
        }
        let mut current = slice * segment + start
        let mut previous = if current == 0 {
          column_count - 1
        } else {
          current - 1
        }
        for i in start..<segment {
          // The first block of a lane in a later pass follows the lane's last
          // block, which the arithmetic above already arranged; the second is
          // the only place the index has to be pulled back.
          if current == 1 {
            previous = 0
          }
          let pseudo = if independent {
            if i % 128 == 0 {
              next_addresses(mem, zero_at, input_at, address_at, scratch)
            }
            mem[address_at * words_per_block + i % 128]
          } else {
            mem[(lane * column_count + previous) * words_per_block]
          }
          // The high half picks the lane. In the first slice of the first pass
          // nothing else has been written that could be referenced, so the lane
          // is forced to our own.
          let reference_lane = if pass == 0 && slice == 0 {
            lane
          } else {
            ((pseudo >> 32) % cost.lanes.to_uint64()).to_int()
          }
          // How far back the reference may reach: everything already written in
          // this lane this pass, plus the whole of every other lane except the
          // slice currently in flight.
          let reach : Int32 = if pass == 0 {
            if slice == 0 {
              i - 1
            } else if reference_lane == lane {
              slice * segment + i - 1
            } else {
              slice * segment + (if i == 0 { -1 } else { 0 })
            }
          } else if reference_lane == lane {
            column_count - segment + i - 1
          } else {
            column_count - segment + (if i == 0 { -1 } else { 0 })
          }
          // Squaring J_1 and scaling by the reach is the non-uniform mapping of
          // §3.4.2: recent blocks are more likely to be referenced than old
          // ones, which is what keeps the memory from being sparse.
          let low = pseudo & 0xFFFF_FFFFUL
          let scaled = (reach.to_uint64() * ((low * low) >> 32)) >> 32
          let back = reach.to_uint64() - 1UL - scaled
          // After the first pass the reference may also come from the part of
          // this lane not yet overwritten, so the window rolls forward.
          let window : Int32 = if pass == 0 || slice == sync_points - 1 {
            0
          } else {
            (slice + 1) * segment
          }
          let width = column_count.to_uint64()
          let reference = ((window.to_uint64() + back) % width).to_int()
          compress(
            mem,
            lane * column_count + previous,
            reference_lane * column_count + reference,
            lane * column_count + current,
            pass != 0,
            scratch,
          )
          current = current + 1
          previous = previous + 1
        }
      }
    }
  }
  // The tag is H' of the XOR of the last column — every lane's final block
  // folded together, so that a lane cannot be computed in isolation.
  let acc : FixedArray[UInt64] = FixedArray::make(words_per_block, 0UL)
  for i in 0..<words_per_block {
    acc[i] = mem[(column_count - 1) * words_per_block + i]
  }
  for lane in 1..<cost.lanes {
    let base = (lane * column_count + column_count - 1) * words_per_block
    for i in 0..<words_per_block {
      acc[i] = acc[i] ^ mem[base + i]
    }
  }
  let tag = h_prime(words_to_bytes(acc), len)
  for i in 0..<mem.length() {
    mem[i] = 0UL
  }
  for i in 0..<acc.length() {
    acc[i] = 0UL
  }
  tag
}
