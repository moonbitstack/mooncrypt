// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The 32-byte address every hash in SLH-DSA is tweaked with (FIPS 205
/// §2.7.3): an address type, a position in the hypertree, and three fields
/// whose meaning the type decides.
///
/// It is the mechanism that makes the scheme sound: two calls that would
/// otherwise hash the same input — one chain step in two different trees — take
/// different addresses, so a node value cannot be lifted from where it was
/// computed to where it would help a forger.
///
/// The layout is four bytes of layer, twelve of tree, four of type, then twelve
/// that the type reads as key pair, chain and hash — or as tree height and
/// tree index.
let adrs_size : Int32 = 32

///|
/// A WOTS+ hash chain step.
let adrs_wots_hash : Int32 = 0

///|
/// A WOTS+ public key, the fold of its chains.
let adrs_wots_pk : Int32 = 1

///|
/// A node of a Merkle tree.
let adrs_tree : Int32 = 2

///|
/// A FORS tree.
let adrs_fors_tree : Int32 = 3

///|
/// The FORS public key, the fold of its trees' roots.
let adrs_fors_roots : Int32 = 4

///|
/// A WOTS+ key-generation `PRF`.
let adrs_wots_prf : Int32 = 5

///|
/// A FORS key-generation `PRF`.
let adrs_fors_prf : Int32 = 6

///|
fn adrs_new() -> FixedArray[Byte] {
  FixedArray::make(adrs_size, b'\x00')
}

///|
fn adrs_copy(a : FixedArray[Byte]) -> FixedArray[Byte] {
  let out = adrs_new()
  for i in 0..<adrs_size {
    out[i] = a[i]
  }
  out
}

///|
/// A four-byte field, big-endian.
fn adrs_set(a : FixedArray[Byte], at : Int32, value : Int32) -> Unit {
  a[at] = ((value >> 24) & 0xFF).to_byte()
  a[at + 1] = ((value >> 16) & 0xFF).to_byte()
  a[at + 2] = ((value >> 8) & 0xFF).to_byte()
  a[at + 3] = (value & 0xFF).to_byte()
}

///|
/// Set the type and clear the twelve bytes the type interprets, which is what
/// FIPS 205 §4.2 requires of every type change: without it the key pair, chain
/// and hash fields of the previous type would leak into the next one's address,
/// and two different steps could hash under the same one.
fn adrs_set_type(a : FixedArray[Byte], value : Int32) -> Unit {
  adrs_set(a, 16, value)
  for i in 20..<adrs_size {
    a[i] = b'\x00'
  }
}

///|
/// The key pair the address currently names, which has to be read back when a
/// type change clears it.
fn adrs_get_key_pair(a : FixedArray[Byte]) -> Int32 {
  (a[20].to_int() << 24) |
  (a[21].to_int() << 16) |
  (a[22].to_int() << 8) |
  a[23].to_int()
}

///|
fn adrs_set_layer(a : FixedArray[Byte], value : Int32) -> Unit {
  adrs_set(a, 0, value)
}

///|
/// The tree position: the low eight of its twelve bytes, which is where a
/// number that wide keeps its value.
fn adrs_set_tree(a : FixedArray[Byte], value : UInt64) -> Unit {
  for i in 0..<8 {
    a[8 + i] = ((value >> (56 - 8 * i)) & 0xFFUL).to_int().to_byte()
  }
}

///|
fn adrs_set_key_pair(a : FixedArray[Byte], value : Int32) -> Unit {
  adrs_set(a, 20, value)
}

///|
fn adrs_set_chain(a : FixedArray[Byte], value : Int32) -> Unit {
  adrs_set(a, 24, value)
}

///|
fn adrs_set_hash(a : FixedArray[Byte], value : Int32) -> Unit {
  adrs_set(a, 28, value)
}

///|
fn adrs_set_tree_height(a : FixedArray[Byte], value : Int32) -> Unit {
  adrs_set(a, 24, value)
}

///|
fn adrs_set_tree_index(a : FixedArray[Byte], value : Int32) -> Unit {
  adrs_set(a, 28, value)
}

///|
/// The address as the digest state sees it. Views cannot point into a mutable
/// array, so this copy is the one place the address leaves the array it is
/// edited in.
fn adrs_bytes(a : FixedArray[Byte]) -> Bytes {
  let out = Array::make(adrs_size, b'\x00')
  for i in 0..<adrs_size {
    out[i] = a[i]
  }
  Bytes::from_array(out)
}
