// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0
//
// The hypertree and the scheme on top of it: FIPS 205 Algorithms 17-20 and the
// signing and verification of 12-14. A layer signs the root of the layer below
// with one XMSS key, so the top layer is one signature over the whole tree and
// a verifier walks down `d` of them.

///|
/// `xmss_sign` (FIPS 205 Algorithm 17): a WOTS+ signature over the message and
/// the path from the leaf to the root of its tree.
fn xmss_sign(
  hs : Hashing,
  msg : BytesView,
  sk_seed : BytesView,
  pk_seed : BytesView,
  idx : Int32,
  adrs : FixedArray[Byte],
  hp : Int32,
) -> Bytes {
  let n = hs.n
  let wots_adrs = adrs_copy(adrs)
  adrs_set_type(wots_adrs, adrs_wots_hash)
  adrs_set_key_pair(wots_adrs, idx)
  let sig = wots_sign(hs, msg, sk_seed, pk_seed, wots_adrs)
  let auth : Array[Bytes] = []
  for _ in 0..<hp {
    auth.push(Bytes::makei(n, fn(_) { b'\x00' }))
  }
  ignore(treehash(hs, sk_seed, pk_seed, adrs, 0, hp, Some(auth), idx))
  let parts : Array[BytesView] = [sig]
  for node in auth {
    parts.push(node)
  }
  concat(parts)
}

///|
/// `xmss_pkFromSig` (FIPS 205 Algorithm 18): the root the signature implies.
fn xmss_pk_from_sig(
  hs : Hashing,
  idx : Int32,
  sig : BytesView,
  msg : BytesView,
  pk_seed : BytesView,
  adrs : FixedArray[Byte],
  hp : Int32,
) -> Bytes {
  let n = hs.n
  let len = len_of(hs)
  let wots_adrs = adrs_copy(adrs)
  adrs_set_type(wots_adrs, adrs_wots_hash)
  adrs_set_key_pair(wots_adrs, idx)
  let mut node = wots_pk_from_sig(hs, sig[0:len * n], msg, pk_seed, wots_adrs)
  for height in 0..<hp {
    let sibling = sig[len * n + height * n:len * n + (height + 1) * n]
    let node_adrs = adrs_copy(adrs)
    adrs_set_type(node_adrs, adrs_tree)
    adrs_set_tree_height(node_adrs, height + 1)
    adrs_set_tree_index(node_adrs, idx >> (height + 1))
    node = if ((idx >> height) & 1) == 0 {
      h(hs, pk_seed, node_adrs, node[:], sibling)
    } else {
      h(hs, pk_seed, node_adrs, sibling, node[:])
    }
  }
  node
}

///|
/// The root of the top tree, which is the public key: one tree of height
/// `h / d` over key pairs that are themselves roots of the layer below.
fn compute_root(
  kind : Kind,
  hs : Hashing,
  sk_seed : BytesView,
  pk_seed : BytesView,
) -> Bytes {
  let adrs = adrs_new()
  adrs_set_layer(adrs, kind.d() - 1)
  adrs_set_type(adrs, adrs_tree)
  treehash(hs, sk_seed, pk_seed, adrs, 0, kind.hp(), None, 0)
}

///|
/// `ht_sign` (FIPS 205 Algorithm 19): one XMSS signature per layer, the top
/// one over the FORS root.
fn ht_sign(
  hs : Hashing,
  msg : BytesView,
  sk_seed : BytesView,
  pk_seed : BytesView,
  idx_tree : UInt64,
  idx_leaf : Int32,
  kind : Kind,
) -> Bytes {
  let hp = kind.hp()
  let mask = (1 << hp) - 1
  let adrs = adrs_new()
  adrs_set_tree(adrs, idx_tree)
  let sig = xmss_sign(hs, msg, sk_seed, pk_seed, idx_leaf, adrs, hp)
  let parts : Array[BytesView] = [sig]
  let mut root = xmss_pk_from_sig(hs, idx_leaf, sig[:], msg, pk_seed, adrs, hp)
  let mut tree = idx_tree
  for layer in 1..<kind.d() {
    let leaf = (tree & mask.to_uint64()).to_int()
    tree = tree >> hp
    let layer_adrs = adrs_new()
    adrs_set_layer(layer_adrs, layer)
    adrs_set_tree(layer_adrs, tree)
    let sig = xmss_sign(hs, root[:], sk_seed, pk_seed, leaf, layer_adrs, hp)
    root = xmss_pk_from_sig(hs, leaf, sig[:], root[:], pk_seed, layer_adrs, hp)
    parts.push(sig)
  }
  concat(parts)
}

///|
/// `ht_verify` (FIPS 205 Algorithm 20): walk the layers back up to a root.
fn ht_verify(
  hs : Hashing,
  msg : BytesView,
  sig : BytesView,
  pk_seed : BytesView,
  idx_tree : UInt64,
  idx_leaf : Int32,
  kind : Kind,
) -> Bytes {
  let hp = kind.hp()
  let mask = (1 << hp) - 1
  let size = (hp + len_of(hs)) * hs.n
  let adrs = adrs_new()
  adrs_set_tree(adrs, idx_tree)
  let mut node = xmss_pk_from_sig(
    hs,
    idx_leaf,
    sig[0:size],
    msg,
    pk_seed,
    adrs,
    hp,
  )
  let mut tree = idx_tree
  for layer in 1..<kind.d() {
    let leaf = (tree & mask.to_uint64()).to_int()
    tree = tree >> hp
    let layer_adrs = adrs_new()
    adrs_set_layer(layer_adrs, layer)
    adrs_set_tree(layer_adrs, tree)
    node = xmss_pk_from_sig(
      hs,
      leaf,
      sig[layer * size:(layer + 1) * size],
      node[:],
      pk_seed,
      layer_adrs,
      hp,
    )
  }
  node
}

///|
/// A big-endian integer of up to eight bytes, which is how `toInt` reads the
/// digest.
fn be_int(b : BytesView) -> UInt64 {
  let mut v = 0UL
  for i in 0..<b.length() {
    v = (v << 8) | b[i].to_uint64()
  }
  v
}

///|
/// The three pieces of the message digest (FIPS 205 Algorithm 19, lines 6-10):
/// the bits FORS signs, the tree to sign in, and the key pair within that tree.
///
/// Each is a whole number of bytes read big-endian and then reduced modulo the
/// number of bits it stands for, so `h - h'` of 54 bits takes seven bytes and
/// keeps the low 54.
fn digest_parts(kind : Kind, digest : BytesView) -> (Bytes, UInt64, Int32) {
  let md_len = (kind.k() * kind.a() + 7) / 8
  let tree_bits = kind.h() - kind.hp()
  let tree_bytes = (tree_bits + 7) / 8
  let leaf_bytes = (kind.hp() + 7) / 8
  let md = digest[0:md_len].to_owned()
  let mut tree = be_int(digest[md_len:md_len + tree_bytes])
  if tree_bits < 64 {
    tree = tree & ((1UL << tree_bits) - 1UL)
  }
  let mut leaf = be_int(
    digest[md_len + tree_bytes:md_len + tree_bytes + leaf_bytes],
  ).to_int()
  if kind.hp() < 64 {
    leaf = leaf & ((1 << kind.hp()) - 1)
  }
  (md, tree, leaf)
}

///|
/// The signature of FIPS 205 Algorithm 12.
///
/// `opt_rand` is the hedged half: the standard's deterministic variant sets it
/// to `PK.seed`, and a random one draws it fresh, which makes two signatures
/// over the same message differ without weakening either.
fn sign_inner(key : PrivateKey, m : Bytes, opt_rand : Bytes?) -> Bytes {
  let kind = key.kind
  let n = kind.n()
  let hs = hashing(kind)
  let raw = key.raw
  let sk_seed = raw[0:n]
  let sk_prf = raw[n:2 * n]
  let pk_seed = raw[2 * n:3 * n]
  let pk_root = raw[3 * n:4 * n]
  let rand = match opt_rand {
    Some(r) => r
    None => pk_seed.to_owned()
  }
  let r = prf_msg(hs, sk_prf, rand[:], m[:])
  let digest = h_msg(hs, r[:], pk_seed, pk_root, m[:])
  let (md, idx_tree, idx_leaf) = digest_parts(kind, digest[:])
  // The FORS key sits in the leftmost layer, in the tree the digest names, as
  // the key pair the digest names.
  let fors_adrs = adrs_new()
  adrs_set_tree(fors_adrs, idx_tree)
  adrs_set_type(fors_adrs, adrs_fors_tree)
  adrs_set_key_pair(fors_adrs, idx_leaf)
  let fors = fors_sign(
    hs,
    md[:],
    sk_seed,
    pk_seed,
    fors_adrs,
    kind.a(),
    kind.k(),
  )
  let fors_root = fors_pk_from_sig(
    hs,
    fors[:],
    md[:],
    pk_seed,
    fors_adrs,
    kind.a(),
    kind.k(),
  )
  let ht = ht_sign(hs, fors_root[:], sk_seed, pk_seed, idx_tree, idx_leaf, kind)
  concat([r, fors, ht])
}

///|
/// The verification of FIPS 205 Algorithm 14.
fn verify_inner(key : PublicKey, m : Bytes, sig : BytesView) -> Bool {
  let kind = key.kind
  let n = kind.n()
  let hs = hashing(kind)
  let pk_seed = key.raw[0:n]
  let pk_root = key.raw[n:2 * n]
  let r = sig[0:n]
  let digest = h_msg(hs, r, pk_seed, pk_root, m[:])
  let (md, idx_tree, idx_leaf) = digest_parts(kind, digest[:])
  let fors_adrs = adrs_new()
  adrs_set_tree(fors_adrs, idx_tree)
  adrs_set_type(fors_adrs, adrs_fors_tree)
  adrs_set_key_pair(fors_adrs, idx_leaf)
  let fors_size = kind.k() * (kind.a() + 1) * n
  let fors_root = fors_pk_from_sig(
    hs,
    sig[n:n + fors_size],
    md[:],
    pk_seed,
    fors_adrs,
    kind.a(),
    kind.k(),
  )
  let root = ht_verify(
    hs,
    fors_root[:],
    sig[n + fors_size:],
    pk_seed,
    idx_tree,
    idx_leaf,
    kind,
  )
  @spec.eq(root, pk_root)
}
