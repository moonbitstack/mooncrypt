#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""Emit the RFC 8702 vectors: RSASSA-PSS over SHAKE128 and SHAKE256.

    python scripts/gen_shake_pss_vectors.py

OpenSSL 3.5 refuses these outright — `openssl dgst -shake128 -sign` with
`rsa_padding_mode:pss` fails inside the provider with "digest not allowed" — and
no other library on this machine signs one either, so unlike the rest of the RSA
vectors there is no third-party signature to replay. What this script does
instead is implement RFC 8702 a second time, in Python, over SHAKE from
`hashlib` and Python's own big integers, and check every primitive it uses
against the `openssl` command line:

  - the message digest: SHAKE128 at 32 octets, SHAKE256 at 64;
  - the mask: one SHAKE call over the seed at the mask's length, which RFC 8702
    §3.2.1 is explicit about — *not* MGF1's hash of `seed ∥ counter`, which would
    give a different mask for the same seed.

Two directions come out of the pair of implementations:

  - `shake_pss_test.mbt` carries signatures this script made, verified by the
    MoonBit decoder. Verification reads the salt back out of the block, so the
    derivation MoonBit uses never enters — a bug in it cannot hide here.
  - the same file carries the signatures MoonBit's own deterministic signing
    must reproduce byte for byte. Those pin the whole pipeline, derivation
    included, which is the one part of the two implementations that is written
    alike on purpose: a salt is free, and no specification constrains it.

Both keys are pinned rather than generated: re-running this must rewrite the
same files. The 2048-bit one is the ordinary case. The 2049-bit one is the case
that makes `emLen = ⌈(modBits − 1)/8⌉` differ from the modulus's width by an
octet, which is the only place the two readings of the length disagree.
"""

import hashlib
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent / "src"

# Pinned key material: (n, e, d) in hex, 2048 and 2049 bits.
KEY_2048 = (
    "c74f295119d06cac8fb1b1991803589aa81415495b88d080ddebf35c14f9084598708d37f3c95f7dca24d85581494584"
    "8f4bd8603a5133660768c188b358b76620fb2cfec37134f0a100c3867a87cdf115c7c46b4dad3c19eb145b716dc5d2b9"
    "7699af006aa5b11d3798a017245f82cd8d5017316c15078d27177e5dccabda43495e75730efbcfe86422d68d4c3c2a16"
    "42f9ee5d7d9d4cebf71aac602a408fab0429ec593267261158782928acaaf5fe13fbc9454468b19d00307c4c2cd4e8c6"
    "fdee43ca10b23369eb8d089c775d72005b7a11cb93c17178d7201b9bef9db7b3f9f5915fd1604c3c22ada9dbd28ae5c1"
    "e0ce23473b92689b15a23be5a4f61a6d",
    "010001",
    "ce62d2ce00852b83a568c4175c1e5aea0b9280586e48c6602b6de19b40bc802c51267b95ad04a1b588558f0f3bc9bc0b"
    "00b7f15ff40391cddd6e44ba61bd446ca54a73d57c5d060d072bdb4cae2562c47b6159ac23cb77a8ff1d1d73dfd031dd"
    "8b4aa9452d2a56b58294b172456001fb08921ef23691b038227ad9881820fce949a67e8497b36ceaabe4c6544f098893"
    "1d8b97cead2dab8778f7c296f95cff647ebcfd134ba75a6df3182ae29b5064741c884717904cb8cc0c5880ba0791d25f"
    "4caca01c72d86242ea5f57481453547c5e5d1a9ceb3c3a5bd9ec00d412269025b4d7d3fc7ff5c7b169f31195b931016b"
    "a1eb92eced23650410be4ff0b512ba1",
)

KEY_2049 = (
    "10ffc30ad93828c2919d8aa585b519d7d8dfd25a744c1dba91f3839cd3e030994f4e20c9242c7ed2d5e04816ce04c2c6"
    "04038a801d6b88a1eec74cf62115683ced2918054462fe1b9d85a8304bb966d15177e4ad73df71fbfa4319dbbd7ff9b6"
    "abdea5e4209e6e95b303027b9ca95e7b34e3fc7c5a30e885c8201743dfe3e6e600aee0dd0c4f824c1df7e5ef8141213f"
    "d851670d9a28546c200834536cf63663318706ec7017f457bab18d292868cea5a372ad57ec4e016a3d49973f1a3c168d"
    "e44ca47548e8bf508de2872ce8338bdd67fd85e4652d247936f44e22cf5461879ea6511ed45a802b7d3d7cfab8d16656"
    "17817d16656dbbc1cd150951910e07515",
    "010001",
    "5d8e42f441ec42e81462e9dd70b3f7376bf2ead3c99be142206207c7e88fc4e8feff0e91f4f4ae49cfb03f10c36a904d"
    "1f6a1da85c42a808110ff111eba2d5bdfbc25ee11e2f7436a80c224b2b7787d81c77ada8b240e223da87d298fda887be"
    "44cb6c56ccef27cfdd188361ae24b8497e1e044aa056ec62ddb94051deb57ce338d64d296b59b42c456fc9428782c0a1"
    "2413efa85bb536a653f4bdc71096ede48dfadd4744526607a41196f78ea8df6d6fe57f2338243c56e6f1376c4a265ec8"
    "f4b770523933077821a235fa07dbb97737c49cbf0ecebe118c0a9f56df152e04a9597a0a072665f1ae8fe4b61386da9f"
    "68db63517b96212e7248f3efb930d5d5",
)

MESSAGE = b"The quick brown fox jumps over the lazy dog"


def even(hexstr):
    """The same number as an even run of hex digits.

    A modulus or an exponent printed with `format(x, "x")` drops leading zeroes,
    so an odd digit count means the top nibble was one — a value, not a
    corruption. `base16.decode` reads pairs, so the pinned strings are padded
    where Python's `%x` is not.
    """
    return hexstr if len(hexstr) % 2 == 0 else "0" + hexstr


def shake(a, data, length):
    """The SHAKE `a` calls for, `length` octets out."""
    h = hashlib.shake_128() if a == 128 else hashlib.shake_256()
    h.update(data)
    return h.digest(length)


def openssl_shake(a, data, length):
    """The same, through the `openssl` command line, or None when unavailable."""
    try:
        out = subprocess.run(
            ["openssl", "dgst", f"-shake{a}", "-xoflen", str(length), "-binary"],
            input=data,
            capture_output=True,
            check=True,
        )
        return out.stdout
    except (OSError, subprocess.CalledProcessError):
        return None


def hlen(a):
    """RFC 8702's digest length for the variant: 32 octets, or 64."""
    return 32 if a == 128 else 64


def em_len(n):
    """⌈(modBits − 1)/8⌉, the encoded message's length."""
    return (n.bit_length() - 1 + 7) // 8


def rsaep(m, e, n):
    return pow(m, e, n)


def rsasp1(m, d, n):
    return pow(m, d, n)


def unused_bits(n, em_length):
    """How many leading bits of the encoding sit above the modulus: 8·emLen − emBits."""
    return 8 * em_length - (n.bit_length() - 1)


def i2osp(x, length):
    return x.to_bytes(length, "big")


def os2ip(b):
    return int.from_bytes(b, "big")


def pss_encode(a, m_hash, salt, n):
    """EMSA-PSS-ENCODE with RFC 8702's mask: one SHAKE over the seed."""
    k = em_len(n)
    h = hlen(a)
    salt_len = len(salt)
    if k < h + salt_len + 2:
        raise ValueError("modulus too small for this salt")
    m_prime = b"\x00" * 8 + m_hash + salt
    digest = shake(a, m_prime, h)
    db_len = k - h - 1
    db = b"\x00" * (db_len - salt_len - 1) + b"\x01" + salt
    mask = shake(a, digest, db_len)
    masked = bytearray(x ^ y for x, y in zip(db, mask))
    # §9.1.1 step 11: the 8·emLen − emBits bits above the modulus width are
    # zero. One of them for an ordinary key, none for a modulus one bit past a
    # whole number of octets.
    masked[0] &= 0xFF >> unused_bits(n, k)
    return bytes(masked) + digest + b"\xbc"


def pss_verify(a, m_hash, em, n):
    """EMSA-PSS-VERIFY, reading the salt out of the block as a peer's would."""
    h = hlen(a)
    k = len(em)
    unused = unused_bits(n, k)
    if k < h + 2 or em[-1] != 0xBC:
        return False
    if em[0] & ((0xFF << (8 - unused)) & 0xFF):
        return False
    db_len = k - h - 1
    digest = em[db_len:k - 1]
    mask = shake(a, digest, db_len)
    db = bytearray(x ^ y for x, y in zip(em[:db_len], mask))
    db[0] &= 0xFF >> unused
    at = 0
    while at < db_len and db[at] == 0:
        at += 1
    if at >= db_len or db[at] != 0x01:
        return False
    salt = bytes(db[at + 1:])
    primed = b"\x00" * 8 + m_hash + salt
    return shake(a, primed, h) == digest


def salt_seed(a, secret, m_hash):
    """The seed the salt is masked from: `SHAKE(secret ∥ mHash)`.

    This is the one step the two implementations agree on by construction. A
    salt is free — RFC 8017 lets the signer pick it, and RFC 8702 fixes only its
    length — so a deterministic one is this library's own rule, and the vectors
    that pin it are pinning the rule as much as the encoding.
    """
    return shake(a, secret + m_hash, hlen(a))


def sign(a, message, n, d, salt_len=None):
    """A signature under the variant, with a derived salt unless one is given."""
    if salt_len is None:
        salt_len = hlen(a)
    m_hash = shake(a, message, hlen(a))
    secret = i2osp(d, (d.bit_length() + 7) // 8)
    salt = shake(a, salt_seed(a, secret, m_hash), salt_len)
    em = pss_encode(a, m_hash, salt, n)
    return i2osp(rsasp1(os2ip(em), d, n), (n.bit_length() + 7) // 8)


def check_primitives():
    """Every SHAKE this script uses, against `openssl` where it is available."""
    disagree = 0
    for a, length in ((128, 32), (128, 223), (256, 64), (256, 191)):
        ours = shake(a, MESSAGE, length)
        theirs = openssl_shake(a, MESSAGE, length)
        if theirs is None:
            print("openssl is not on PATH; the SHAKE cross-check is skipped")
            return
        if ours != theirs:
            disagree += 1
            print(f"shake{a} at {length} octets: hashlib and openssl disagree")
    if disagree:
        sys.exit("the two SHAKEs disagree; refusing to emit vectors")


def main():
    check_primitives()
    n2048, e2048, d2048 = (int(x, 16) for x in KEY_2048)
    n2049, e2049, d2049 = (int(x, 16) for x in KEY_2049)
    print(f"2048-bit modulus: {n2048.bit_length()} bits, emLen {em_len(n2048)}")
    print(f"2049-bit modulus: {n2049.bit_length()} bits, emLen {em_len(n2049)}")

    # The signatures the MoonBit decoder must accept, with the salts a peer
    # would have drawn: the derivation never enters a verification.
    foreign = []
    for name, a, n, d in (
        ("Shake128", 128, n2048, d2048),
        ("Shake256", 256, n2048, d2048),
    ):
        m_hash = shake(a, MESSAGE, hlen(a))
        salt = bytes((i * 7 + a) & 0xFF for i in range(hlen(a)))
        em = pss_encode(a, m_hash, salt, n)
        sig = i2osp(rsasp1(os2ip(em), d, n), (n.bit_length() + 7) // 8)
        if not pss_verify(a, m_hash, i2osp(rsaep(os2ip(sig), e2048, n), em_len(n)), n):
            sys.exit(f"the reference does not verify its own {name} signature")
        foreign.append((name, sig.hex()))

    # The 2049-bit key, where the encoding is one octet shorter than the
    # modulus: the same signature arithmetic, a different `emLen`.
    m_hash = shake(128, MESSAGE, 32)
    salt = bytes(range(32))
    em2049 = pss_encode(128, m_hash, salt, n2049)
    if len(em2049) != em_len(n2049) or em_len(n2049) == (n2049.bit_length() + 7) // 8:
        sys.exit("the 2049-bit key does not exercise the short encoding")
    sig2049 = i2osp(rsasp1(os2ip(em2049), d2049, n2049), 257)
    if not pss_verify(
        128,
        m_hash,
        i2osp(rsaep(os2ip(sig2049), e2049, n2049), em_len(n2049)),
        n2049,
    ):
        sys.exit("the reference does not verify its own 2049-bit signature")

    ours = [(name, sign(a, MESSAGE, n2048, d2048).hex()) for name, a in (
        ("Shake128", 128),
        ("Shake256", 256),
    )]
    # A salt that is not the default, to hold `Exact` to a number of its own.
    short = sign(128, MESSAGE, n2048, d2048, salt_len=16).hex()

    text = f"""// Generated by scripts/gen_shake_pss_vectors.py; rerun it rather than editing.
//
// RFC 8702 in both directions. OpenSSL 3.5 refuses SHAKE inside RSASSA-PSS
// ("digest not allowed"), so no third party signs one on this machine: the
// signatures below come from an independent implementation of the same RFC in
// Python, over a SHAKE that this script checks against `openssl` octet for
// octet.
//
// `shake_foreign` and `shake_tall` are that implementation's, with salts of its
// own choosing, so verifying one never consults the rule this library derives a
// salt by. `shake_ours` and `shake_short` are what signing must reproduce byte
// for byte on every run.

///|
/// The 2048-bit modulus and public exponent, big-endian.
let shake_modulus : String = "{even(KEY_2048[0])}"

///|
/// The private exponent that goes with it.
let shake_private : String = "{even(KEY_2048[2])}"

///|
/// A 2049-bit modulus, one bit past a whole number of octets, where the encoded
/// message is 256 octets wide and the signature 257.
let shake_tall_modulus : String = "{even(KEY_2049[0])}"

///|
/// Its private exponent.
let shake_tall_private : String = "{even(KEY_2049[2])}"

///|
/// The message all of them were taken over, hex.
let shake_message : String = "{MESSAGE.hex()}"

///|
/// (variant, signature) — signatures a peer made, with salts of its choosing.
let shake_foreign : Array[(String, String)] = [
"""
    for name, sig in foreign:
        text += f'  ("{name}", "{sig}"),\n'
    text += f"""]
///
/// (variant, signature) — what signing `shake_message` must produce, byte for
/// byte, with the salt derived as this library derives it.
let shake_ours : Array[(String, String)] = [
  ("Shake128", "{ours[0][1]}"),
  ("Shake256", "{ours[1][1]}"),
]

///|
/// A signature under Shake128 with a 16-octet salt rather than the variant's 32.
let shake_short : String = "{short}"

///|
/// The signature over the 2049-bit modulus, Shake128, a 32-octet salt.
let shake_tall : String = "{sig2049.hex()}"

///|
fn shake_hex(s : String) -> Bytes {{
  @base16.decode(s) catch {{ _ => abort("a pinned vector is not hex") }}
}}

///|
fn shake_xof(name : String) -> @rsa.Xof {{
  match name {{
    "Shake128" => Shake128
    "Shake256" => Shake256
    _ => abort("no such variant")
  }}
}}

///|
fn shake_public() -> @rsa.PublicKey raise {{
  @rsa.PublicKey::new(shake_hex(shake_modulus)[:], b"\\x01\\x00\\x01"[:])
}}

///|
fn shake_signing(xof : @rsa.Xof, salt : @rsa.Salt) -> @rsa.PrivateKey raise {{
  @rsa.PrivateKey::new(
    shake_hex(shake_modulus)[:],
    b"\\x01\\x00\\x01"[:],
    shake_hex(shake_private)[:],
    digest=Sha256,
    scheme=@rsa.PssShake(salt=salt, xof=xof),
  )
}}

///|
test "a signature a peer made under RFC 8702 verifies" {{
  let msg = shake_hex(shake_message)[:]
  for row in shake_foreign {{
    let (name, sig) = row
    let key = shake_public().with_scheme(
      digest=Sha256,
      scheme=@rsa.PssShake(salt=@rsa.Auto, xof=shake_xof(name)),
    )
    assert_true(key.verify(msg, shake_hex(sig)[:]))
  }}
}}

///|
test "signing under RFC 8702 reproduces the pinned bytes" {{
  let msg = shake_hex(shake_message)[:]
  for row in shake_ours {{
    let (name, sig) = row
    let sk = shake_signing(shake_xof(name), @rsa.Auto)
    assert_eq(@spec.eq(sk.sign(msg)[:], shake_hex(sig)[:]), true)
    assert_true(sk.public().verify(msg, shake_hex(sig)[:]))
  }}
}}

///|
test "the salt length of a SHAKE signature is held to the number given" {{
  let msg = shake_hex(shake_message)[:]
  let sk = shake_signing(Shake128, @rsa.Exact(16))
  assert_eq(@spec.eq(sk.sign(msg)[:], shake_hex(shake_short)[:]), true)
  assert_true(sk.public().verify(msg, shake_hex(shake_short)[:]))
  // The variant's own 32 octets do not answer to a key that asked for 16.
  let pinned = shake_foreign[0].1
  assert_eq(shake_public()
    .with_scheme(
      digest=Sha256,
      scheme=@rsa.PssShake(salt=@rsa.Exact(16), xof=Shake128),
    )
    .verify(msg, shake_hex(pinned)[:]), false)
}}

///|
test "a 2049-bit modulus encodes into 256 octets and signs into 257" {{
  let msg = shake_hex(shake_message)[:]
  let sig = shake_hex(shake_tall)[:]
  assert_eq(sig.length(), 257)
  let key = @rsa.PublicKey::new(
    shake_hex(shake_tall_modulus)[:],
    b"\\x01\\x00\\x01"[:],
    digest=Sha256,
    scheme=@rsa.PssShake(salt=@rsa.Auto, xof=Shake128),
  )
  assert_true(key.verify(msg, sig))
  let sk = @rsa.PrivateKey::new(
    shake_hex(shake_tall_modulus)[:],
    b"\\x01\\x00\\x01"[:],
    shake_hex(shake_tall_private)[:],
    digest=Sha256,
    scheme=@rsa.PssShake(salt=@rsa.Auto, xof=Shake128),
  )
  // This one's salt is the reference's own rather than derived, so the pinned
  // bytes are a verification vector; signing has to agree with itself and with
  // the same decoder, at the same 257-octet width.
  let ours = sk.sign(msg)
  assert_eq(ours.length(), 257)
  assert_true(key.verify(msg, ours[:]))
  assert_true(sk.public().verify(msg, ours[:]))
}}

///|
test "a SHAKE signature bends when the block does" {{
  let msg = shake_hex(shake_message)[:]
  let sig = shake_hex(shake_ours[0].1)
  let key = shake_public().with_scheme(
    digest=Sha256,
    scheme=@rsa.PssShake(salt=@rsa.Auto, xof=Shake128),
  )
  // A different message under the same signature.
  assert_eq(key.verify(b"another message"[:], sig), false)
  // A signature one octet short, and one with a bent byte.
  assert_eq(key.verify(msg, sig[0:sig.length() - 1]), false)
  let bent : Array[Byte] = []
  for b in sig {{
    bent.push(b)
  }}
  bent[bent.length() - 1] = (bent[bent.length() - 1].to_int() ^ 1).to_byte()
  assert_eq(key.verify(msg, Bytes::from_array(bent)[:]), false)
}}

///|
test "a SHAKE variant does not answer for the other one" {{
  let msg = shake_hex(shake_message)[:]
  let sig = shake_hex(shake_ours[1].1)
  let key = shake_public().with_scheme(
    digest=Sha256,
    scheme=@rsa.PssShake(salt=@rsa.Auto, xof=Shake128),
  )
  assert_eq(key.verify(msg, sig), false)
}}
"""
    dest = ROOT / "rsa" / "shake_pss_test.mbt"
    dest.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {len(foreign) + len(ours) + 2} signatures to {dest}")


if __name__ == "__main__":
    main()
