#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""Emit the Camellia block vectors for src/cipher/camellia.

The reference here is written from RFC 3713 — the S-box table, the F-function's
byte permutation, the FL/FLINV pair and the four shift lists are transcribed
straight out of the text of the RFC, not from any implementation. It is then
pinned twice over:

  1. The three worked examples in Appendix A of the RFC must reproduce, one for
     each key length.
  2. Every emitted case is cross-checked against OpenSSL's Camellia, which is an
     independent implementation.

A transcription slip in the tables breaks the first check; a shared misreading
of the round structure breaks the second. Neither alone is enough, which is why
both are here.

Usage:
    python scripts/gen_camellia_vectors.py
"""

import subprocess

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF
MASK128 = (1 << 128) - 1

SIGMA1 = 0xA09E667F3BCC908B
SIGMA2 = 0xB67AE8584CAA73B2
SIGMA3 = 0xC6EF372FE94F82BE
SIGMA4 = 0x54FF53A5F1D36F1C
SIGMA5 = 0x10E527FADE682D1D
SIGMA6 = 0xB05688C2B3E6C1FD

# RFC 3713 §2.4.2, SBOX1. SBOX2, SBOX3 and SBOX4 are derived from this one.
SBOX1 = [
    112, 130, 44, 236, 179, 39, 192, 229, 228, 133, 87, 53, 234, 12, 174, 65,
    35, 239, 107, 147, 69, 25, 165, 33, 237, 14, 79, 78, 29, 101, 146, 189,
    134, 184, 175, 143, 124, 235, 31, 206, 62, 48, 220, 95, 94, 197, 11, 26,
    166, 225, 57, 202, 213, 71, 93, 61, 217, 1, 90, 214, 81, 86, 108, 77,
    139, 13, 154, 102, 251, 204, 176, 45, 116, 18, 43, 32, 240, 177, 132, 153,
    223, 76, 203, 194, 52, 126, 118, 5, 109, 183, 169, 49, 209, 23, 4, 215,
    20, 88, 58, 97, 222, 27, 17, 28, 50, 15, 156, 22, 83, 24, 242, 34,
    254, 68, 207, 178, 195, 181, 122, 145, 36, 8, 232, 168, 96, 252, 105, 80,
    170, 208, 160, 125, 161, 137, 98, 151, 84, 91, 30, 149, 224, 255, 100, 210,
    16, 196, 0, 72, 163, 247, 117, 219, 138, 3, 230, 218, 9, 63, 221, 148,
    135, 92, 131, 2, 205, 74, 144, 51, 115, 103, 246, 243, 157, 127, 191, 226,
    82, 155, 216, 38, 200, 55, 198, 59, 129, 150, 111, 75, 19, 190, 99, 46,
    233, 121, 167, 140, 159, 110, 188, 142, 41, 245, 249, 182, 47, 253, 180, 89,
    120, 152, 6, 106, 231, 70, 113, 186, 212, 37, 171, 66, 136, 162, 141, 250,
    114, 7, 185, 85, 248, 238, 172, 10, 54, 73, 42, 104, 60, 56, 241, 164,
    64, 40, 211, 123, 187, 201, 67, 193, 21, 227, 173, 244, 119, 199, 128, 158,
]


def rol8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


SBOX2 = [rol8(v, 1) for v in SBOX1]
SBOX3 = [rol8(v, 7) for v in SBOX1]
SBOX4 = [SBOX1[rol8(x, 1)] for x in range(256)]


def f(x, k):
    """RFC 3713 §2.4.1: the round function."""
    t = x ^ k
    t1 = (t >> 56) & 0xFF
    t2 = (t >> 48) & 0xFF
    t3 = (t >> 40) & 0xFF
    t4 = (t >> 32) & 0xFF
    t5 = (t >> 24) & 0xFF
    t6 = (t >> 16) & 0xFF
    t7 = (t >> 8) & 0xFF
    t8 = t & 0xFF
    t1 = SBOX1[t1]
    t2 = SBOX2[t2]
    t3 = SBOX3[t3]
    t4 = SBOX4[t4]
    t5 = SBOX2[t5]
    t6 = SBOX3[t6]
    t7 = SBOX4[t7]
    t8 = SBOX1[t8]
    y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8
    y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8
    y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8
    y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7
    y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8
    y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8
    y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8
    y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7
    return (
        (y1 << 56) | (y2 << 48) | (y3 << 40) | (y4 << 32)
        | (y5 << 24) | (y6 << 16) | (y7 << 8) | y8
    )


def fl(x, k):
    x1 = (x >> 32) & MASK32
    x2 = x & MASK32
    k1 = (k >> 32) & MASK32
    k2 = k & MASK32
    x2 ^= rol32(x1 & k1, 1)
    x1 ^= x2 | k2
    return ((x1 & MASK32) << 32) | (x2 & MASK32)


def flinv(y, k):
    y1 = (y >> 32) & MASK32
    y2 = y & MASK32
    k1 = (k >> 32) & MASK32
    k2 = k & MASK32
    y1 ^= y2 | k2
    y2 ^= rol32(y1 & k1, 1)
    return ((y1 & MASK32) << 32) | (y2 & MASK32)


def rol32(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK32


def rol128(v, n):
    v &= MASK128
    return ((v << n) | (v >> (128 - n))) & MASK128


def halves(v):
    return (v >> 64) & MASK64, v & MASK64


def join(hi, lo):
    return ((hi & MASK64) << 64) | (lo & MASK64)


def schedule(key):
    """RFC 3713 §2.2 and the two subkey tables that follow it.

    Returns (kw, k, ke) in encryption order. Decryption is the same lists read
    backwards, with the four whitening words swapped in pairs — §2.3.3.
    """
    bits = len(key) * 8
    assert bits in (128, 192, 256), bits
    k_int = int.from_bytes(key, "big")

    if bits == 128:
        kl = k_int
        kr = 0
    elif bits == 192:
        kl = k_int >> 64
        kr = join(k_int & MASK64, ~k_int & MASK64)
    else:
        kl = k_int >> 128
        kr = k_int & MASK128

    d1, d2 = halves(kl ^ kr)
    d2 ^= f(d1, SIGMA1)
    d1 ^= f(d2, SIGMA2)
    kl1, kl2 = halves(kl)
    d1 ^= kl1
    d2 ^= kl2
    d2 ^= f(d1, SIGMA3)
    d1 ^= f(d2, SIGMA4)
    ka = join(d1, d2)

    d1, d2 = halves(ka ^ kr)
    d2 ^= f(d1, SIGMA5)
    d1 ^= f(d2, SIGMA6)
    kb = join(d1, d2)

    def take(v, n, right):
        hi, lo = halves(rol128(v, n))
        return lo if right else hi

    if bits == 128:
        kw = [
            take(kl, 0, False), take(kl, 0, True),
            take(ka, 111, False), take(ka, 111, True),
        ]
        ks = [
            take(ka, 0, False), take(ka, 0, True),
            take(kl, 15, False), take(kl, 15, True),
            take(ka, 15, False), take(ka, 15, True),
            take(kl, 45, False), take(kl, 45, True),
            take(ka, 45, False),
            # The one asymmetry in the 128-bit list: k10 comes from KL, not KA.
            take(kl, 60, True),
            take(ka, 60, False), take(ka, 60, True),
            take(kl, 94, False), take(kl, 94, True),
            take(ka, 94, False), take(ka, 94, True),
            take(kl, 111, False), take(kl, 111, True),
        ]
        ke = [
            take(ka, 30, False), take(ka, 30, True),
            take(kl, 77, False), take(kl, 77, True),
        ]
        return kw, ks, ke

    kw = [
        take(kl, 0, False), take(kl, 0, True),
        take(kb, 111, False), take(kb, 111, True),
    ]
    ks = [
        take(kb, 0, False), take(kb, 0, True),
        take(kr, 15, False), take(kr, 15, True),
        take(ka, 15, False), take(ka, 15, True),
        take(kb, 30, False), take(kb, 30, True),
        take(kl, 45, False), take(kl, 45, True),
        take(ka, 45, False), take(ka, 45, True),
        take(kr, 60, False), take(kr, 60, True),
        take(kb, 60, False), take(kb, 60, True),
        take(kl, 77, False), take(kl, 77, True),
        take(kr, 94, False), take(kr, 94, True),
        take(ka, 94, False), take(ka, 94, True),
        take(kl, 111, False), take(kl, 111, True),
    ]
    ke = [
        take(kr, 30, False), take(kr, 30, True),
        take(kl, 60, False), take(kl, 60, True),
        take(ka, 77, False), take(ka, 77, True),
    ]
    return kw, ks, ke


def encrypt(key, plain):
    """The Feistel network of RFC 3713 §2.3, written once for both key sizes."""
    kw, ks, ke = schedule(key)
    d1, d2 = halves(int.from_bytes(plain, "big"))
    d1 ^= kw[0]
    d2 ^= kw[1]
    at = 0
    groups = len(ks) // 6
    for g in range(groups):
        d2 ^= f(d1, ks[at]); at += 1
        d1 ^= f(d2, ks[at]); at += 1
        d2 ^= f(d1, ks[at]); at += 1
        d1 ^= f(d2, ks[at]); at += 1
        d2 ^= f(d1, ks[at]); at += 1
        d1 ^= f(d2, ks[at]); at += 1
        if g < groups - 1:
            d1 = fl(d1, ke[2 * g])
            d2 = flinv(d2, ke[2 * g + 1])
    d2 ^= kw[2]
    d1 ^= kw[3]
    return join(d2, d1).to_bytes(16, "big")


def decrypt(key, cipher):
    """§2.3.3: the same network with every subkey list reversed."""
    kw, ks, ke = schedule(key)
    d1, d2 = halves(int.from_bytes(cipher, "big"))
    kw = [kw[2], kw[3], kw[0], kw[1]]
    ks = list(reversed(ks))
    ke = list(reversed(ke))
    d1 ^= kw[0]
    d2 ^= kw[1]
    at = 0
    groups = len(ks) // 6
    for g in range(groups):
        d2 ^= f(d1, ks[at]); at += 1
        d1 ^= f(d2, ks[at]); at += 1
        d2 ^= f(d1, ks[at]); at += 1
        d1 ^= f(d2, ks[at]); at += 1
        d2 ^= f(d1, ks[at]); at += 1
        d1 ^= f(d2, ks[at]); at += 1
        if g < groups - 1:
            d1 = fl(d1, ke[2 * g])
            d2 = flinv(d2, ke[2 * g + 1])
    d2 ^= kw[2]
    d1 ^= kw[3]
    return join(d2, d1).to_bytes(16, "big")


PUBLISHED = [
    (
        "0123456789abcdeffedcba9876543210",
        "0123456789abcdeffedcba9876543210",
        "67673138549669730857065648eabe43",
    ),
    (
        "0123456789abcdeffedcba98765432100011223344556677",
        "0123456789abcdeffedcba9876543210",
        "b4993401b3e996f84ee5cee7d79b09b9",
    ),
    (
        "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
        "0123456789abcdeffedcba9876543210",
        "9acc237dff16d76c20ef7c919e3a7509",
    ),
]


def openssl(key, plain):
    """Camellia as an independent implementation sees it."""
    bits = len(key) * 4
    name = {128: "camellia-128-ecb", 192: "camellia-192-ecb", 256: "camellia-256-ecb"}
    out = subprocess.run(
        ["openssl", "enc", "-" + name[bits], "-K", key, "-nopad"],
        input=bytes.fromhex(plain),
        capture_output=True,
        check=True,
    )
    return out.stdout.hex()


def check():
    for key, plain, want in PUBLISHED:
        got = encrypt(bytes.fromhex(key), bytes.fromhex(plain)).hex()
        assert got == want, f"appendix {len(key) * 4}-bit: {got} != {want}"
        back = decrypt(bytes.fromhex(key), bytes.fromhex(want)).hex()
        assert back == plain, f"appendix {len(key) * 4}-bit: decrypt {back} != {plain}"
    print("Camellia reproduces all three Appendix A examples")
    # SBOX1[0x3d] == 86, the example the RFC gives when it introduces the table.
    assert SBOX1[0x3D] == 86, SBOX1[0x3D]


CASES = {
    128: [
        "0123456789abcdeffedcba9876543210",
        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffff",
        "0123456789abcdeffedcba9876543210",
        "80000000000000000000000000000000",
        "000102030405060708090a0b0c0d0e0f",
        "fedcba98765432100123456789abcdef",
        "a1b2c3d4e5f60718293a4b5c6d7e8f90",
    ],
    192: [
        "0123456789abcdeffedcba98765432100011223344556677",
        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffffffffffffffffffff",
        "00112233445566778899aabbccddeeff1021324354657687",
        "800000000000000000000000000000000000000000000000",
    ],
    256: [
        "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f",
        "8000000000000000000000000000000000000000000000000000000000000000",
    ],
}

PLAINS = [
    "0123456789abcdeffedcba9876543210",
    "00000000000000000000000000000000",
    "ffffffffffffffffffffffffffffffff",
    "00000000000000000000000000000001",
    "4e6f77206973207468652074696d6521",
    "000102030405060708090a0b0c0d0e0f",
]

for _p in PLAINS:
    assert len(_p) == 32, f"a block is 32 hex digits, not {len(_p)}: {_p}"


def main():
    check()

    for bits in (128, 192, 256):
        print()
        print(f"// {bits}-bit keys")
        for i, key in enumerate(CASES[bits]):
            plain = PLAINS[i % len(PLAINS)]
            mine = encrypt(bytes.fromhex(key), bytes.fromhex(plain)).hex()
            theirs = openssl(key, plain)
            assert mine == theirs, f"{bits}/{key}: {mine} != openssl {theirs}"
            print(
                '  { key: "%s", plain: "%s", cipher: "%s" },'
                % (key, plain, mine)
            )
    print()
    print("Camellia agrees with OpenSSL on every emitted case", flush=True)


if __name__ == "__main__":
    main()
