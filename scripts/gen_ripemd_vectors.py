#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""Emit the RIPEMD-160 digest vectors for src/hash/ripemd.

The reference below is the algorithm written out from the specification, tables
and all, and it has to agree with PyCryptodome on every case before a digest is
printed. Writing it out is the point: RIPEMD-160 is two parallel lines of eighty
rounds with four tables of eighty entries, and a transcription error in one of
them is exactly the kind of mistake that a test generated from the same
transcription would never catch.

Three published digests are asserted first, so the tables are pinned by the
standard and not only by another implementation.

Usage:
    python scripts/gen_ripemd_vectors.py
"""

import struct

from Crypto.Hash import RIPEMD160

# --- the algorithm, written out -------------------------------------------

# Message word order, left and right lines (RIPEMD-160 specification section 3).
R = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
]
RP = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
]
S = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
]
SP = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
]
K = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
KP = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]


def rol(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def f(j, x, y, z):
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & z)
    if j < 48:
        return (x | ~y) ^ z
    if j < 64:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def compress(h, block):
    x = list(struct.unpack("<16I", block))
    al, bl, cl, dl, el = h
    ar, br, cr, dr, er = h
    for j in range(80):
        t = (rol((al + f(j, bl, cl, dl) + x[R[j]] + K[j // 16]) & 0xFFFFFFFF, S[j]) + el) & 0xFFFFFFFF
        al, el, dl, cl, bl = el, dl, rol(cl, 10), bl, t
        t = (rol((ar + f(79 - j, br, cr, dr) + x[RP[j]] + KP[j // 16]) & 0xFFFFFFFF, SP[j]) + er) & 0xFFFFFFFF
        ar, er, dr, cr, br = er, dr, rol(cr, 10), br, t
    # The five words are combined across the two lines, one from each and the
    # previous state word from neither: that shuffle is what makes the lines
    # inseparable.
    return [
        (h[1] + cl + dr) & 0xFFFFFFFF,
        (h[2] + dl + er) & 0xFFFFFFFF,
        (h[3] + el + ar) & 0xFFFFFFFF,
        (h[4] + al + br) & 0xFFFFFFFF,
        (h[0] + bl + cr) & 0xFFFFFFFF,
    ]


def ripemd160(msg):
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    bits = len(msg) * 8
    padded = msg + b"\x80"
    while len(padded) % 64 != 56:
        padded += b"\x00"
    padded += struct.pack("<Q", bits)
    for i in range(0, len(padded), 64):
        h = compress(h, padded[i:i + 64])
    return struct.pack("<5I", *h)


# --- checks and output ----------------------------------------------------

PUBLISHED = [
    (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
]

CASES = [
    ("empty", b""),
    ("a", b"a"),
    ("abc", b"abc"),
    ("message digest", b"message digest"),
    ("alphabet", b"abcdefghijklmnopqrstuvwxyz"),
    ("alnum", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
    ("digits", b"1234567890" * 8),
    ("block 55", bytes(range(55))),
    ("block 56", bytes(range(56))),
    ("block 63", bytes(range(63))),
    ("block 64", bytes(range(64))),
    ("block 65", bytes(range(65))),
    ("block 119", bytes(range(119))),
    ("block 120", bytes(range(120))),
    ("long", b"a" * 1000),
    ("eight thousand", bytes(range(256)) * 32),
]


def check():
    for msg, want in PUBLISHED:
        got = ripemd160(msg).hex()
        assert got == want, f"published vector {msg!r}: {got} != {want}"
    for label, msg in CASES:
        mine = ripemd160(msg).hex()
        theirs = RIPEMD160.new(msg).hexdigest()
        assert mine == theirs, f"{label}: {mine} != {theirs}"
    print("RIPEMD-160 reproduces the published digests and agrees with PyCryptodome")


def main():
    check()

    print()
    for label, msg in CASES:
        print('  { msg: "%s", expected: "%s" },' % (msg.hex(), ripemd160(msg).hex()))


if __name__ == "__main__":
    main()
