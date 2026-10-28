#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""Emit the MurmurHash3 test vectors for src/sum/murmur3.

Both references below are written out from the algorithm rather than lifted from
a library, and then every case is checked against the `mmh3` module before
anything is printed. The 128-bit form is checked as its two 64-bit halves, which
is how the algorithm itself defines it.

Usage:
    python scripts/gen_murmur3_vectors.py
"""

import mmh3

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF

C32_1 = 0xCC9E2D51
C32_2 = 0x1B873593

C64_1 = 0x87C37B91114253D5
C64_2 = 0x4CF5AD432745937F


def rotl32(x, r):
    return ((x << r) | (x >> (32 - r))) & M32


def rotl64(x, r):
    return ((x << r) | (x >> (64 - r))) & M64


def fmix32(h):
    h ^= h >> 16
    h = h * 0x85EBCA6B & M32
    h ^= h >> 13
    h = h * 0xC2B2AE35 & M32
    h ^= h >> 16
    return h


def fmix64(k):
    k ^= k >> 33
    k = k * 0xFF51AFD7ED558CCD & M64
    k ^= k >> 33
    k = k * 0xC4CEB9FE1A85EC53 & M64
    k ^= k >> 33
    return k


def murmur3_x86_32(data, seed=0):
    n = len(data)
    h = seed & M32
    at = 0
    while at + 4 <= n:
        k = int.from_bytes(data[at:at + 4], "little")
        k = k * C32_1 & M32
        k = rotl32(k, 15)
        k = k * C32_2 & M32
        h ^= k
        h = rotl32(h, 13)
        h = (h * 5 + 0xE6546B64) & M32
        at += 4
    tail = data[at:]
    if tail:
        k = 0
        for i in range(len(tail)):
            k |= tail[i] << (8 * i)
        k = k * C32_1 & M32
        k = rotl32(k, 15)
        k = k * C32_2 & M32
        h ^= k
    h ^= n
    return fmix32(h)


def murmur3_x64_128(data, seed=0):
    n = len(data)
    h1 = seed & M64
    h2 = seed & M64
    at = 0
    while at + 16 <= n:
        k1 = int.from_bytes(data[at:at + 8], "little")
        k2 = int.from_bytes(data[at + 8:at + 16], "little")
        k1 = k1 * C64_1 & M64
        k1 = rotl64(k1, 31)
        k1 = k1 * C64_2 & M64
        h1 ^= k1
        h1 = rotl64(h1, 27)
        h1 = (h1 + h2) & M64
        h1 = (h1 * 5 + 0x52DCE729) & M64
        k2 = k2 * C64_2 & M64
        k2 = rotl64(k2, 33)
        k2 = k2 * C64_1 & M64
        h2 ^= k2
        h2 = rotl64(h2, 31)
        h2 = (h2 + h1) & M64
        h2 = (h2 * 5 + 0x38495AB5) & M64
        at += 16
    tail = data[at:]
    if tail:
        k1 = 0
        k2 = 0
        for i in range(len(tail)):
            if i < 8:
                k1 |= tail[i] << (8 * i)
            else:
                k2 |= tail[i] << (8 * (i - 8))
        if len(tail) > 8:
            k2 = k2 * C64_2 & M64
            k2 = rotl64(k2, 33)
            k2 = k2 * C64_1 & M64
            h2 ^= k2
        k1 = k1 * C64_1 & M64
        k1 = rotl64(k1, 31)
        k1 = k1 * C64_2 & M64
        h1 ^= k1
    h1 ^= n
    h2 ^= n
    h1 = (h1 + h2) & M64
    h2 = (h2 + h1) & M64
    h1 = fmix64(h1)
    h2 = fmix64(h2)
    h1 = (h1 + h2) & M64
    h2 = (h2 + h1) & M64
    return h1, h2


# Lengths either side of the 4-byte and 16-byte block boundaries, plus a long one.
CASES = [
    ("", b""),
    ("61", b"a"),
    ("616263", b"abc"),
    ("666f6f", b"foo"),
    ("666f6f626172", b"foobar"),
    ("313233343536373839", b"123456789"),
    ("00", b"\x00"),
    ("00010203", bytes(range(4))),
    ("000102030405060708", bytes(range(9))),
    ("000102030405060708090a0b0c0d0e0f", bytes(range(16))),
    ("000102030405060708090a0b0c0d0e0f10", bytes(range(17))),
    ("000102030405060708090a0b0c0d0e0f101112131415161718", bytes(range(25))),
    ("6d6f6f6e6372797074", b"mooncrypt"),
    ("6d65737361676520646967657374", b"message digest"),
    ("ff" * 33, b"\xff" * 33),
    ("54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
     b"The quick brown fox jumps over the lazy dog"),
]


def check_reference():
    for _, data in CASES:
        for seed in (0, 1, 0x9747B28C, 0xFFFFFFFF):
            mine = murmur3_x86_32(data, seed)
            theirs = mmh3.hash(data, seed, signed=False)
            assert mine == theirs, (
                f"x86_32 mismatch on {data!r} seed {seed:#x}: "
                f"{mine:#010x} != {theirs:#010x}"
            )
            h1, h2 = murmur3_x64_128(data, seed)
            t1, t2 = mmh3.hash64(data, seed, signed=False)
            assert (h1, h2) == (t1, t2), (
                f"x64_128 mismatch on {data!r} seed {seed:#x}: "
                f"({h1:#018x},{h2:#018x}) != ({t1:#018x},{t2:#018x})"
            )
    print("MurmurHash3 reference agrees with mmh3 on every case and seed")


def row(width, seed, label, low, high):
    if width == 32:
        print(
            '  { width: 32, seed: 0x%08XUL, data: "%s", low: 0x%08XUL, high: 0UL },'
            % (seed, label, low)
        )
    else:
        print(
            '  { width: 128, seed: 0x%08XUL, data: "%s", low: 0x%016XUL, high: 0x%016XUL },'
            % (seed, label, low, high)
        )


def main():
    check_reference()
    print()
    print("// x86_32")
    for label, data in CASES:
        row(32, 0, label, murmur3_x86_32(data), 0)
    print()
    print("// x64_128")
    for label, data in CASES:
        h1, h2 = murmur3_x64_128(data)
        row(128, 0, label, h1, h2)
    print()
    print("// seeded")
    for seed in (1, 0x9747B28C, 0xFFFFFFFF):
        for label, data in CASES[:6]:
            row(32, seed, label, murmur3_x86_32(data, seed), 0)
            h1, h2 = murmur3_x64_128(data, seed)
            row(128, seed, label, h1, h2)


if __name__ == "__main__":
    main()
