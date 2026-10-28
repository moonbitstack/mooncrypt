#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""Emit the XXH32 and XXH64 test vectors for src/sum/xxhash.

The reference here is written out longhand from the xxHash specification rather
than taken from a library, and then checked against the `xxhash` C extension for
every case before anything is printed. Two independent implementations agreeing
on a case is the only reason a row is emitted.

The messages are a deliberate mix of lengths: XXH32 switches algorithm at 16
bytes and XXH64 at 32, so the cases bracket both thresholds from below and
above, and a couple of long ones confirm that the accumulator drains correctly
over many stripes.

Usage:
    python scripts/gen_xxhash_vectors.py
"""

import xxhash

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF

P32_1 = 0x9E3779B1
P32_2 = 0x85EBCA77
P32_3 = 0xC2B2AE3D
P32_4 = 0x27D4EB2F
P32_5 = 0x165667B1

P64_1 = 0x9E3779B185EBCA87
P64_2 = 0xC2B2AE3D27D4EB4F
P64_3 = 0x165667B19E3779F9
P64_4 = 0x85EBCA77C2B2AE63
P64_5 = 0x27D4EB2F165667C5


def rotl32(x, r):
    return ((x << r) | (x >> (32 - r))) & M32


def rotl64(x, r):
    return ((x << r) | (x >> (64 - r))) & M64


def le32(b, at):
    return int.from_bytes(b[at:at + 4], "little")


def le64(b, at):
    return int.from_bytes(b[at:at + 8], "little")


def xxh32(data, seed=0):
    n = len(data)
    at = 0
    if n >= 16:
        v1 = (seed + P32_1 + P32_2) & M32
        v2 = (seed + P32_2) & M32
        v3 = seed & M32
        v4 = (seed - P32_1) & M32
        while at + 16 <= n:
            v1 = rotl32((v1 + le32(data, at) * P32_2) & M32, 13) * P32_1 & M32
            v2 = rotl32((v2 + le32(data, at + 4) * P32_2) & M32, 13) * P32_1 & M32
            v3 = rotl32((v3 + le32(data, at + 8) * P32_2) & M32, 13) * P32_1 & M32
            v4 = rotl32((v4 + le32(data, at + 12) * P32_2) & M32, 13) * P32_1 & M32
            at += 16
        h = (rotl32(v1, 1) + rotl32(v2, 7) + rotl32(v3, 12) + rotl32(v4, 18)) & M32
    else:
        h = (seed + P32_5) & M32
    h = (h + n) & M32
    while at + 4 <= n:
        h = (h + le32(data, at) * P32_3) & M32
        h = rotl32(h, 17) * P32_4 & M32
        at += 4
    while at < n:
        h = (h + data[at] * P32_5) & M32
        h = rotl32(h, 11) * P32_1 & M32
        at += 1
    h ^= h >> 15
    h = h * P32_2 & M32
    h ^= h >> 13
    h = h * P32_3 & M32
    h ^= h >> 16
    return h


def xxh64(data, seed=0):
    n = len(data)
    at = 0
    if n >= 32:
        v1 = (seed + P64_1 + P64_2) & M64
        v2 = (seed + P64_2) & M64
        v3 = seed & M64
        v4 = (seed - P64_1) & M64
        while at + 32 <= n:
            v1 = rotl64((v1 + le64(data, at) * P64_2) & M64, 31) * P64_1 & M64
            v2 = rotl64((v2 + le64(data, at + 8) * P64_2) & M64, 31) * P64_1 & M64
            v3 = rotl64((v3 + le64(data, at + 16) * P64_2) & M64, 31) * P64_1 & M64
            v4 = rotl64((v4 + le64(data, at + 24) * P64_2) & M64, 31) * P64_1 & M64
            at += 32
        h = (rotl64(v1, 1) + rotl64(v2, 7) + rotl64(v3, 12) + rotl64(v4, 18)) & M64
        for v in (v1, v2, v3, v4):
            h ^= rotl64(v * P64_2 & M64, 31) * P64_1 & M64
            h = (h * P64_1 + P64_4) & M64
    else:
        h = (seed + P64_5) & M64
    h = (h + n) & M64
    while at + 8 <= n:
        k = rotl64(le64(data, at) * P64_2 & M64, 31) * P64_1 & M64
        h ^= k
        h = (rotl64(h, 27) * P64_1 + P64_4) & M64
        at += 8
    if at + 4 <= n:
        h ^= le32(data, at) * P64_1 & M64
        h = (rotl64(h, 23) * P64_2 + P64_3) & M64
        at += 4
    while at < n:
        h ^= data[at] * P64_5 & M64
        h = rotl64(h, 11) * P64_1 & M64
        at += 1
    h ^= h >> 33
    h = h * P64_2 & M64
    h ^= h >> 29
    h = h * P64_3 & M64
    h ^= h >> 32
    return h


# (label, bytes) — lengths bracket the 16-byte and 32-byte thresholds.
CASES = [
    ("", b""),
    ("61", b"a"),
    ("616263", b"abc"),
    ("6162636465666768696a6b6c6d6e6f", bytes(range(0x61, 0x70))),
    ("313233343536373839", b"123456789"),
    ("00", b"\x00"),
    ("000102030405060708090a0b0c0d0e0f", bytes(range(16))),
    ("000102030405060708090a0b0c0d0e0f10", bytes(range(17))),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     bytes(range(32))),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
     bytes(range(33))),
    ("6d65737361676520646967657374", b"message digest"),
    ("666f6f", b"foo"),
    ("666f6f626172", b"foobar"),
    ("6d6f6f6e6372797074", b"mooncrypt"),
    ("ff" * 64, b"\xff" * 64),
    ("54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
     b"The quick brown fox jumps over the lazy dog"),
]

# Seeds: zero everywhere, plus a couple of non-zero ones so the seed really is
# threaded through the accumulator rather than being decorative.
SEEDS = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]


def check_reference():
    """Refuse to emit unless our hand-written reference agrees with the C one."""
    for _, data in CASES:
        for seed in (0, 1, 0x9E3779B1, 0xFFFFFFFF):
            mine32 = xxh32(data, seed)
            theirs32 = xxhash.xxh32(data, seed=seed).intdigest()
            assert mine32 == theirs32, (
                f"XXH32 mismatch on {data!r} seed {seed:#x}: "
                f"{mine32:#010x} != {theirs32:#010x}"
            )
            mine64 = xxh64(data, seed)
            theirs64 = xxhash.xxh64(data, seed=seed).intdigest()
            assert mine64 == theirs64, (
                f"XXH64 mismatch on {data!r} seed {seed:#x}: "
                f"{mine64:#018x} != {theirs64:#018x}"
            )
    # The empty-input digests are the published ones from the xxHash
    # specification; asserting them pins the constants independently of the
    # library.
    assert xxh32(b"") == 0x02CC5D05
    assert xxh64(b"") == 0xEF46DB3751D8E999
    print("xxHash reference agrees with the C extension and the published anchors")


def row(width, seed, label, digest):
    """One Case literal. MoonBit wants the field names written out."""
    print(
        '  { width: %d, seed: 0x%08XUL, data: "%s", expected: 0x%0*XUL },'
        % (width, seed, label, 8 if width == 32 else 16, digest)
    )


def main():
    check_reference()
    print()
    print("// XXH32")
    for label, data in CASES:
        row(32, 0, label, xxh32(data))
    print()
    print("// XXH64")
    for label, data in CASES:
        row(64, 0, label, xxh64(data))
    print()
    print("// seeded")
    for seed in (1, 0x9E3779B1, 0xFFFFFFFF):
        for label, data in CASES[:6]:
            row(32, seed, label, xxh32(data, seed))
            row(64, seed, label, xxh64(data, seed))

if __name__ == "__main__":
    main()
