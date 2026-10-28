#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""Emit the SipHash test vectors for src/mac/siphash.

The reference below is written out from the SipHash paper, then every case is
checked against the `siphash` module before anything is printed. The module
writes its digest little-endian, so the comparison reads it back the same way.

Two published anchors are asserted first, so the constants are pinned
independently of the module: the paper's own vectors for the empty message and
for the message of bytes 0..7 under the same key.

Usage:
    python scripts/gen_siphash_vectors.py
"""

import siphash

M64 = 0xFFFFFFFFFFFFFFFF


def rotl(x, r):
    return ((x << r) | (x >> (64 - r))) & M64


def sipround(v):
    v0, v1, v2, v3 = v
    v0 = (v0 + v1) & M64
    v1 = rotl(v1, 13)
    v1 ^= v0
    v0 = rotl(v0, 32)
    v2 = (v2 + v3) & M64
    v3 = rotl(v3, 16)
    v3 ^= v2
    v0 = (v0 + v3) & M64
    v3 = rotl(v3, 21)
    v3 ^= v0
    v2 = (v2 + v1) & M64
    v1 = rotl(v1, 17)
    v1 ^= v2
    v2 = rotl(v2, 32)
    return (v0, v1, v2, v3)


def siphash_ref(key, data, c=2, d=4):
    k0 = int.from_bytes(key[0:8], "little")
    k1 = int.from_bytes(key[8:16], "little")
    v = (
        k0 ^ 0x736F6D6570736575,
        k1 ^ 0x646F72616E646F6D,
        k0 ^ 0x6C7967656E657261,
        k1 ^ 0x7465646279746573,
    )
    n = len(data)
    at = 0
    while at + 8 <= n:
        m = int.from_bytes(data[at:at + 8], "little")
        v = (v[0], v[1], v[2], v[3] ^ m)
        for _ in range(c):
            v = sipround(v)
        v = (v[0] ^ m, v[1], v[2], v[3])
        at += 8
    last = (n & 0xFF) << 56
    for i in range(n - at):
        last |= data[at + i] << (8 * i)
    v = (v[0], v[1], v[2], v[3] ^ last)
    for _ in range(c):
        v = sipround(v)
    v = (v[0] ^ last, v[1], v[2], v[3])
    v = (v[0], v[1], v[2] ^ 0xFF, v[3])
    for _ in range(d):
        v = sipround(v)
    return v[0] ^ v[1] ^ v[2] ^ v[3]


# The paper's key, and messages that bracket every multiple of the 8-byte block.
KEY = bytes(range(16))
KEY2 = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")

CASES = [
    (KEY, "", b""),
    (KEY, "000102030405060708090a0b0c0d0e", bytes(range(15))),
    (KEY, "000102030405060708090a0b0c0d0e0f", bytes(range(16))),
    (KEY, "00", b"\x00"),
    (KEY, "61", b"a"),
    (KEY, "616263", b"abc"),
    (KEY, "666f6f", b"foo"),
    (KEY, "666f6f626172", b"foobar"),
    (KEY, "0001020304050607", bytes(range(8))),
    (KEY, "000102030405060708", bytes(range(9))),
    (KEY, "000102030405060708090a0b0c0d0e0f1011121314151617", bytes(range(24))),
    (KEY, "6d6f6f6e6372797074", b"mooncrypt"),
    (KEY, "ff" * 17, b"\xff" * 17),
    (KEY, "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
     b"The quick brown fox jumps over the lazy dog"),
    (KEY2, "", b""),
    (KEY2, "666f6f626172", b"foobar"),
    (KEY2, "000102030405060708090a0b0c0d0e0f", bytes(range(16))),
]


def check_reference():
    for key, _, data in CASES:
        mine = siphash_ref(key, data, 2, 4)
        h = siphash.SipHash_2_4(key)
        h.update(data)
        theirs = int.from_bytes(h.digest(), "little")
        assert mine == theirs, (
            f"SipHash-2-4 mismatch on {data!r}: {mine:#018x} != {theirs:#018x}"
        )
    # The published vectors from the SipHash paper (reference.c's test output),
    # for the key 000102...0f: the empty message and the eight-byte message.
    assert siphash_ref(KEY, b"") == 0x726FDB47DD0E0E31
    assert siphash_ref(KEY, bytes(range(8))) == 0x93F5F5799A932462
    print("SipHash reference agrees with the module and the published vectors")


def row(key, label, digest):
    print(
        '  { key: "%s", data: "%s", expected: 0x%016XUL },'
        % (key.hex(), label, digest)
    )


def main():
    check_reference()
    print()
    for key, label, data in CASES:
        row(key, label, siphash_ref(key, data, 2, 4))


if __name__ == "__main__":
    main()
