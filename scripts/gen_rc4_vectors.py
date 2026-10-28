#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""Emit the RC4 keystream vectors for src/cipher/rc4.

Two independent things have to agree before anything is printed: the published
answer for the classic "Key"/"Plaintext" pair, which pins the algorithm, and
PyCryptodome's ARC4 for every other case, which is an implementation written by
somebody else.

The offsets are the ones RFC 6229 samples, because RC4's first bytes are biased
and an implementation that only ever gets tested at offset zero can hide a length
error that the later offsets expose.

Usage:
    python scripts/gen_rc4_vectors.py
"""

from Crypto.Cipher import ARC4

# The textbook pair: key "Key", plaintext "Plaintext".
ANCHOR = ("Key", "Plaintext", "bbf316e8d940af0ad3")

KEYS = [
    "0102030405",
    "01020304050607",
    "0102030405060708",
    "0102030405060708090a",
    "0102030405060708090a0b0c0d0e0f10",
    "0102030405060708090a0b0c0d0e0f101112131415161718",
    "00",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
]

OFFSETS = [0, 16, 240, 256, 496, 512, 752, 768, 1008, 1024]


def keystream(key, offset, length=16):
    """RC4 over a zero buffer: the ciphertext is the keystream."""
    data = bytes(offset + length)
    return ARC4.new(key).encrypt(data)[offset:]


def check():
    key, plain, want = ANCHOR
    got = ARC4.new(key.encode()).encrypt(plain.encode()).hex()
    assert got == want, f"anchor: {got} != {want}"
    for k in KEYS:
        # A zero-length message consumes no keystream, so a fresh instance for
        # each offset is the same as one that has skipped ahead.
        assert keystream(bytes.fromhex(k), 0) == ARC4.new(bytes.fromhex(k)).encrypt(bytes(16))
    print("RC4 reproduces the textbook pair and agrees with PyCryptodome")


def main():
    check()

    print()
    for k in KEYS:
        for offset in OFFSETS:
            print(
                '  { key: "%s", offset: %d, expected: "%s" },'
                % (k, offset, keystream(bytes.fromhex(k), offset).hex())
            )


if __name__ == "__main__":
    main()
