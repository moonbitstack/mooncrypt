#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""Emit the Salsa20 keystream vectors for src/cipher/salsa20.

The anchor is the example in the Salsa20 specification itself: the key 0x80
followed by thirty-one zero bytes, a zero nonce, and the first sixty-four bytes
of keystream. PyCryptodome reproduces it, so the vector is pinned by the spec and
every other case is pinned by an implementation written by somebody else.

Usage:
    python scripts/gen_salsa20_vectors.py
"""

from Crypto.Cipher import Salsa20

# The specification's own example, section 9.
ANCHOR_KEY = bytes([0x80]) + bytes(31)
ANCHOR_NONCE = bytes(8)
ANCHOR_STREAM = (
    "e3be8fdd8beca2e3ea8ef9475b29a6e7003951e1097a5c38d23b7a5fad9f6844"
    "b22c97559e2723c7cbbd3fe4fc8d9a0744652a83e72a9c461876af4d7ef1a117"
)

# Offsets in blocks, so the counter is exercised past its low byte and past the
# point where a 32-bit counter would have wrapped.
BLOCKS = [0, 1, 2, 255, 256, 65535, 65536, 4294967296]

CASES = [
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "0001020304050607"),
    ("00" * 32, "00" * 8),
    ("ff" * 32, "ff" * 8),
    (ANCHOR_KEY.hex(), ANCHOR_NONCE.hex()),
]


def stream(key, nonce, block):
    """Sixty-four bytes of keystream, starting at a block boundary."""
    cipher = Salsa20.new(key=key, nonce=nonce)
    cipher.seek(block * 64)
    return cipher.encrypt(bytes(64))


def check():
    got = stream(ANCHOR_KEY, ANCHOR_NONCE, 0).hex()
    assert got == ANCHOR_STREAM, f"anchor: {got}"
    if len({len(bytes.fromhex(k)) for k, _ in CASES}) != 1:
        raise AssertionError("every case must use a 32-byte key")
    print("Salsa20 reproduces the specification's example keystream")


def main():
    check()

    print()
    for key, nonce in CASES:
        for block in BLOCKS:
            print(
                '  { key: "%s", nonce: "%s", block: %dUL, expected: "%s" },'
                % (key, nonce, block, stream(bytes.fromhex(key), bytes.fromhex(nonce), block).hex())
            )


if __name__ == "__main__":
    main()
