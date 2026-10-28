#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""Generate the CCM test vectors in src/aead/ccm/ccm_test.mbt.

The reference is the `cryptography` package's AESCCM, which is itself checked
against RFC 3610 packet vector #1 below. Every case is printed in the shape the
MoonBit test consumes, so the table in the test file is never hand-edited and
can never drift from what the reference computes.

Inputs are built from `bytes(range(...))` wherever a length matters, because a
hex literal that is one digit short is exactly the kind of mistake this script
exists to prevent.

    python scripts/gen_ccm_vectors.py
"""

import binascii

from cryptography.hazmat.primitives.ciphers.aead import AESCCM


def seq(n):
    """`n` bytes counting up from zero."""
    return bytes(range(n))


def raw(key, nonce, aad, plain, tag):
    """The ciphertext followed by the tag, as one hex string."""
    sealed = AESCCM(key, tag_length=tag).encrypt(nonce, plain, aad)
    return binascii.hexlify(sealed).decode()


AES128 = seq(16)
AES192 = seq(24)
AES256 = seq(32)

# RFC 3610 packet vector #1, used both as a case and as a self-check.
RFC_KEY = bytes.fromhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")
RFC_NONCE = bytes.fromhex("00000003020100a0a1a2a3a4a5")
RFC_AAD = bytes.fromhex("0001020304050607")
RFC_PLAIN = bytes.fromhex("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e")

# (key, nonce, aad, plaintext, tag length, comment)
CASES = [
    (
        RFC_KEY,
        RFC_NONCE,
        RFC_AAD,
        RFC_PLAIN,
        8,
        "RFC 3610 packet vector #1.",
    ),
    (
        RFC_KEY,
        RFC_NONCE,
        RFC_AAD,
        RFC_PLAIN,
        16,
        "The same inputs with a longer tag: not the same computation\n"
        "/// truncated, but a different one, because the tag length is\n"
        "/// in the first block.",
    ),
    (
        AES128,
        seq(13),
        b"",
        b"",
        16,
        "Nothing but a tag: an empty message with no associated data.",
    ),
    (
        AES128,
        seq(13),
        seq(8),
        b"",
        12,
        "Associated data but no plaintext.",
    ),
    (
        AES128,
        seq(13),
        seq(24),
        b"",
        10,
        "Associated data past the first block, so the length header\n"
        "/// spills into a second block, and still no plaintext.",
    ),
    (
        AES128,
        seq(13),
        b"\xf0\xf1\xf2\xf3",
        b"A",
        4,
        "The shortest tag CCM allows, over one byte.",
    ),
    (
        AES128,
        seq(13),
        b"",
        seq(16),
        16,
        "Exactly one block of plaintext and no associated data.",
    ),
    (
        AES128,
        seq(8),
        bytes.fromhex("cafebabe"),
        b"Hello, CCM!",
        8,
        "An eight-byte nonce, so `L = 7`, and a plaintext that is not\n"
        "/// a whole number of blocks.",
    ),
    (
        AES128,
        seq(7),
        bytes.fromhex("cafebabe"),
        b"Hello, CCM!",
        8,
        "A seven-byte nonce, the shortest CCM allows, which leaves\n"
        "/// `L = 8`: the widest length field the format has.",
    ),
    (
        AES128,
        bytes.fromhex("0008090a0b0c0d0e0f101112"),
        bytes.fromhex("deadbeef"),
        b"Hello, CCM!",
        14,
        "A twelve-byte nonce with a two-byte tag: a tag length that is\n"
        "/// neither short nor long.",
    ),
    (
        AES128,
        seq(13),
        b"\xa0\xa1",
        bytes.fromhex("00112233445566778899aabbccddeeff1021324354657687"),
        6,
        "A thirteen-byte nonce, the longest CCM allows, so `L = 2` and\n"
        "/// the message length has to fit in two bytes.",
    ),
    (
        AES192,
        seq(8),
        bytes.fromhex("feedface"),
        seq(16),
        16,
        "An AES-192 key.",
    ),
    (
        AES256,
        seq(8),
        bytes.fromhex("feedface"),
        seq(16),
        16,
        "An AES-256 key.",
    ),
]


def indent(comment):
    """A `//` comment in which each source line keeps its own indentation.

    The continuation lines of a wrapped comment are written as `///` above so
    that the source still reads as prose; the marker is stripped here.
    """
    lines = [line.removeprefix("///").strip() for line in comment.split("\n")]
    return "".join(f"    // {line}\n" for line in lines)


def main():
    # RFC 3610 packet vector #1, as a self-check on the reference itself.
    got = raw(*CASES[0][:5])
    want = "588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0"
    if got != want:
        raise SystemExit(f"reference disagrees with RFC 3610: {got}")

    out = []
    for key, nonce, aad, plain, tag, comment in CASES:
        body = ",\n".join(
            [
                f'    key: "{key.hex()}"',
                f'    nonce: "{nonce.hex()}"',
                f'    aad: "{aad.hex()}"',
                f'    plain: "{plain.hex()}"',
                f"    tag: {tag}",
                f'    expected: "{raw(key, nonce, aad, plain, tag)}"',
            ]
        )
        out.append(f"  {{\n{indent(comment)}{body},\n  }}")
    print("let cases : Array[Case] = [")
    print(",\n".join(out))
    print("]")


if __name__ == "__main__":
    main()
