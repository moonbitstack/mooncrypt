#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""Emit the DES and Triple DES block vectors for src/cipher/des.

Two published answers are asserted first — the classic "Now is t" block under the
key 0123456789abcdef, and the all-zero key on the all-zero block — so that the
tables are pinned by the standard rather than only by PyCryptodome. Every other
case comes from PyCryptodome.

Usage:
    python scripts/gen_des_vectors.py
"""

from Crypto.Cipher import DES, DES3

PUBLISHED = [
    # FIPS 81's example: "Now is t" encrypted under 0123456789abcdef.
    ("0123456789abcdef", "4e6f772069732074", "3fa40e8a984d4815"),
    # The degenerate case every implementation is checked against.
    ("0000000000000000", "0000000000000000", "8ca64de9c1b123a7"),
]

DES_CASES = [
    ("0123456789abcdef", "4e6f772069732074"),
    ("0000000000000000", "0000000000000000"),
    ("ffffffffffffffff", "ffffffffffffffff"),
    ("133457799bbcdff1", "0123456789abcdef"),
    ("8000000000000000", "0000000000000000"),
    ("0000000000000000", "ffffffffffffffff"),
    ("0e329232ea6d0d73", "8787878787878787"),
    ("0123456789abcdef", "0000000000000000"),
    ("fedcba9876543210", "0123456789abcdef"),
    ("a1b2c3d4e5f60718", "0123456789abcdef"),
]

# Each triple key is written as its three eight-byte parts and joined here, so a
# miscount is impossible: a 47-digit key is not a typo that fails loudly later,
# it is a `KeyError` on the next line.
TRIPLE_CASES = [
    (("0123456789abcdef", "fedcba9876543210", "89abcdef01234567"), "0000000000000000"),
    (("0123456789abcdef", "fedcba9876543210", "89abcdef01234567"), "ffffffffffffffff"),
    # A key that repeats all three parts is single DES, and PyCryptodome refuses
    # to build it — so that property is asserted in the MoonBit test instead,
    # against the DES vectors above.
    (("fedcba9876543210", "0123456789abcdef", "ffffffffffffffff"), "4e6f772069732074"),
    (("0123456789abcdef", "fedcba9876543210", "0123456789abcdef"), "0001020304050607"),
]

TWO_KEY_CASES = [
    (("0123456789abcdef", "fedcba9876543210"), "0123456789abcdef"),
    # Not all zero: a two-key key whose halves are equal degenerates to single
    # DES, which PyCryptodome refuses, and rightly so.
    (("0000000000000000", "26469c9f0badbeef"), "0123456789abcdef"),
]


def key_of(parts):
    """Join eight-byte hex parts, refusing anything that is not eight bytes."""
    for part in parts:
        assert len(part) == 16, f"key part {part} is {len(part)} hex digits, not 16"
    return "".join(parts)


def check():
    for key, plain, want in PUBLISHED:
        got = DES.new(bytes.fromhex(key), DES.MODE_ECB).encrypt(bytes.fromhex(plain)).hex()
        assert got == want, f"published {key}/{plain}: {got} != {want}"
    print("DES reproduces both published blocks")


def main():
    check()

    print()
    print("// DES")
    for key, plain in DES_CASES:
        cipher = DES.new(bytes.fromhex(key), DES.MODE_ECB)
        print(
            '  { key: "%s", plain: "%s", cipher: "%s" },'
            % (key, plain, cipher.encrypt(bytes.fromhex(plain)).hex())
        )

    print()
    print("// Triple DES")
    for parts, plain in TRIPLE_CASES:
        key = key_of(parts)
        cipher = DES3.new(bytes.fromhex(key), DES3.MODE_ECB)
        print(
            '  { key: "%s", plain: "%s", cipher: "%s" },'
            % (key, plain, cipher.encrypt(bytes.fromhex(plain)).hex())
        )

    print()
    print("// Two-key Triple DES")
    for parts, plain in TWO_KEY_CASES:
        key = key_of(parts)
        cipher = DES3.new(bytes.fromhex(key), DES3.MODE_ECB)
        print(
            '  { key: "%s", plain: "%s", cipher: "%s" },'
            % (key, plain, cipher.encrypt(bytes.fromhex(plain)).hex())
        )


if __name__ == "__main__":
    main()
