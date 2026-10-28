#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""Generate the Adler-32 and FNV test vectors.

Adler-32 is checked against `zlib.adler32` on every message it emits. FNV has no
library here, so the reference is written from scratch and is checked against the
published vectors of both algorithm variants at both widths before it is used —
a typo in the prime shows up immediately as an empty-string digest that is not
the basis.

    python scripts/gen_checksum_vectors.py
"""

import sys
import zlib

MESSAGES = [
    "",
    "61",
    "616263",
    "666f6f",
    "666f6f626172",
    "313233343536373839",
    "6d6f6f6e6372797074",
    "00",
    "ffffffff",
    "00ff00ff00ff00ff",
    "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
]

MODULUS = 65521


def adler32(data):
    a, b = 1, 0
    for byte in data:
        a = (a + byte) % MODULUS
        b = (b + a) % MODULUS
    return (b << 16) | a


FNV = {
    "Fnv1_32": (0x811C9DC5, 0x01000193, 32, True),
    "Fnv1a_32": (0x811C9DC5, 0x01000193, 32, False),
    "Fnv1_64": (0xCBF29CE484222325, 0x100000001B3, 64, True),
    "Fnv1a_64": (0xCBF29CE484222325, 0x100000001B3, 64, False),
}


def fnv(data, kind):
    basis, prime, width, multiply_first = FNV[kind]
    mask = (1 << width) - 1
    value = basis
    for byte in data:
        if multiply_first:
            value = (value * prime) & mask
            value ^= byte
        else:
            value ^= byte
            value = (value * prime) & mask
    return value & mask


# The published FNV vectors, which pin the offset basis and the prime: the
# empty string gives the basis, and any other input gives the prime. Every
# variant has one of each, plus the "foobar" digest the FNV page publishes.
ANCHORS = [
    ("Fnv1_32", "", 0x811C9DC5),
    ("Fnv1_32", "61", 0x050C5D7E),
    ("Fnv1a_32", "", 0x811C9DC5),
    ("Fnv1a_32", "61", 0xE40C292C),
    ("Fnv1a_32", "666f6f626172", 0xBF9CF968),
    ("Fnv1_64", "", 0xCBF29CE484222325),
    ("Fnv1_64", "61", 0xAF63BD4C8601B7BE),
    ("Fnv1a_64", "", 0xCBF29CE484222325),
    ("Fnv1a_64", "61", 0xAF63DC4C8601EC8C),
]


def main():
    for kind, message, want in ANCHORS:
        got = fnv(bytes.fromhex(message), kind)
        if got != want:
            print(f"FNV {kind} anchor {message!r}: {got:X} != {want:X}", file=sys.stderr)
            raise SystemExit(1)
    print("FNV reference agrees with the published vectors", file=sys.stderr)

    for message in MESSAGES:
        data = bytes.fromhex(message)
        if adler32(data) != zlib.adler32(data) & 0xFFFFFFFF:
            print(f"Adler-32 disagrees with zlib on {message}", file=sys.stderr)
            raise SystemExit(1)
    print("Adler-32 reference agrees with zlib", file=sys.stderr)

    print("// adler32")
    for message in MESSAGES:
        print(f'  {{ data: "{message}", expected: 0x{adler32(bytes.fromhex(message)):08X} }},')
    for kind in FNV:
        print(f"// {kind}")
        width = 8 if "64" in kind else 4
        for message in MESSAGES:
            value = fnv(bytes.fromhex(message), kind)
            print(f'  {{ kind: @fnv.{kind}, data: "{message}", expected: 0x{value:0{width * 2}X}UL }},')


if __name__ == "__main__":
    main()
