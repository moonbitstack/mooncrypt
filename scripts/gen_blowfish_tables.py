"""Emit the Blowfish initialisation tables for src/cipher/blowfish.

Blowfish's P-array and S-boxes are not arbitrary: they are the hexadecimal
digits of the fractional part of pi, read four at a time as big-endian words.
The first word of the P-array is therefore 0x243f6a88, and that is asserted
below so a mistake in the arithmetic cannot go unnoticed.

Usage: python scripts/gen_blowfish_tables.py > src/cipher/blowfish/tables.mbt
"""

import sys

WORD_COUNT = 18 + 4 * 256  # 18 P words and 1024 S words


def pi_fraction_words(count):
    """The `count` words of pi's hex fraction, as integers."""
    bits = 32 * count + 64  # a little slack so the last word is exact
    one = 1 << bits

    def atan_inv(x):
        """arctan(1/x) scaled by 2**bits, by its Taylor series."""
        total = term = one // x
        x2 = x * x
        n = 1
        while term:
            term //= x2
            total += (-1 if n & 1 else 1) * (term // (2 * n + 1))
            n += 1
        return total

    # Machin's formula: pi = 16 atan(1/5) - 4 atan(1/239).
    pi = 16 * atan_inv(5) - 4 * atan_inv(239)
    fraction = pi - 3 * one
    return [(fraction >> (bits - 32 * (i + 1))) & 0xFFFFFFFF for i in range(count)]


def main():
    words = pi_fraction_words(WORD_COUNT)
    if words[0] != 0x243F6A88:
        raise SystemExit(f"pi looks wrong: first word is {words[0]:#010x}")
    if words[1] != 0x85A308D3:
        raise SystemExit(f"pi looks wrong: second word is {words[1]:#010x}")

    out = sys.stdout
    out.write("""// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The initial P-array: the first 18 words of the hexadecimal fraction of pi.
///
/// Blowfish takes its starting subkeys from nothing-up-my-sleeve constants, so
/// that nobody can claim the choice hides a weakness. The digits carry no
/// meaning beyond being the digits of pi, which is exactly the point.
let p_initial : FixedArray[UInt32] = [
""")
    for i in range(0, 18, 6):
        out.write(
            "  "
            + " ".join(f"0x{w:08X}U," for w in words[i : i + 6])
            + "\n"
        )
    out.write("]\n\n")

    out.write("""///|
/// The four initial S-boxes, 256 words each, taken from pi where the P-array
/// left off.
let s_initial : FixedArray[UInt32] = [
""")
    # Rows of eight, because 256 divides by eight exactly: a partial row would
    # have to be clipped at the box boundary, and a slice that is not clipped
    # quietly takes words from the next box.
    for box in range(4):
        start = 18 + box * 256
        out.write(f"  // S-box {box}.\n")
        for i in range(0, 256, 8):
            row = words[start + i : start + i + 8]
            assert len(row) == 8, (box, i, len(row))
            out.write("  " + " ".join(f"0x{w:08X}U," for w in row) + "\n")
    out.write("]\n")


if __name__ == "__main__":
    main()
