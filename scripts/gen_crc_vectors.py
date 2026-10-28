#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""Generate the CRC test vectors in src/sum/crc32/ and src/sum/crc16/.

The check value of "123456789" — the anchor every CRC catalogue publishes — is
asserted for each variant before anything is emitted, and the IEEE cases are also
compared against `zlib.crc32`. A polynomial entered with a typo therefore fails
here rather than becoming the expected output of a test.

    python scripts/gen_crc_vectors.py
"""

import sys
import zlib

# name, polynomial, initial, reflected, xorout, published check value
CRC16 = [
    ("Arc", 0x8005, 0x0000, True, 0x0000, 0xBB3D),
    ("CcittFalse", 0x1021, 0xFFFF, False, 0x0000, 0x29B1),
    ("Xmodem", 0x1021, 0x0000, False, 0x0000, 0x31C3),
    ("Kermit", 0x1021, 0x0000, True, 0x0000, 0x2189),
    ("X25", 0x1021, 0xFFFF, True, 0xFFFF, 0x906E),
    ("Modbus", 0x8005, 0xFFFF, True, 0x0000, 0x4B37),
]

CRC32 = [
    ("Ieee", 0x04C11DB7, 0xFFFFFFFF, True, 0xFFFFFFFF),
    ("Castagnoli", 0x1EDC6F41, 0xFFFFFFFF, True, 0xFFFFFFFF),
]


def reflect(value, width):
    out = 0
    for _ in range(width):
        out = (out << 1) | (value & 1)
        value >>= 1
    return out


def crc(data, width, poly, init, reflected, xorout):
    """The reference: shift and xor, one bit at a time, no table."""
    top = 1 << (width - 1)
    mask = (1 << width) - 1
    if reflected:
        poly = reflect(poly, width)
    register = init
    for byte in data:
        register ^= byte if reflected else byte << (width - 8)
        for _ in range(8):
            if reflected:
                register = (register >> 1) ^ poly if register & 1 else register >> 1
            else:
                register = (
                    ((register << 1) ^ poly) & mask
                    if register & top
                    else (register << 1) & mask
                )
            register &= mask
    return register ^ xorout


MESSAGES = [
    "",
    "313233343536373839",
    "61",
    "616263",
    "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
    "6d6f6f6e6372797074",
    "deadbeef",
    "00",
    "ff",
]


def main():
    out32 = []
    for name, poly, init, reflected, xorout in CRC32:
        check = crc(b"123456789", 32, poly, init, reflected, xorout)
        if check != (0xCBF43926 if name == "Ieee" else 0xE3069283):
            print(f"CRC-32 {name} check value {check:08X} is wrong", file=sys.stderr)
            raise SystemExit(1)
        for message in MESSAGES:
            got = crc(bytes.fromhex(message), 32, poly, init, reflected, xorout)
            if name == "Ieee" and got != zlib.crc32(bytes.fromhex(message)) & 0xFFFFFFFF:
                print(f"zlib disagrees on {message}", file=sys.stderr)
                raise SystemExit(1)
            out32.append((name, message, got))

    out16 = []
    for name, poly, init, reflected, xorout, check in CRC16:
        got = crc(b"123456789", 16, poly, init, reflected, xorout)
        if got != check:
            print(f"CRC-16/{name} check value {got:04X} != {check:04X}", file=sys.stderr)
            raise SystemExit(1)
        for message in MESSAGES:
            value = crc(bytes.fromhex(message), 16, poly, init, reflected, xorout)
            out16.append((name, message, value))

    print("// ---- src/sum/crc32/crc32_test.mbt", file=sys.stderr)
    for name, message, value in out32:
        print(f"{name:12s} {message or '(empty)':>10s} 0x{value:08X}")
    print("// ---- src/sum/crc16/crc16_test.mbt", file=sys.stderr)
    for name, message, value in out16:
        print(f"{name:12s} {message or '(empty)':>10s} 0x{value:04X}")


if __name__ == "__main__":
    main()
