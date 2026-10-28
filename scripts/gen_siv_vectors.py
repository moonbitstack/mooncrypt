#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""Generate the SIV test vectors in src/aead/siv/siv_test.mbt.

Deliberately built on nothing but AES block encryption, so it shares no code
with any library that implements SIV and cannot inherit its bugs. It is checked
against both vectors in RFC 5297 appendix A before it is allowed to emit
anything: if the reference is wrong the script exits instead of writing nonsense
into the tests.

Note that the `cryptography` package's AESSIV does *not* agree with RFC 5297
appendix A.1 (it produces a different SIV for the published inputs), which is
exactly why the reference here is written from the RFC.

    python scripts/gen_siv_vectors.py
"""

import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def aes_ecb(key, block):
    """One AES block encryption."""
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def dbl(block):
    """Multiply by x in GF(2^128), RFC 5297 §2.3."""
    out = bytearray(16)
    carry = 0
    for i in range(15, -1, -1):
        out[i] = ((block[i] << 1) & 0xFF) | carry
        carry = (block[i] >> 7) & 1
    if carry:
        out[15] ^= 0x87
    return bytes(out)


def cmac(key, message):
    """AES-CMAC, RFC 4493."""
    k1 = dbl(aes_ecb(key, b"\x00" * 16))
    k2 = dbl(k1)
    blocks = [message[i : i + 16] for i in range(0, len(message), 16)]
    if not blocks:
        return aes_ecb(key, xor(k2, b"\x80" + b"\x00" * 15))
    if len(blocks[-1]) == 16:
        blocks[-1] = xor(blocks[-1], k1)
    else:
        padded = blocks[-1] + b"\x80" + b"\x00" * (15 - len(blocks[-1]))
        blocks[-1] = xor(padded, k2)
    state = b"\x00" * 16
    for block in blocks:
        state = aes_ecb(key, xor(state, block))
    return state


def pad(x):
    """RFC 5297 §2.1: a one bit, then zeroes, out to a block."""
    return x + b"\x80" + b"\x00" * (15 - len(x))


def xorend(a, b):
    """RFC 5297 §2.1: xor `b` onto the end of `a`."""
    return a[: len(a) - len(b)] + xor(a[len(a) - len(b) :], b)


def s2v(mac_key, parts):
    """RFC 5297 §2.4."""
    if not parts:
        return cmac(mac_key, b"\x00" * 15 + b"\x01")
    d = cmac(mac_key, b"\x00" * 16)
    for part in parts[:-1]:
        d = xor(dbl(d), cmac(mac_key, part))
    last = parts[-1]
    t = xorend(last, d) if len(last) >= 16 else xor(dbl(d), pad(last))
    return cmac(mac_key, t)


def ctr(ctr_key, iv, data):
    """RFC 5297 §2.5: clear bits 31 and 63, then count in the low 64 bits."""
    block = bytearray(iv)
    block[8] &= 0x7F
    block[12] &= 0x7F
    out = bytearray()
    for i in range(0, len(data), 16):
        out += xor(data[i : i + 16], aes_ecb(ctr_key, bytes(block)))
        for j in range(15, 7, -1):
            block[j] = (block[j] + 1) & 0xFF
            if block[j]:
                break
    return bytes(out)


def siv(key, ads, plain):
    """Seal: the SIV followed by the ciphertext, as RFC 5297 defines it."""
    half = len(key) // 2
    mac_key, ctr_key = key[:half], key[half:]
    v = s2v(mac_key, list(ads) + [plain])
    return v + ctr(ctr_key, v, plain)


def h(text):
    return bytes.fromhex(text)


# RFC 5297 appendix A: (key, [associated data...], plaintext, SIV || ciphertext).
RFC_VECTORS = [
    (
        "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        [
            "101112131415161718191a1b1c1d1e1f2021222324252627",
        ],
        "112233445566778899aabbccddee",
        "85632d07c6e8f37f950acd320a2ecc93" "40c02b9690c4dc04daef7f6afe5c",
    ),
    (
        "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f",
        [
            "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa9988"
            "7766554433221100",
            "102030405060708090a0",
            "09f911029d74e35bd84156c5635688c0",
        ],
        "7468697320697320736f6d6520706c61696e7465787420746f20656e63727970"
        "74207573696e67205349562d414553",
        "7bdb6e3b432667eb06f4d14bff2fbd0f"
        "cb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829"
        "ea64ad544a272e9c485b62a3fd5c0d",
    ),
]

KEY128 = "000102030405060708090a0b0c0d0e0f" "101112131415161718191a1b1c1d1e1f"

# (comment, key, associated data excluding the nonce, nonce, plaintext)
CASES = [
    (
        "RFC 5297 A.1: no nonce, one associated data component of two\n"
        "/// blocks, and a plaintext that is not a whole number of blocks.",
        RFC_VECTORS[0][0],
        RFC_VECTORS[0][1],
        "",
        RFC_VECTORS[0][2],
    ),
    (
        "RFC 5297 A.2: the nonce is the last associated data component, so\n"
        "/// it changes the SIV without appearing in the ciphertext.",
        RFC_VECTORS[1][0],
        RFC_VECTORS[1][1][:-1],
        RFC_VECTORS[1][1][-1],
        RFC_VECTORS[1][2],
    ),
    (
        "An empty message with no associated data, which is the shortest\n"
        "/// input S2V can be given.",
        KEY128,
        [],
        "",
        "",
    ),
    (
        "An empty message that still has associated data, so the tag\n"
        "/// commits to something.",
        KEY128,
        ["a0a1a2a3a4a5a6a7"],
        "",
        "",
    ),
    (
        "Exactly one block of plaintext, which is the boundary between the\n"
        "/// two arms of `len(Sn) >= 128` in S2V.",
        KEY128,
        ["cafebabe"],
        "",
        "00112233445566778899aabbccddeeff",
    ),
    (
        "One byte past that boundary.",
        KEY128,
        ["cafebabe"],
        "",
        "00112233445566778899aabbccddeeff00",
    ),
    (
        "Four associated data components, more than the two RFC 5297\n"
        "/// exercises, so the doubling chain is walked further. One of them\n"
        "/// is empty.",
        KEY128,
        ["deadbeef", "", "0badc0de", "00112233445566778899aabbccddeeff"],
        "",
        "48656c6c6f2c2053495621",
    ),
    (
        "Associated data long enough to need several blocks, with a\n"
        "/// nonce and a plaintext that is not aligned.",
        KEY128,
        [
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
            "202122232425262728292a2b2c2d2e2f"
        ],
        "f0f1f2f3f4f5",
        "48656c6c6f2c2053495621",
    ),
    (
        "A 192-bit key, so both halves are AES-192.",
        "000102030405060708090a0b0c0d0e0f1011121314151617"
        "18191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
        ["a1b2c3"],
        "0102030405060708090a0b0c",
        "00112233445566778899aabbccddeeff",
    ),
    (
        "A 512-bit key, so both halves are AES-256.",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        ["a1b2c3"],
        "0102030405060708090a0b0c",
        "00112233445566778899aabbccddeeff",
    ),
    (
        "A message several blocks long, so the counter carries past a block\n"
        "/// boundary.",
        KEY128,
        ["ad"],
        "",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f3031323334353637",
    ),
]


def comment(text):
    lines = [line.removeprefix("///").strip() for line in text.split("\n")]
    return "".join(f"    // {line}\n" for line in lines)


def main():
    for key, ads, plain, want in RFC_VECTORS:
        got = siv(h(key), [h(a) for a in ads], h(plain))
        if got.hex() != want:
            print(
                f"RFC 5297 mismatch\n  got  {got.hex()}\n  want {want}",
                file=sys.stderr,
            )
            raise SystemExit(1)
    print("reference agrees with RFC 5297 appendix A", file=sys.stderr)

    out = []
    for text, key, ads, nonce, plain in CASES:
        vector = [h(a) for a in ads] + ([h(nonce)] if nonce else [])
        want = siv(h(key), vector, h(plain))
        body = ",\n".join(
            [
                f'    key: "{key}"',
                "    ads: [" + ", ".join(f'"{a}"' for a in ads) + "]",
                f'    nonce: "{nonce}"',
                f'    plain: "{plain}"',
                f'    expected: "{want.hex()}"',
            ]
        )
        out.append(f"  {{\n{comment(text)}{body},\n  }}")
    print("let cases : Array[Case] = [")
    print(",\n".join(out))
    print("]")


if __name__ == "__main__":
    main()
