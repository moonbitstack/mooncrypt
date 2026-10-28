#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""A from-scratch AES-SIV (RFC 5297) used to generate the SIV test vectors.

Deliberately built on nothing but AES block encryption, so it shares no code
with any library that implements SIV and cannot inherit its bugs. It is checked
against every vector in RFC 5297 appendix A before it is used, so if the
reference is wrong the script exits instead of writing nonsense into the tests.

    python scripts/gen_siv_vectors.py
"""

import binascii
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def aes_ecb(key, block):
    """One AES block encryption."""
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def dbl(block):
    """Multiply by x in GF(2^128), RFC 5297 §2.3: shift left, then reduce."""
    out = bytearray(16)
    carry = 0
    for i in range(15, -1, -1):
        out[i] = ((block[i] << 1) & 0xFF) | carry
        carry = (block[i] >> 7) & 1
    if carry:
        out[15] ^= 0x87
    return bytes(out)


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def cmac(key, message):
    """AES-CMAC, RFC 4493, in the streaming form SIV needs."""
    k1 = dbl(aes_ecb(key, b"\x00" * 16))
    k2 = dbl(k1)
    if not message:
        return aes_ecb(key, xor(k2, b"\x80" + b"\x00" * 15))
    blocks = [message[i : i + 16] for i in range(0, len(message), 16)]
    if len(blocks[-1]) == 16:
        blocks[-1] = xor(blocks[-1], k1)
    else:
        last = blocks[-1] + b"\x80" + b"\x00" * (15 - len(blocks[-1]))
        blocks[-1] = xor(last, k2)
    state = b"\x00" * 16
    for block in blocks:
        state = aes_ecb(key, xor(state, block))
    return state


def s2v(mac_key, parts):
    """RFC 5297 §2.4: the synthetic IV."""
    if not parts:
        return aes_ecb(mac_key, b"\x00" * 16)
    state = cmac(mac_key, parts[0])
    for part in parts[1:]:
        state = xor(dbl(state), cmac(mac_key, part))
    return xor(state, cmac(mac_key, b"\x00" * 16))


def siv_encrypt(key, parts, plain):
    """Seal: the SIV followed by the ciphertext, as RFC 5297 defines it."""
    half = len(key) // 2
    mac_key, ctr_key = key[:half], key[half:]
    iv = s2v(mac_key, parts)
    # CTR mode with the SIV masked down to 127 bits and the halves swapped.
    counter = bytearray(xor(iv, bytes([iv[8] & 0x7F, iv[9], iv[10], iv[11],
                                       iv[12], iv[13], iv[14], iv[15],
                                       iv[0], iv[1], iv[2], iv[3],
                                       iv[4], iv[5], iv[6], iv[7]])))
    out = bytearray()
    for i in range(0, len(plain), 16):
        out += xor(plain[i : i + 16], aes_ecb(ctr_key, bytes(counter)))
        for j in range(15, -1, -1):
            counter[j] = (counter[j] + 1) & 0xFF
            if counter[j]:
                break
    return iv + bytes(out)


def h(text):
    return bytes.fromhex(text)


# RFC 5297 appendix A, as (key, [associated data...], plaintext, siv,
# ciphertext). The script refuses to run unless every one of these matches.
RFC_VECTORS = [
    (
        "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        ["101112131415161718191a1b1c1d1e1f2021222324252627",
         "202122232425262728292a2b2c2d2e2f3031323334353637"],
        "112233445566778899aabbccddee",
        "85632d07c6e8f37f950acd320a2ecc93",
        "40c02b9690c4dc04daef7f6afe5c",
    ),
    (
        "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        ["101112131415161718191a1b1c1d1e1f2021222324252627",
         "202122232425262728292a2b2c2d2e2f3031323334353637"],
        "112233445566778899aabbccddee",
        "85632d07c6e8f37f950acd320a2ecc93",
        "40c02b9690c4dc04daef7f6afe5c",
    ),
    (
        "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f",
        ["00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
         "102030405060708090a0",
         "09f911029d74e35bd84156c5635688c0"],
        "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553",
        "7bdb6e3b432667eb06f4d14bff2fbd0f",
        "cb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d",
    ),
]


def main():
    for key, ads, plain, siv, cipher in RFC_VECTORS:
        got = siv_encrypt(h(key), [h(a) for a in ads], h(plain))
        want = h(siv) + h(cipher)
        if got != want:
            print(
                f"RFC 5297 mismatch\n  got  {got.hex()}\n  want {want.hex()}",
                file=sys.stderr,
            )
            raise SystemExit(1)
    print("// reference agrees with RFC 5297 appendix A", file=sys.stderr)
    print(RFC_VECTORS[0][0])


if __name__ == "__main__":
    main()
