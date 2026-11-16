#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""Emit the OpenSSL cross-check vectors for src/cipher/aria, seed and idea.

The ciphers themselves are written from their specifications (RFC 5794, RFC 4269, Lai and
Massey's paper) and pinned by the examples those carry. These vectors are the second check:
each key and block is put through OpenSSL's own implementation, which shares no code with
mooncrypt. SEED and IDEA live in OpenSSL's legacy provider.

Usage:
    python scripts/gen_legacy_block_vectors.py
"""

import hashlib
import subprocess


def openssl(cipher: str, key: str, plain: str) -> str:
    args = ["openssl", "enc", f"-{cipher}", "-K", key, "-nopad", "-nosalt"]
    if not cipher.startswith("aria"):
        args += ["-provider", "legacy", "-provider", "default"]
    out = subprocess.run(args, input=bytes.fromhex(plain), capture_output=True, check=True)
    return out.stdout.hex()


def derived(label: str, hexdigits: int) -> str:
    return hashlib.sha512(label.encode()).hexdigest()[:hexdigits]


def main() -> None:
    plain = derived("aria block", 64)
    for bits in (128, 192, 256):
        key = hashlib.sha256(b"aria key %d" % bits).hexdigest()[: bits // 4]
        print(f"aria-{bits}", key, plain, openssl(f"aria-{bits}-ecb", key, plain))
    key = hashlib.sha256(b"seed key").hexdigest()[:32]
    plain = derived("seed block", 64)
    print("seed", key, plain, openssl("seed-ecb", key, plain))
    key = hashlib.sha256(b"idea key").hexdigest()[:32]
    plain = derived("idea block", 48)
    print("idea", key, plain, openssl("idea-ecb", key, plain))
    for key, plain in (("00" * 16, "00" * 8), ("ff" * 16, "ff" * 8)):
        print("idea", key, plain, openssl("idea-ecb", key, plain))


if __name__ == "__main__":
    main()
