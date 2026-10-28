#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""Emit the Concat KDF vectors for src/kdf/concat.

Two references have to agree before anything is printed: a five-line transcription
of SP 800-56A section 5.8.1, and `cryptography`'s ConcatKDFHash. The first is the
thing under test's twin; the second is somebody else's reading of the same
paragraph, which is what makes the agreement worth something.

Usage:
    python scripts/gen_concat_vectors.py
"""

import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

ALGOS = {
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}

CRYPTO_HASHES = {
    "sha1": hashes.SHA1,
    "sha256": hashes.SHA256,
    "sha512": hashes.SHA512,
}


def concat(z, other_info, length, algo):
    """SP 800-56A 5.8.1: H(counter || Z || OtherInfo), counter big-endian from 1."""
    out = b""
    counter = 1
    while len(out) < length:
        out += algo(counter.to_bytes(4, "big") + z + other_info).digest()
        counter += 1
    return out[:length]


# The inputs are all derived from a range so that no length can be miscounted,
# and the lengths are picked to land on, just under and just over a block
# boundary for every digest size in play.
CASES = [
    ("sha256", 32, 0, 32),
    ("sha256", 32, 0, 31),
    ("sha256", 32, 0, 33),
    ("sha256", 32, 8, 16),
    ("sha256", 32, 64, 96),
    ("sha256", 1, 0, 1),
    ("sha1", 20, 0, 20),
    ("sha1", 20, 0, 21),
    ("sha1", 20, 12, 40),
    ("sha512", 64, 0, 64),
    ("sha512", 64, 0, 65),
    ("sha512", 64, 5, 200),
]


def check():
    for name, zlen, olen, length in CASES:
        z = bytes(range(zlen))
        info = bytes(range(olen))
        mine = concat(z, info, length, ALGOS[name])
        theirs = ConcatKDFHash(
            algorithm=CRYPTO_HASHES[name](), length=length, otherinfo=info
        ).derive(z)
        assert mine == theirs, (
            f"{name} z={zlen} other={olen} len={length}: "
            f"{mine.hex()} != {theirs.hex()}"
        )
    print("Concat KDF reference agrees with cryptography on every case")


def main():
    check()

    print()
    for name, zlen, olen, length in CASES:
        z = bytes(range(zlen))
        info = bytes(range(olen))
        digest = concat(z, info, length, ALGOS[name])
        print(
            '  { hash: "%s", z: "%s", other: "%s", len: %d, expected: "%s" },'
            % (name, z.hex(), info.hex(), length, digest.hex())
        )


if __name__ == "__main__":
    main()
