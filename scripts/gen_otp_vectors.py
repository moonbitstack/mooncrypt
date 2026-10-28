#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""Emit the one-time-password vectors for src/otp.

Both RFCs publish their test tables in full, so the whole file is a transcription
of them: RFC 4226 appendix D for the counter-based codes, RFC 6238 appendix B for
the time-based ones. The transcription is not trusted on its own — the reference
below recomputes every code from the definition and has to agree with each
published row before a single line is printed.

Usage:
    python scripts/gen_otp_vectors.py
"""

import hashlib
import hmac


def hotp(secret, counter, digits=6, algo=hashlib.sha1):
    """RFC 4226 §5.3, written out rather than taken from a library."""
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(secret, msg, algo).digest()
    # Dynamic truncation: the low nibble of the last byte picks the offset, and
    # the top bit of the four bytes read from there is masked off so the result
    # is a positive 31-bit number on every platform.
    offset = digest[-1] & 0x0F
    binary = (
        ((digest[offset] & 0x7F) << 24)
        | (digest[offset + 1] << 16)
        | (digest[offset + 2] << 8)
        | digest[offset + 3]
    )
    return str(binary % 10**digits).zfill(digits)


# RFC 4226 appendix D: the shared secret is the ASCII digits 1..0 twice.
HOTP_SECRET = b"12345678901234567890"

RFC4226 = {
    0: "755224",
    1: "287082",
    2: "359152",
    3: "969429",
    4: "338314",
    5: "254676",
    6: "287922",
    7: "162583",
    8: "399871",
    9: "520489",
}

# RFC 6238 appendix B. Each hash gets its own seed, because the seeds are
# different lengths: 20, 32 and 64 bytes.
TOTP_SEEDS = {
    "sha1": b"12345678901234567890",
    "sha256": b"12345678901234567890123456789012",
    "sha512": b"1234567890123456789012345678901234567890123456789012345678901234",
}

TOTP_TIMES = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000]

RFC6238 = {
    "sha1": ["94287082", "07081804", "14050471", "89005924", "69279037", "65353130"],
    "sha256": ["46119246", "68084774", "67062674", "91819424", "90698825", "77737706"],
    "sha512": ["90693936", "25091201", "99943326", "93441116", "38618901", "47863826"],
}

ALGOS = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha512": hashlib.sha512}


def check():
    for counter, want in RFC4226.items():
        got = hotp(HOTP_SECRET, counter)
        assert got == want, f"HOTP counter {counter}: {got} != {want}"

    for name, want in RFC6238.items():
        seed = TOTP_SEEDS[name]
        for at, expect in zip(TOTP_TIMES, want):
            got = hotp(seed, at // 30, 8, ALGOS[name])
            assert got == expect, f"TOTP {name} at {at}: {got} != {expect}"

    print("reference reproduces RFC 4226 appendix D and RFC 6238 appendix B")


def main():
    check()

    print()
    print("// RFC 4226 appendix D")
    for counter, want in RFC4226.items():
        print('  { counter: %dUL, expected: "%s" },' % (counter, want))

    print()
    print("// RFC 6238 appendix B")
    for name, want in RFC6238.items():
        for at, expect in zip(TOTP_TIMES, want):
            print(
                '  { hash: "%s", time: %dUL, expected: "%s" },'
                % (name, at, expect)
            )


if __name__ == "__main__":
    main()
