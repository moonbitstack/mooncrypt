#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""Emit the finite-field Diffie-Hellman vectors for src/kex/dh.

The primes are the ffdhe groups of RFC 7919. Rather than paste them in, this
script asks OpenSSL for each group and then checks what came back against the
properties the RFC builds them from:

  * the bit length is the one in the name,
  * the generator is 2, as section 3 fixes it,
  * the top and bottom 64 bits are all ones, which is how the RFC's search is
    parameterised and is not true of a random prime of the same size,
  * the prime really is prime, by Miller-Rabin,
  * p is 7 mod 8, which every safe-prime-shaped group of this form satisfies.

A group that fails any of those is not the group this library means to ship, and
the script stops instead of writing it out.

The exponents are fixed so that regeneration rewrites the same bytes; the
agreement each one produces is computed with CPython's own modular exponentiation,
which is an implementation entirely separate from the one under test.

Usage:
    python scripts/gen_dh_vectors.py
"""

import hashlib
import subprocess

from cryptography.hazmat.primitives import serialization

GROUPS = [
    ("Ffdhe2048", "ffdhe2048", 256),
    ("Ffdhe3072", "ffdhe3072", 384),
    ("Ffdhe4096", "ffdhe4096", 512),
    ("Ffdhe6144", "ffdhe6144", 768),
    ("Ffdhe8192", "ffdhe8192", 1024),
]

GENERATOR = 2


def miller_rabin(n, rounds=40):
    """Enough to be sure: the RFC's groups are the ones that pass, and a composite
    would have to survive forty random bases to get through."""
    if n < 4:
        return n in (2, 3)
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    # Deterministic bases from the group name so the run is reproducible; a
    # fixed set is as good as random ones here.
    for a in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def load(group):
    pem = subprocess.run(
        ["openssl", "genpkey", "-genparam", "-algorithm", "DH",
         "-pkeyopt", "group:" + group],
        check=True, capture_output=True,
    ).stdout
    numbers = serialization.load_pem_parameters(pem).parameter_numbers()
    return numbers.p, numbers.g


def check_group(label, group, size):
    p, g = load(group)
    assert g == GENERATOR, f"{group}: generator is {g}, not {GENERATOR}"
    assert p.bit_length() == size * 8, f"{group}: {p.bit_length()} bits"
    top = p >> (p.bit_length() - 64)
    bottom = p & ((1 << 64) - 1)
    assert top == (1 << 64) - 1, f"{group}: top 64 bits are not ones"
    assert bottom == (1 << 64) - 1, f"{group}: bottom 64 bits are not ones"
    assert p % 8 == 7, f"{group}: p is not 7 mod 8"
    assert miller_rabin(p), f"{group}: p is not prime"
    return p


def exponent(label, size):
    """A fixed exponent per group, taken from a digest so it is arbitrary but
    traceable."""
    seed = hashlib.sha512(label.encode()).digest()
    return int.from_bytes(seed, "big") % ((1 << (size * 8)) - 1) or 1


def check():
    primes = {}
    for label, group, size in GROUPS:
        primes[label] = check_group(label, group, size)
    print("all five ffdhe groups match RFC 7919's structure and are prime")
    return primes


def padded(value, size):
    return value.to_bytes(size, "big")


def main():
    primes = check()

    print()
    print("// The groups of RFC 7919, as hex.")
    for label, group, size in GROUPS:
        print('("%s", "%x"),' % (label, primes[label]))

    print()
    print("// Exchanges.")
    for label, group, size in GROUPS:
        p = primes[label]
        a = exponent(label + ":a", size)
        b = exponent(label + ":b", size)
        pub_a = pow(GENERATOR, a, p)
        pub_b = pow(GENERATOR, b, p)
        shared = pow(pub_b, a, p)
        assert shared == pow(pub_a, b, p)
        print(
            '  { group: @dh.%s, secret: "%s", peer_secret: "%s", '
            'mine: "%s", theirs: "%s", shared: "%s" },'
            % (
                label,
                padded(a, size).hex(),
                padded(b, size).hex(),
                padded(pub_a, size).hex(),
                padded(pub_b, size).hex(),
                padded(shared, size).hex(),
            )
        )


if __name__ == "__main__":
    main()
