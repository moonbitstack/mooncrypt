#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""Emit the BIP 340 signature vectors for src/sign/schnorr.

libsecp256k1 is the reference implementation of this scheme and `coincurve`
exposes its Schnorr signing, so every vector is produced by it rather than by a
transcription. Before anything is printed, the first case is also checked against
the published values in the BIP's own test CSV, which pins the transcription of
the scheme itself and not just of the numbers.

Every vector below signs a 32-byte message: that is the only length libsecp256k1
will sign without a custom hasher, and it is the length the BIP's CSV uses.
Schema 340 itself is defined for a message of any length, which the MoonBit tests
cover by round-tripping longer and shorter ones.

Usage:
    python scripts/gen_schnorr_vectors.py
"""

import hashlib

import coincurve

# BIP 340's first test vector, transcribed from the CSV.
ANCHOR = {
    "sk": "0000000000000000000000000000000000000000000000000000000000000003",
    "pubkey": "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
    "aux": "00" * 32,
    "msg": "00" * 32,
    "sig": "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
           "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
}

ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def digest(label):
    """A fixed value per label: reproducible, arbitrary, and traceable."""
    return hashlib.sha256(label.encode()).digest()


def scalar(label):
    return (int.from_bytes(digest(label), "big") % (ORDER - 1)) + 1


CASES = [
    # The published vector, and the same key on a different message.
    (int(ANCHOR["sk"], 16), bytes.fromhex(ANCHOR["aux"]), bytes(32)),
    (int(ANCHOR["sk"], 16), bytes.fromhex(ANCHOR["aux"]), bytes(31) + b"\x01"),
    # The smallest and largest scalars that are keys at all. Both exercise the
    # parity step: a key whose point has an odd y is negated before signing.
    (1, bytes(32), digest("schnorr/one")),
    (2, bytes(32), digest("schnorr/two")),
    (ORDER - 1, bytes(32), digest("schnorr/top")),
    (ORDER - 2, digest("schnorr/aux"), digest("schnorr/top2")),
]

# Arbitrary keys and auxiliary inputs, so both the parity of the public point and
# the parity of the nonce are exercised more than once.
for i in range(6):
    CASES.append(
        (scalar("schnorr/sk/%d" % i), digest("schnorr/aux/%d" % i), digest("schnorr/msg/%d" % i))
    )


def sign(case):
    sk, aux, msg = case
    key = coincurve.PrivateKey(sk.to_bytes(32, "big"))
    pubkey = key.public_key.format(compressed=True)[1:]
    sig = key.sign_schnorr(msg, aux)
    coincurve.PublicKeyXOnly(pubkey).verify(sig, msg)
    return pubkey, sig


def check():
    pubkey, sig = sign(CASES[0])
    assert pubkey.hex().upper() == ANCHOR["pubkey"], pubkey.hex()
    assert sig.hex().upper() == ANCHOR["sig"], sig.hex()
    for case in CASES:
        sign(case)
    print("libsecp256k1 reproduces BIP 340's first test vector and verifies every case")


def main():
    check()

    for sk, aux, msg in CASES:
        pubkey, sig = sign((sk, aux, msg))
        print()
        print("  {")
        print('    sk: "%s",' % sk.to_bytes(32, "big").hex())
        print('    pubkey: "%s",' % pubkey.hex())
        print('    aux: "%s",' % aux.hex())
        print('    msg: "%s",' % msg.hex())
        print('    sig: "%s",' % sig.hex())
        print("  },")


if __name__ == "__main__":
    main()
