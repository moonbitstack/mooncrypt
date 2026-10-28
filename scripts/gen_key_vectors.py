#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""Emit the key-encoding vectors for src/key.

The DER writer below is written out from X.690 by hand rather than taken from
`cryptography`, and then every blob it produces is checked against the bytes
`cryptography` emits for the same key before anything is printed. That gives two
independent encoders agreeing on the test data, which is what makes the vectors
worth asserting against.

The RSA key is 1024-bit. The size has nothing to do with the encoding — a larger
key would be a longer file and the same DER — and a smaller one keeps the test
readable.

Usage:
    python scripts/gen_key_vectors.py
"""

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization


# --- X.690 writer, hand-written -------------------------------------------


def tlv(tag, body):
    n = len(body)
    if n < 128:
        length = bytes([n])
    else:
        digits = []
        while n:
            digits.append(n & 0xFF)
            n >>= 8
        length = bytes([0x80 | len(digits)]) + bytes(reversed(digits))
    return bytes([tag]) + length + body


def der_int(value):
    if value == 0:
        return tlv(0x02, b"\x00")
    body = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return tlv(0x02, body)


def der_oid(arcs):
    body = bytes([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        digits = []
        n = arc
        digits.append(n & 0x7F)
        n >>= 7
        while n:
            digits.append((n & 0x7F) | 0x80)
            n >>= 7
        body += bytes(reversed(digits))
    return tlv(0x06, body)


def der_seq(*parts):
    return tlv(0x30, b"".join(parts))


def der_octets(b):
    return tlv(0x04, b)


def der_bits(b):
    return tlv(0x03, b"\x00" + b)


def der_null():
    return tlv(0x05, b"")


RSA_OID = [1, 2, 840, 113549, 1, 1, 1]
EC_OID = [1, 2, 840, 10045, 2, 1]
CURVES = {
    "P256": [1, 2, 840, 10045, 3, 1, 7],
    "Secp256k1": [1, 3, 132, 0, 10],
}


def pkcs1_public(n, e):
    return der_seq(der_int(n), der_int(e))


def pkcs1_private(numbers):
    n, e, d, p, q, dp, dq, qinv = numbers
    return der_seq(
        der_int(0), der_int(n), der_int(e), der_int(d), der_int(p),
        der_int(q), der_int(dp), der_int(dq), der_int(qinv),
    )


def pkcs8(pkcs1):
    return der_seq(
        der_int(0),
        der_seq(der_oid(RSA_OID), der_null()),
        der_octets(pkcs1),
    )


def spki(pkcs1_pub):
    return der_seq(
        der_seq(der_oid(RSA_OID), der_null()),
        der_bits(pkcs1_pub),
    )


def sec1(scalar, point, curve="P256"):
    return der_seq(
        der_int(1),
        der_octets(scalar),
        tlv(0xA0, der_oid(CURVES[curve])),
        tlv(0xA1, der_bits(point)),
    )


def spki_ec(point, curve="P256"):
    return der_seq(
        der_seq(der_oid(EC_OID), der_oid(CURVES[curve])),
        der_bits(point),
    )


# --- keys and cross-checks -------------------------------------------------

# The key material is pinned rather than generated, because this script has to be
# reproducible: re-running it must rewrite the file the test asserts against with
# the same bytes. A fresh key each run would turn every regeneration into a diff
# of several thousand hex digits that nobody can review.
#
# These are the numbers of an ordinary 1024-bit RSA key, and a P-256 scalar taken
# from the first 32 bytes of a SHA-256 digest so that its provenance is at least
# checkable.
N = 0xd2977f84e364ac3c76f78bf7e47cd02dc70634e768d393fe2a6df95c92ff17204cae9fa2a00a6614915b2c8eaf126427da92fc68a67a2e96cdc77f6840dc9c8ef27f6fdb681ca30d3e305e4ecd5c0edd41df7d43c94dddfbe950f35bc5d92d65105db13f5d99ea4c19154ea20b9c386c58c158ea75e4f8615a8dfe364290e051
E = 0x10001
D = 0x5e57e098f80631e324a8e1dbbc50ee3293e703ec67d9e1830c1f188790931719314149e2e12fc76b8f72f91332fb5a43407878fba91933a5fbaa5439b055250d549f5794778cd93b8dcf927e99ba87b3c394df9e30ffe928eb743b9418be1d0208fbed729fa4dffe75fadf94b3d4b5c9d52274f77dcee9eb2741b8196aa073d
P = 0xf9ae700dfc181a9aed775828c517bead71b00a4d9bd8f836e3bdf2f7d594b48968a4d92bfccdf03e439b7ea098e55501d5cd913752f7b712ddeb5b66a6f06a4b
Q = 0xd7ebd173b992d36dedda5d37ec2554630de9aa9965f97b869eeb875cece6647d03f4a336d6c1a7fe4bd689b25102b299b5c41e8706f811c91b0182119278fe53
DP = 0xebc1b478e002fa8c3391af22c007cdba04514f493cd1407ec3c885f5522cd9d3ad858ab2a840e48a46583ad6f5c805de77bd655331fa49597d4650c5baf7e3c5
DQ = 0xcc673094061449d5223aface4ade17e1e1b4d7cc79edd0936374826364dcc23a5af9475d4db66c6b5eadcd12a280144550fe450bfc7bf09259df769b5df6ee83
QINV = 0x10326a27eed868f4fad369910bb15e378631a36902eb2e145e285b8c378822d21b4f9a29b3bf2b7be930e2076e5122ef20682b7bb59a177a8edc26c82f33c1d2

EC_SCALAR = 0xb5662bf47a5fbac373388adfb6781a28f4420a47b2e64cf596dbc6dd30a4f8a4


def rsa_key():
    """The pinned key, rebuilt from its numbers."""
    pub = rsa.RSAPublicNumbers(E, N)
    return rsa.RSAPrivateNumbers(P, Q, D, DP, DQ, QINV, pub).private_key()


def check():
    rsa_key_ = rsa_key()
    numbers = (N, E, D, P, Q, DP, DQ, QINV)

    mine_pub = pkcs1_public(N, E)
    mine_priv = pkcs1_private(numbers)
    theirs_pub = rsa_key_.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
    theirs_priv = rsa_key_.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption())
    assert mine_pub == theirs_pub, "PKCS#1 public key disagrees"
    assert mine_priv == theirs_priv, "PKCS#1 private key disagrees"

    mine_pkcs8 = pkcs8(mine_priv)
    theirs_pkcs8 = rsa_key_.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    assert mine_pkcs8 == theirs_pkcs8, "PKCS#8 disagrees"

    mine_spki = spki(mine_pub)
    theirs_spki = rsa_key_.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    assert mine_spki == theirs_spki, "SubjectPublicKeyInfo disagrees"

    # An EC key: the scalar and the uncompressed point.
    ec_key = ec.derive_private_key(EC_SCALAR, ec.SECP256R1())
    scalar = EC_SCALAR.to_bytes(32, "big")
    point = ec_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint)
    mine_sec1 = sec1(scalar, point)
    theirs_sec1 = ec_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption())
    assert mine_sec1 == theirs_sec1, "SEC1 EC private key disagrees"

    mine_ec_spki = spki_ec(point)
    theirs_ec_spki = ec_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    assert mine_ec_spki == theirs_ec_spki, "EC SubjectPublicKeyInfo disagrees"

    print("hand-written DER agrees with cryptography on all six formats")
    return numbers, mine_pub, mine_priv, mine_pkcs8, mine_spki, scalar, point, mine_sec1, mine_ec_spki


def hexlit(b):
    return b.hex()


def even_hex(value):
    """Hex with an even number of digits.

    A DER INTEGER drops its leading zero bytes while the *number* does not always
    fill a whole number of them: 65537 is 0x10001, five digits, and a hex decoder
    given an odd count has to guess. Padding to a byte boundary is what the
    upstream encoding does anyway.
    """
    text = format(value, "x")
    return text if len(text) % 2 == 0 else "0" + text


def main():
    (numbers, pub_der, priv_der, pkcs8_der, spki_der,
     scalar, point, sec1_der, ec_spki) = check()
    n, e, d, p, q, dp, dq, qinv = numbers

    print()
    print("// RSA numbers")
    for name, value in [
        ("modulus", n), ("exponent", e), ("private_exponent", d),
        ("prime1", p), ("prime2", q), ("exponent1", dp),
        ("exponent2", dq), ("coefficient", qinv),
    ]:
        print('  ("%s", "%s"),' % (name, even_hex(value)))

    print()
    print("// RSA DER")
    for name, blob in [
        ("rsa_public", pub_der), ("rsa_private", priv_der),
        ("rsa_pkcs8", pkcs8_der), ("rsa_spki", spki_der),
    ]:
        print('  ("%s", "%s"),' % (name, hexlit(blob)))

    print()
    print("// EC")
    for name, blob in [
        ("ec_scalar", scalar), ("ec_point", point),
        ("ec_sec1", sec1_der), ("ec_spki", ec_spki),
    ]:
        print('  ("%s", "%s"),' % (name, blob.hex()))


if __name__ == "__main__":
    main()
