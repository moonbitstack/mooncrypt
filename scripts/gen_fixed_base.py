"""Emit the fixed-base tables for src/internal/ec.

A signature is `[k]G` with the base point fixed, and so is a key pair. The comb
method (Lim-Lee) turns that into a precomputation problem: writing the scalar as
`k = sum_j 2^j (sum_i b_{i d + j} 2^i)`, the table

    T[c] = sum over the set bits i of c of 2^{i d} G

answers each column with one lookup, so the multiplication costs `d - 1`
doublings and `d` additions instead of one doubling per scalar bit. With `w = 5`
and `d = ceil(bits(n) / 5)` that is 51 doublings on P-256 rather than 256.

The table is public data about the curve, so it is computed here and stored in
Montgomery form — the same `R = 2^(32k)` the field uses — which keeps the
runtime path free of conversions.

Usage: python scripts/gen_fixed_base.py > src/internal/ec/fixed_base.mbt
"""

from __future__ import annotations

import sys
from math import ceil

# The window, in bits. Five keeps the table at 32 points, which is small enough
# that scanning all of it — the constant-time read — stays cheaper than the
# arithmetic it saves.
W = 5

# name, p, a, b, n, gx, gy — FIPS 186-4 §D.1.2, SEC 2 v2 §2.4.1, RFC 5639.
CURVES = [
    (
        "p256",
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
    ),
    (
        "p384",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
        "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
        "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
        "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
    ),
    (
        "p521",
        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
        "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
        "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
        "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
    ),
    (
        "secp256k1",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000007",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
    ),
    # RFC 5639 §3.2–3.4. `a` is arbitrary on these, so the doubling has no
    # shortcut, but the comb does not care what `a` is: it only needs the base
    # point fixed.
    (
        "brainpool_p256",
        "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
        "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
        "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
        "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7",
        "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
        "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
    ),
    (
        "brainpool_p384",
        "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
        "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
        "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",
        "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565",
        "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E",
        "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315",
    ),
    (
        "brainpool_p512",
        "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
        "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
        "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
        "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069",
        "81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822",
        "7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",
    ),
]


def limbs(value: int, k: int) -> list[int]:
    """`value` as `k` little-endian 32-bit limbs."""
    return [(value >> (32 * i)) & 0xFFFFFFFF for i in range(k)]


class Curve:
    def __init__(self, p, a, b, n, gx, gy):
        self.p, self.a, self.b, self.n = p, a, b, n
        self.g = (gx, gy)

    def add(self, one, two):
        if one is None:
            return two
        if two is None:
            return one
        (x1, y1), (x2, y2) = one, two
        if x1 == x2:
            if (y1 + y2) % self.p == 0:
                return None
            lam = (3 * x1 * x1 + self.a) * pow(2 * y1, -1, self.p) % self.p
        else:
            lam = (y2 - y1) * pow(x2 - x1, -1, self.p) % self.p
        x3 = (lam * lam - x1 - x2) % self.p
        return (x3, (lam * (x1 - x3) - y1) % self.p)

    def mul(self, k, point):
        acc, addend = None, point
        while k:
            if k & 1:
                acc = self.add(acc, addend)
            addend = self.add(addend, addend)
            k >>= 1
        return acc


def comb_table(c: Curve, w: int, d: int):
    """T[c] for c in [0, 2^w): the multiples `2^(i d) G` combined by the bits."""
    strides = []
    step = c.g
    for _ in range(w):
        strides.append(step)
        step = c.mul(pow(2, d, c.n), step)
    table = []
    for entry in range(1 << w):
        acc = None
        for i in range(w):
            if entry >> i & 1:
                acc = c.add(acc, strides[i])
        table.append(acc)
    return table


def check(c: Curve, table, w: int, d: int) -> None:
    """Three conditions, in the order the README asks for them.

    The first two are independent of the arithmetic that built the table: `T[1]`
    has to be the generator the specification prints, and every entry has to
    satisfy the curve equation. The third runs the loop the runtime will run, so
    the indexing convention is checked rather than assumed.
    """
    if table[1] != c.g:
        raise SystemExit("T[1] is not the published generator")
    for point in table:
        if point is None:
            continue
        x, y = point
        if (y * y - (x * x * x + c.a * x + c.b)) % c.p:
            raise SystemExit(f"table entry ({x:#x}, {y:#x}) is not on the curve")

    for k in [1, 2, 3, 255, 65537, c.n - 1, (c.n // 3), 0xDEADBEEF]:
        acc = None
        for j in range(d - 1, -1, -1):
            if j < d - 1:
                acc = c.add(acc, acc)
            row = 0
            for i in range(w):
                if k >> (i * d + j) & 1:
                    row |= 1 << i
            acc = c.add(acc, table[row])
        want = c.mul(k, c.g)
        if acc != want:
            raise SystemExit(f"comb disagrees with double-and-add at k={k:#x}")


def main() -> None:
    # The file is committed with LF endings, and the redirect would otherwise
    # write the platform's own.
    sys.stdout.reconfigure(newline="\n")
    curves = []
    for name, p, a, b, n, gx, gy in CURVES:
        curves.append(
            (name, Curve(int(p, 16), int(a, 16), int(b, 16), int(n, 16), int(gx, 16), int(gy, 16)))
        )

    out = sys.stdout
    out.write("// Copyright 2026 Leo Cheng\n")
    out.write("// SPDX-License-Identifier: Apache-2.0\n")
    out.write("\n")
    out.write("// Generated by `scripts/gen_fixed_base.py` — do not edit.\n")
    out.write("//\n")
    out.write("// The comb tables: `T[c]` is the sum of `2^(i d) G` over the set bits `i`\n")
    out.write("// of `c`, with `d = ceil(bits(n) / WINDOW)`. Each point is stored as `x` then\n")
    out.write("// `y`, `k` limbs each, in Montgomery form and little-endian, so the runtime\n")
    out.write("// reads it straight into the field.\n")
    out.write("\n")
    out.write("///|\n")
    out.write("/// The window the tables were built for.\n")
    out.write(f"let fixed_window : Int32 = {W}\n")

    for name, c in curves:
        k = (c.p.bit_length() + 31) // 32
        d = ceil(c.n.bit_length() / W)
        table = comb_table(c, W, d)
        check(c, table, W, d)
        r = 1 << (32 * k)
        out.write("\n///|\n")
        out.write(f"/// `{name}`, {len(table)} entries of {2 * k} limbs.\n")
        out.write(f"let {name}_fixed : FixedArray[UInt64] = [\n")
        flat = []
        for entry in table:
            if entry is None:
                entry = (0, 0)
            for part in entry:
                flat.extend(limbs(part * r % c.p, k))
        # Six to a line: `moon fmt` packs the list to its own width, and a
        # generated file that the formatter would rewrite is a file the docs
        # check fails on.
        width = 6
        for start in range(0, len(flat), width):
            chunk = flat[start : start + width]
            out.write("  " + ", ".join(f"0x{w:08X}UL" for w in chunk) + ",\n")
        out.write("]\n")
        print(
            f"{name}: d={d}, {len(table)} entries, {2 * k} limbs each",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
