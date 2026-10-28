#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""Generate the XChaCha20 test vectors in src/cipher/xchacha20/xchacha20_test.mbt.

From scratch, on nothing but integer arithmetic: the twenty rounds, the
feed-forward, HChaCha20 and the counter mode are all written out here, so this
shares no code with any library that implements ChaCha20. Before it emits
anything it is checked against the HChaCha20 vector in draft-irtf-cfrg-xchacha
§2.2.1 and both XChaCha20 vectors in appendix A.3.2, so a mistake here fails the
script instead of quietly becoming the expected output of a test.

    python scripts/gen_xchacha20_vectors.py
"""

import sys

MASK = 0xFFFFFFFF

SIGMA = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]


def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK


def quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & MASK
    s[d] = rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK
    s[b] = rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & MASK
    s[d] = rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK
    s[b] = rotl(s[b] ^ s[c], 7)


def rounds(s):
    for _ in range(10):
        quarter(s, 0, 4, 8, 12)
        quarter(s, 1, 5, 9, 13)
        quarter(s, 2, 6, 10, 14)
        quarter(s, 3, 7, 11, 15)
        quarter(s, 0, 5, 10, 15)
        quarter(s, 1, 6, 11, 12)
        quarter(s, 2, 7, 8, 13)
        quarter(s, 3, 4, 9, 14)


def words(data):
    return [int.from_bytes(data[i : i + 4], "little") for i in range(0, len(data), 4)]


def unwords(ws):
    return b"".join(w.to_bytes(4, "little") for w in ws)


def hchacha20(key, nonce):
    """draft-irtf-cfrg-xchacha §2.2."""
    assert len(key) == 32 and len(nonce) == 16
    s = SIGMA + words(key) + words(nonce)
    rounds(s)
    return unwords([s[0], s[1], s[2], s[3], s[12], s[13], s[14], s[15]])


def chacha20_block(key, counter, nonce):
    """RFC 8439 §2.3, with the twelve-byte IETF nonce."""
    assert len(key) == 32 and len(nonce) == 12
    init = SIGMA + words(key) + [counter & MASK] + words(nonce)
    s = list(init)
    rounds(s)
    return unwords([(s[i] + init[i]) & MASK for i in range(16)])


def chacha20(key, counter, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        stream = chacha20_block(key, counter + i // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[i : i + 64], stream))
    return bytes(out)


def xchacha20(key, nonce, data, counter=0):
    """draft-irtf-cfrg-xchacha §2.3."""
    assert len(nonce) == 24
    subkey = hchacha20(key, nonce[:16])
    return chacha20(subkey, counter, b"\x00" * 4 + nonce[16:], data)


def h(text):
    return bytes.fromhex(text)


# draft-irtf-cfrg-xchacha §2.2.1: key, nonce, expected subkey.
HCHACHA_VECTOR = (
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "000000090000004a0000000031415927",
    "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc",
)

# draft-irtf-cfrg-xchacha appendix A.3.2: one key and nonce, two counters.
A3_KEY = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
A3_NONCE = "404142434445464748494a4b4c4d4e4f5051525354555658"
A3_PLAIN = (
    "5468652064686f6c65202870726f6e6f756e6365642022646f6c652229206973"
    "20616c736f206b6e6f776e2061732074686520417369617469632077696c6420"
    "646f672c2072656420646f672c20616e642077686973746c696e6720646f672e"
    "2049742069732061626f7574207468652073697a65206f662061204765726d61"
    "6e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061"
    "206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c"
    "757369766520616e6420736b696c6c6564206a756d70657220697320636c6173"
    "736966696564207769746820776f6c7665732c20636f796f7465732c206a6163"
    "6b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d6963"
    "2066616d696c792043616e696461652e"
)
A3_COUNTER_0 = (
    "4559abba4e48c16102e8bb2c05e6947f50a786de162f9b0b7e592a9b53d0d4e9"
    "8d8d6410d540a1a6375b26d80dace4fab52384c731acbf16a5923c0c48d3575d"
    "4d0d2c673b666faa731061277701093a6bf7a158a8864292a41c48e3a9b4c0da"
    "ece0f8d98d0d7e05b37a307bbb66333164ec9e1b24ea0d6c3ffddcec4f68e744"
    "3056193a03c810e11344ca06d8ed8a2bfb1e8d48cfa6bc0eb4e2464b74814240"
    "7c9f431aee769960e15ba8b96890466ef2457599852385c661f752ce20f9da0c"
    "09ab6b19df74e76a95967446f8d0fd415e7bee2a12a114c20eb5292ae7a349ae"
    "577820d5520a1f3fb62a17ce6a7e68fa7c79111d8860920bc048ef43fe84486c"
    "cb87c25f0ae045f0cce1e7989a9aa220a28bdd4827e751a24a6d5c62d790a663"
    "93b93111c1a55dd7421a10184974c7c5"
)
A3_COUNTER_1 = (
    "7d0a2e6b7f7c65a236542630294e063b7ab9b555a5d5149aa21e4ae1e4fbce87"
    "ecc8e08a8b5e350abe622b2ffa617b202cfad72032a3037e76ffdcdc4376ee05"
    "3a190d7e46ca1de04144850381b9cb29f051915386b8a710b8ac4d027b8b050f"
    "7cba5854e028d564e453b8a968824173fc16488b8970cac828f11ae53cabd201"
    "12f87107df24ee6183d2274fe4c8b1485534ef2c5fbc1ec24bfc3663efaa08bc"
    "047d29d25043532db8391a8a3d776bf4372a6955827ccb0cdd4af403a7ce4c63"
    "d595c75a43e045f0cce1f29c8b93bd65afc5974922f214a40b7c402cdb91ae73"
    "c0b63615cdad0480680f16515a7ace9d39236464328a37743ffc28f4ddb324f4"
    "d0f5bbdc270c65b1749a6efff1fbaa09536175ccd29fb9e6057b307320d31683"
    "8a9c71f70b5b5907a66f7ea49aadc409"
)

# (comment, key, nonce, counter, plaintext)
CASES = [
    (
        "draft-irtf-cfrg-xchacha §A.3.2.1: a 162-byte message starting at\n"
        "/// counter 0, so the keystream runs for three blocks.",
        A3_KEY,
        A3_NONCE,
        0,
        A3_PLAIN,
    ),
    (
        "The same key, nonce and message starting at counter 1, which must\n"
        "/// produce something entirely different — one block of keystream is\n"
        "/// skipped.",
        A3_KEY,
        A3_NONCE,
        1,
        A3_PLAIN,
    ),
    (
        "An empty message, which produces no keystream at all and must not\n"
        "/// fail.",
        A3_KEY,
        A3_NONCE,
        0,
        "",
    ),
    (
        "An all-zero key and nonce, the weakest input the cipher will ever\n"
        "/// be handed.",
        "00" * 32,
        "00" * 24,
        0,
        "00" * 64,
    ),
    (
        "Exactly one block, so the counter is used once and never\n"
        "/// incremented.",
        A3_KEY,
        A3_NONCE,
        0,
        "00" * 64,
    ),
    (
        "One byte, the shortest non-empty message.",
        A3_KEY,
        A3_NONCE,
        0,
        "ff",
    ),
    (
        "A counter near the top of its range, to check that it is used as a\n"
        "/// full thirty-two bit word rather than being truncated.",
        A3_KEY,
        A3_NONCE,
        0xFFFFFFFE,
        "00" * 96,
    ),
    (
        "A nonce whose halves are unrelated: only the first sixteen bytes\n"
        "/// go into the subkey and only the last eight become the ChaCha20\n"
        "/// nonce, so swapping them must not go unnoticed.",
        A3_KEY,
        "000102030405060708090a0b0c0d0e0f1011121314151617",
        0,
        "48656c6c6f2c2058436861436861323021",
    ),
    (
        "A message of 2 blocks plus one byte with a nonce that differs from\n"
        "/// the draft's only in its last byte.",
        A3_KEY,
        "404142434445464748494a4b4c4d4e4f5051525354555659",
        0,
        "00" * 129,
    ),
]


def comment(text):
    lines = [line.removeprefix("///").strip() for line in text.split("\n")]
    return "".join(f"    // {line}\n" for line in lines)


def check(what, got, want):
    if got.hex() != want:
        print(f"{what} mismatch\n  got  {got.hex()}\n  want {want}", file=sys.stderr)
        raise SystemExit(1)


def main():
    key, nonce, want = HCHACHA_VECTOR
    check("HChaCha20 §2.2.1", hchacha20(h(key), h(nonce)), want)

    check(
        "XChaCha20 §A.3.2.1",
        xchacha20(h(A3_KEY), h(A3_NONCE), h(A3_PLAIN), 0),
        A3_COUNTER_0,
    )
    check(
        "XChaCha20 §A.3.2.2",
        xchacha20(h(A3_KEY), h(A3_NONCE), h(A3_PLAIN), 1),
        A3_COUNTER_1,
    )
    print("reference agrees with draft-irtf-cfrg-xchacha", file=sys.stderr)

    out = []
    for text, k, n, counter, plain in CASES:
        want = xchacha20(h(k), h(n), h(plain), counter)
        body = ",\n".join(
            [
                f'    key: "{k}"',
                f'    nonce: "{n}"',
                f"    counter: {counter}",
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
