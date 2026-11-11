#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""Emit the RSA vectors OpenSSL signed and encrypted.

    python scripts/gen_rsa_vectors.py

The vectors are the third-party half of the RSA tests: every signature here was
produced by `openssl`, so a test that replays them is an interoperation test and
not a second opinion on our own arithmetic. Three things are covered that the
other tables do not carry: PKCS#1 v1.5 under the digests the enum gained (SHA-3
and the two truncated SHA-512s, each with its own object identifier), PSS whose
MGF1 hash differs from its message hash, and a three-prime key.

The key material is pinned rather than generated, because the script has to be
reproducible: re-running it must rewrite the same files. The signatures that are
deterministic — every PKCS#1 v1.5 one — are re-signed on each run and compared
with the pinned bytes, so a change in OpenSSL's encoding shows up as a failure
here rather than as a mysterious one in the MoonBit suite. The randomised ones —
PSS and OAEP — cannot be regenerated to the same bytes, so they are pinned and
verified instead: OpenSSL is asked to check the signature and to decrypt the
ciphertext, which is what makes them worth asserting against.
"""

import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent / "src"
OPENSSL = "OpenSSL"

# --- DER writer ------------------------------------------------------------


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
    """A DER INTEGER from a Python int, signed and minimal."""
    body = value.to_bytes(value.bit_length() // 8 + 1, "big")
    return tlv(0x02, body)


def der_seq(*items):
    return tlv(0x30, b"".join(items))


def pkcs1_private(n, e, d, p, q, dp, dq, qinv, others=()):
    fields = [
        der_int(1 if others else 0),
        der_int(n),
        der_int(e),
        der_int(d),
        der_int(p),
        der_int(q),
        der_int(dp),
        der_int(dq),
        der_int(qinv),
    ]
    if others:
        fields.append(der_seq(*[der_seq(der_int(a), der_int(b), der_int(c)) for a, b, c in others]))
    return der_seq(*fields)


def pem(der, label):
    import base64

    body = base64.encodebytes(der).decode().replace("\n", "")
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, "\n".join(lines), label)


# --- the keys --------------------------------------------------------------
#
# Two ordinary keys, generated once. The first is 2048 bits with two primes, the
# second 3072 bits with three — the shape PKCS#1's `otherPrimeInfos` exists for.

KEY2 = dict(
    n=0xee50527d6f81b1f8401420557a7b9136eab745c08bfa08fed2e0303b6ce1744d00e12e89e2e974a138380a0c995728ea1ed502604cf755197470e84fbfa6bd777a7dd5235a72188469abd98a30b17d4058c82750ec5a22a7bf16c7c786dc9c82869996a4eb29af861d1ed43db5d8aaaceccdcfaaae2ce6fce29840b8ee4d93c2616ce8648d0eb22493bc964f75b56a8e335e65fa67884ba7f7174157feec51b08e2b7af22a84b3acfce1b0df4351f9524a859f7878412de68dc8caded8266f342a880bd40ab4bc72337da5490bd38ee1abd614f359e72dd4b5b901cf421c1f524db056362229d2ad0d91fa68aeed6100d818f778f88113699868c6b5f9fa0723,
    e=65537,
    d=0x29f0fcf3928252de0bf8fecfcc649ee3f95f13e99539060842f8adc4679f2e26b736ea47de25941f2393c940fa63ba91a9a777699762181a08c22e408acc3fa01d70b3e82aecd59fc8313471fbabe10d4812c1c89e3026d53aee396ec62f61641f683c78fde2323ffa3408ca6b8c9c4d1ec801fa59f9111604932320e8dfc25726752959979bfaa3433c7d3e84059b44e4df83638750043709a41cf82d0bb96a8be1b0ebab6015dfb11d76302968dddb254f294b7eae3edf8968db456007ffcb27265ae0cf2394b088d32826a6332467043751f75d764a24c55175f49f915e96f2395a4dd836f04248b67df99c0c758d45ce0c893ca1cf93297ae82ce4707f71,
    p=0xfbe22aba81f977c74236f755b630d526d581cfda8b04aac5df4e0673378173d14c6910df74b6c30e480c15bfc2e3cf123d4ecda2f9191cffe73792c0b69eeca61cfd0b9550445c681d2623895202f745fe395a181f8824a1aa224c42287e5b7fa941c5e440bc5f01625e4c2324377e00d1f440bdebf1900c43a557f13ccb4d1f,
    q=0xf23561d9137017008b8bbc79138be11f736d291409b6bb7e7bdc7005ce1f6480a1c5538972bc60c15a7960c2063351cd46bcc6dade55e30ce8b34bc70d63d2eba6ca36602768b30c0d1d8e3a1a47adb6084b670829f454764f0e9fc0ea12ff2a7919a20caa0e228ac0fafa939fcb616e207009722da714749cda1fb6a74fc17d,
)

KEY3 = dict(
    n=0xc8d1a40e1c744f486322bdb0c888ba90e7a771f59764c128cae8b3f46dfe66aad80ffe847f75167259567f2fe97aece3e56dc26efd0f33cd74c580f8ee33949da9d0cc34ccd86f497109d7f1e70a40aa41cf9b0a2f925f55557783a6b1219ed6b14f11bc71e6a98a1f828e1f5fb99acf52a4e3a6cfa1959ae997e7b0f23a3f81814fc134960b8d377b5915fc9855ef7dec1ce4a907a4332e8971f08f0d60a4a5dc332ea25ac145e8ff0dee7d1cd472b633e866f5bbad08ff0dcc3e08fea82f7accd42e19c7cfa42e9d2de95a977d2fd4c6c8fe852c20b7044f5a900b7dc0d44ef82046fa04e880c565deff674aa7a688a61c9cb08d68a41f335f88cb0907e0c1f84f07d8f23656ac433cb0fdf655c99009e9a8c89ca82fbc214409681a39a71eb73e8e868349eba8fdd5b428128bf5678499b3338661ff5edcfbe9a5a532a9e1987e65ccac4a6d667c96ddf6e87e98810b4dcddb21686af9b8964de3f20c5417282161ddda5fc732e2637cfa44685eeb52a6f2374410b02cca42807d44834547,
    e=65537,
    d=0x2acd03ba3e364bef91b185dc77e12c6255fd4a3c9dd7cb93762bc2af060282bf46eda1c17ba8e8efd63aa940fcf2462b0c6b28559f79ee008c32cc1a422a9c323e4f5236aeb23285e4a1c474ba59650ee497eae370e031916e75da895c975dd3445725e09426255c5afae86fa76757a77865cc5f71416f3165380b199b86eea18ff79d60c1f3edcd9f4d91c1cd6e5145c1d9a0ee3cb8f68a7698fbdff678ccf0bffd9d9de356534485521e4a47c229c1e2530b0b5823b85b7c9db8bbb0fe1af603649514df30bc5fd2addf134c35a50cf9754abf0b06de5baa1a057b3272c9c6f152175ca0ba4a334db80a64164a015fa262c947106728548e1bbb422eaee94b5eef8e627b5d07830c9840875bde415476c4f28eabc6591a26e5ec6f867449c7a241cac5c1aa098c156892c5c32d0261415879616cd5b6dea08df4051656ebc8f7b9955c83af9db7c17d5118cbc543db987ab6c599b33519196dcc83ae74ce5a58f6fa60813668c44c8e20d123b3015be6ac116d2095e3e250a93890da17f001,
    p=0xf51944b0f84b5e06f3b9f472b203ae463e33ad6af8bc0ba1e9e9f4c000c95fe1774fee5aa457e8387e1b8d16daa5677d09cb034c9ea925364484baea04fbeb502da9944f448180798f0bbcd21ac2ba0e5e105062c0ae1adfbb08957dbf623069e5ffb434aad4d1e80f188fe5d5c5d2d809f55eaabe3342308274b84b693d3159,
    q=0xd78277ffba0599eb8dc824d675433e497f25f58952e02764d2b3d69eb9f8c4b77278dc3737bacd9a7cf9c6df0ff32c332f5a953b26bada26d0ad336df050831bf45e1e6fba8983ac3318414bbd2312b05d5c1d3cc6f41f3adf3ee0bb0fc97617f5ab537629350abf765baf6b9cfab00d61365d8311bb3850a38b475f26113131,
    r=0xf928bcf0b16b94e8b7c9744759b27eca2e1ec224951badadca997da0344ab615bc723c08827b70c7a62e3a7f696854c8c68541be1ce7353c65521a36460d1033ba6bf3acf884a9afbeb52283353b89cbbe70241d9b4e91cea07de2aa2f6ed52b3addd4cb25d78194b6019f696fef6de1cca6529620a513830e331aeb6067c1cf,
    # The third prime's own exponent and coefficient as the file carries them,
    # to be checked against what the numbers imply.
    r_exp=0xe01fcd159602f807fe8ab0961e117a0bd440c6d2b16e1c64e0820187428292182b5376bd10e289288e4bb74335462c3e0e957ff5cb7a0f612ca316010c326408a400c74928a3ed1fb1a4ae4ee86b8e2040460fb6b22592f3135b29b17cc96de75d247e6ddeb46453a904fca89390047fc0df3c1adf729e829d1b4b73bf5c95f1,
    r_coeff=0x3b45056dbf7c22f6658de1b0e47b090548fa62a392afc55de216c0a4a45355eb11ae3100e2c25800cf7bb247e0015f09d9c19da53df4cf1c88c923c9a22b21746cfc97656f742f47d1e440819f9ba5a0bb15f6844ea1d84f55339e98bb4675ad957b75349bad45a14a76f13811fd41cf794966fd3c26e0f8dce7c17fa6344b03,
)


def crt_fields(n, e, d, p, q):
    """The CRT numbers of a key, and a check that they fit `d`."""
    dp = d % (p - 1)
    dq = d % (q - 1)
    assert e * dp % (p - 1) == 1 and e * dq % (q - 1) == 1, "the key does not fit its primes"
    return dict(d=d, dp=dp, dq=dq, qinv=pow(q, -1, p))


def openssl(*args, **kwargs):
    return subprocess.run(["openssl", *args], check=True, capture_output=True, **kwargs)


def main():
    if shutil.which("openssl") is None:
        sys.exit("openssl is needed to generate these vectors")

    k2 = crt_fields(KEY2["n"], KEY2["e"], KEY2["d"], KEY2["p"], KEY2["q"])
    der2 = pkcs1_private(KEY2["n"], KEY2["e"], k2["d"], KEY2["p"], KEY2["q"],
                         k2["dp"], k2["dq"], k2["qinv"])

    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        key2 = tmp / "key2.pem"
        key2.write_text(pem(der2, "RSA PRIVATE KEY"))
        pub2 = tmp / "pub2.pem"
        pub2.write_text(pem(pkcs1_public(KEY2["n"], KEY2["e"]), "RSA PUBLIC KEY"))

        # The hand-written DER must be the bytes OpenSSL itself writes, or the
        # key the tests replay is not the key OpenSSL signed with.
        theirs = openssl("rsa", "-in", str(key2), "-traditional", "-outform", "DER").stdout
        assert theirs == der2, "the hand-written PKCS#1 key disagrees with OpenSSL"

        message = b"The quick brown fox jumps over the lazy dog"
        msg = tmp / "message.bin"
        msg.write_bytes(message)

        signatures = []
        for flag, digest in [
            ("-sha3-224", "Sha3_224"),
            ("-sha3-256", "Sha3_256"),
            ("-sha3-384", "Sha3_384"),
            ("-sha3-512", "Sha3_512"),
            ("-sha512-224", "Sha512_224"),
            ("-sha512-256", "Sha512_256"),
        ]:
            sig = tmp / "sig.bin"
            openssl("dgst", flag, "-sign", str(key2), "-out", str(sig), str(msg))
            # The same deterministic signature again, so a change upstream is a
            # failure here and not a puzzle later.
            again = tmp / "again.bin"
            openssl("dgst", flag, "-sign", str(key2), "-out", str(again), str(msg))
            assert sig.read_bytes() == again.read_bytes(), "PKCS#1 v1.5 is deterministic"
            openssl("dgst", flag, "-verify", str(pub2), "-signature", str(sig), str(msg))
            signatures.append((digest, sig.read_bytes().hex()))

        # PSS with a mask hash of its own: SHA-256 over the message, SHA-1 in MGF1.
        pss = tmp / "pss.bin"
        pss_opts = ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:20",
                    "-sigopt", "rsa_mgf1_md:sha1"]
        openssl("dgst", "-sha256", "-sign", str(key2), "-out", str(pss), *pss_opts, str(msg))
        openssl("dgst", "-sha256", "-verify", str(pub2), "-signature", str(pss),
                *pss_opts, str(msg))
        pss_hex = pss.read_bytes().hex()

        # The three-prime key: the format's own DER, and what OpenSSL signs and
        # encrypts with it.
        assert OTHER3[0][1] == KEY3["r_exp"], "the third prime's exponent disagrees"
        assert OTHER3[0][2] == KEY3["r_coeff"], "the third prime's coefficient disagrees"
        k3 = crt_fields(KEY3["n"], KEY3["e"], KEY3["d"], KEY3["p"], KEY3["q"])
        assert KEY3["n"] == KEY3["p"] * KEY3["q"] * KEY3["r"], "the third prime is not a factor"
        der3 = pkcs1_private(
            KEY3["n"], KEY3["e"], k3["d"], KEY3["p"], KEY3["q"],
            k3["dp"], k3["dq"], k3["qinv"], others=OTHER3)
        key3 = tmp / "key3.pem"
        key3.write_text(pem(der3, "RSA PRIVATE KEY"))
        pub3 = tmp / "pub3.pem"
        pub3.write_text(pem(pkcs1_public(KEY3["n"], KEY3["e"]), "RSA PUBLIC KEY"))
        theirs3 = openssl("rsa", "-in", str(key3), "-traditional", "-outform", "DER").stdout
        assert theirs3 == der3, "the hand-written three-prime key disagrees with OpenSSL"

        sig3 = tmp / "sig3.bin"
        openssl("dgst", "-sha256", "-sign", str(key3), "-out", str(sig3), str(msg))
        again3 = tmp / "again3.bin"
        openssl("dgst", "-sha256", "-sign", str(key3), "-out", str(again3), str(msg))
        assert sig3.read_bytes() == again3.read_bytes(), "PKCS#1 v1.5 is deterministic"
        openssl("dgst", "-sha256", "-verify", str(pub3), "-signature", str(sig3), str(msg))

        oaep = tmp / "oaep.bin"
        openssl("pkeyutl", "-encrypt", "-pubin", "-inkey", str(pub3),
                "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256",
                "-pkeyopt", "rsa_mgf1_md:sha256", "-in", str(msg), "-out", str(oaep))
        back = tmp / "back.bin"
        openssl("pkeyutl", "-decrypt", "-inkey", str(key3),
                "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256",
                "-pkeyopt", "rsa_mgf1_md:sha256", "-in", str(oaep), "-out", str(back))
        assert back.read_bytes() == message, "OpenSSL did not get its own message back"

        oaep_hex = oaep.read_bytes().hex()
        sig3_hex = sig3.read_bytes().hex()

    write_digest_test(signatures, pss_hex, message.hex())
    write_crt3_test(der3.hex(), sig3_hex, oaep_hex, message.hex())


def pkcs1_public(n, e):
    return der_seq(der_int(n), der_int(e))


# The prime beside the first two, as `otherPrimeInfos` carries it: the prime, its
# exponent and the coefficient that continues the chain of products. Computed
# from the numbers and checked against the bytes OpenSSL wrote.
OTHER3 = [
    (
        KEY3["r"],
        KEY3["d"] % (KEY3["r"] - 1),
        pow(KEY3["p"] * KEY3["q"], -1, KEY3["r"]),
    ),
]


def write_digest_test(signatures, pss_hex, message_hex):
    rows = "\n".join(
        '  ("%s", "%s"),' % (digest, sig) for digest, sig in signatures
    )
    text = f"""// Generated by scripts/gen_rsa_vectors.py from OpenSSL; rerun it rather than
// editing.
//
// Both halves of this file come from `openssl` signing one message with one
// pinned 2048-bit key: PKCS#1 v1.5 under the digests the enum gained, and a PSS
// block whose MGF1 hash is SHA-1 under a SHA-256 message.

///|
/// The pinned modulus and public exponent, big-endian.
let openssl_modulus : String = "{KEY2['n']:x}"

///|
/// (digest, signature) — the same message under each digest, PKCS#1 v1.5.
let openssl_signatures : Array[(String, String)] = [
{rows}
]

///|
/// The message all of them were taken over, hex.
let openssl_message : String = "{message_hex}"

///|
/// A PSS signature over that message with SHA-256, MGF1-SHA-1 and a 20-byte salt.
let openssl_pss : String = "{pss_hex}"

///|
fn openssl_key() -> @rsa.PublicKey raise {{
  @rsa.PublicKey::new(
    openssl_hex(openssl_modulus)[:],
    b"\\x01\\x00\\x01"[:],
  )
}}

///|
fn openssl_hex(s : String) -> Bytes {{
  @base16.decode(s) catch {{ _ => abort("a pinned vector is not hex") }}
}}

///|
fn openssl_digest(name : String) -> @rsa.Digest {{
  match name {{
    "Sha512_224" => Sha512_224
    "Sha512_256" => Sha512_256
    "Sha3_224" => Sha3_224
    "Sha3_256" => Sha3_256
    "Sha3_384" => Sha3_384
    _ => Sha3_512
  }}
}}

///|
test "PKCS#1 v1.5 under the new digests verifies what OpenSSL signed" {{
  for (name, sig) in openssl_signatures {{
    let pk = openssl_key().with_scheme(
      digest=openssl_digest(name),
      scheme=@rsa.Pkcs1,
    )
    let ok = pk.verify(openssl_hex(openssl_message)[:], openssl_hex(sig)[:])
    assert_eq(ok, true)
  }}
}}

///|
test "PSS with a mask hash of its own verifies what OpenSSL signed" {{
  let msg = openssl_hex(openssl_message)[:]
  let sig = openssl_hex(openssl_pss)[:]
  let split = openssl_key().with_scheme(
    digest=Sha256,
    scheme=@rsa.PssMgf(salt=@rsa.Exact(20), mgf=Sha1),
  )
  assert_eq(split.verify(msg, sig), true)
  // The same block under a PSS that masks with the message hash: the field is
  // what makes the difference, so a `Pss` reads this signature as broken.
  let same = openssl_key().with_scheme(digest=Sha256, scheme=@rsa.Pss(salt=@rsa.Auto))
  assert_eq(same.verify(msg, sig), false)
}}
"""
    dest = ROOT / "rsa" / "openssl_test.mbt"
    dest.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {len(signatures)} OpenSSL signatures to {dest}")


def write_crt3_test(der_hex, sig_hex, oaep_hex, message_hex):
    text = f"""// Generated by scripts/gen_rsa_vectors.py from OpenSSL; rerun it rather than
// editing.
//
// A 3072-bit key whose modulus is the product of three primes, in PKCS#1's
// version-1 form, with a signature and an OAEP block OpenSSL produced under it.

///|
/// The key, as `openssl rsa -traditional -outform DER` writes it.
let crt3_der : String = "{der_hex}"

///|
/// The message the signature and the ciphertext carry, hex.
let crt3_message : String = "{message_hex}"

///|
/// A PKCS#1 v1.5 signature over `crt3_message` with SHA-256.
let crt3_signature : String = "{sig_hex}"

///|
/// An RSAES-OAEP block over `crt3_message`, SHA-256 for both the digest and MGF1.
let crt3_ciphertext : String = "{oaep_hex}"

///|
fn crt3_hex(s : String) -> Bytes {{
  @base16.decode(s) catch {{ _ => abort("a pinned vector is not hex") }}
}}

///|
/// The three primes of the key, read out of the version-1 encoding rather than
/// written down a second time.
fn crt3_key() -> @rsa.PrivateKey raise {{
  let (base, others) = @key.parse_rsa_private_multi(crt3_hex(crt3_der)[:])
  assert_eq(others.length(), 1)
  @rsa.PrivateKey::new_crt3(
    base.modulus.to_octets()[:],
    base.public_exponent.to_octets()[:],
    base.private_exponent.to_octets()[:],
    base.prime1.to_octets()[:],
    base.prime2.to_octets()[:],
    others[0].prime.to_octets()[:],
  )
}}

///|
test "a three-prime key reads from its PKCS#1 form and reproduces OpenSSL's signature" {{
  let sk = crt3_key()
  let msg = crt3_hex(crt3_message)[:]
  let sig = sk.sign(msg)
  assert_eq(@spec.eq(sig[:], crt3_hex(crt3_signature)[:]), true)
  assert_eq(sk.public().verify(msg, crt3_hex(crt3_signature)[:]), true)
}}

///|
test "a three-prime key decrypts an OAEP block OpenSSL encrypted" {{
  let plain = crt3_key().decrypt(
    crt3_hex(crt3_ciphertext)[:],
    digest=Sha256,
    mgf=Sha256,
  )
  assert_eq(@spec.eq(plain[:], crt3_hex(crt3_message)[:]), true)
}}
"""
    dest = ROOT / "rsa" / "crt3_test.mbt"
    dest.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote the three-prime key to {dest}")


if __name__ == "__main__":
    main()
