"""Argon2 reference, written from RFC 9106 for cross-checking the MoonBit port.

Not optimised: the point is to be obviously the spec, so the test vectors in
src/kdf/argon2/argon2_test.mbt have a second opinion behind them.
"""

import hashlib
import struct
import sys

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1

ARGON2D, ARGON2I, ARGON2ID = 0, 1, 2


def le32(x):
    return struct.pack("<I", x & MASK32)


def h_prime(x, tau):
    """RFC 9106 section 3.3: variable-length hash built on BLAKE2b-512."""
    if tau <= 64:
        return hashlib.blake2b(le32(tau) + x, digest_size=tau).digest()
    r = (tau + 31) // 32 - 2
    out = b""
    v = hashlib.blake2b(le32(tau) + x, digest_size=64).digest()
    out += v[:32]
    for _ in range(r - 1):
        v = hashlib.blake2b(v, digest_size=64).digest()
        out += v[:32]
    out += hashlib.blake2b(v, digest_size=tau - 32 * r).digest()
    assert len(out) == tau
    return out


def rotr64(x, n):
    return ((x >> n) | (x << (64 - n))) & MASK64


def fbla(a, b):
    """a + b + 2 * lo32(a) * lo32(b), modulo 2**64."""
    return (a + b + 2 * ((a & MASK32) * (b & MASK32))) & MASK64


def gb(a, b, c, d):
    a = fbla(a, b)
    d = rotr64(d ^ a, 32)
    c = fbla(c, d)
    b = rotr64(b ^ c, 24)
    a = fbla(a, b)
    d = rotr64(d ^ a, 16)
    c = fbla(c, d)
    b = rotr64(b ^ c, 63)
    return a, b, c, d


def round_nomsg(v):
    v = list(v)
    v[0], v[4], v[8], v[12] = gb(v[0], v[4], v[8], v[12])
    v[1], v[5], v[9], v[13] = gb(v[1], v[5], v[9], v[13])
    v[2], v[6], v[10], v[14] = gb(v[2], v[6], v[10], v[14])
    v[3], v[7], v[11], v[15] = gb(v[3], v[7], v[11], v[15])
    v[0], v[5], v[10], v[15] = gb(v[0], v[5], v[10], v[15])
    v[1], v[6], v[11], v[12] = gb(v[1], v[6], v[11], v[12])
    v[2], v[7], v[8], v[13] = gb(v[2], v[7], v[8], v[13])
    v[3], v[4], v[9], v[14] = gb(v[3], v[4], v[9], v[14])
    return v


def fill_block(prev, ref, cur=None, with_xor=False):
    r = [p ^ q for p, q in zip(prev, ref)]
    base = list(r)
    if with_xor and cur is not None:
        base = [a ^ b for a, b in zip(base, cur)]
    for i in range(8):
        r[16 * i : 16 * i + 16] = round_nomsg(r[16 * i : 16 * i + 16])
    for i in range(8):
        idx = []
        for k in range(8):
            idx.append(2 * i + 16 * k)
            idx.append(2 * i + 16 * k + 1)
        vals = round_nomsg([r[j] for j in idx])
        for j, val in zip(idx, vals):
            r[j] = val
    return [a ^ b for a, b in zip(base, r)]


def to_words(data):
    return list(struct.unpack("<%dQ" % (len(data) // 8), data))


def from_words(words):
    return struct.pack("<%dQ" % len(words), *words)


def argon2(
    password,
    salt,
    secret=b"",
    ad=b"",
    lanes=1,
    tag_len=32,
    memory=8,
    passes=1,
    version=0x13,
    kind=ARGON2ID,
):
    if memory < 8 * lanes:
        raise ValueError("memory must be at least 8 * lanes")
    if lanes < 1 or passes < 1 or tag_len < 4:
        raise ValueError("bad parameters")

    h = hashlib.blake2b(digest_size=64)
    for value in (lanes, tag_len, memory, passes, version, kind):
        h.update(le32(value))
    for blob in (password, salt, secret, ad):
        h.update(le32(len(blob)))
        h.update(blob)
    h0 = h.digest()

    m_prime = 4 * lanes * (memory // (4 * lanes))
    q = m_prime // lanes  # blocks per lane
    seg = q // 4  # blocks per segment

    b = [[None] * q for _ in range(lanes)]
    for lane in range(lanes):
        b[lane][0] = to_words(h_prime(h0 + le32(0) + le32(lane), 1024))
        b[lane][1] = to_words(h_prime(h0 + le32(1) + le32(lane), 1024))

    zero = [0] * 128

    def next_addresses(input_block):
        input_block[6] += 1
        tmp = fill_block(zero, input_block)
        return fill_block(zero, tmp)

    for p in range(passes):
        for s in range(4):
            for lane in range(lanes):
                indep = kind == ARGON2I or (
                    kind == ARGON2ID and p == 0 and s < 2
                )
                if indep:
                    input_block = [0] * 128
                    input_block[0] = p
                    input_block[1] = lane
                    input_block[2] = s
                    input_block[3] = m_prime
                    input_block[4] = passes
                    input_block[5] = kind
                    address_block = None
                start = 0
                if p == 0 and s == 0:
                    start = 2
                    if indep:
                        address_block = next_addresses(input_block)

                # Indices within this lane: the block at absolute offset
                # `lane*q + k` is `b[lane][k]`, so the lane offset is the
                # residue and nothing else.
                curr = s * seg + start
                prev = curr + q - 1 if curr == 0 else curr - 1

                for i in range(start, seg):
                    if curr == 1:
                        prev = 0
                    if indep:
                        if i % 128 == 0:
                            address_block = next_addresses(input_block)
                        pseudo = address_block[i % 128]
                    else:
                        pseudo = b[lane][prev][0]

                    ref_lane = (pseudo >> 32) % lanes
                    if p == 0 and s == 0:
                        ref_lane = lane

                    j1 = pseudo & MASK32
                    same = ref_lane == lane
                    if p == 0:
                        if s == 0:
                            area = i - 1
                        elif same:
                            area = s * seg + i - 1
                        else:
                            area = s * seg + (-1 if i == 0 else 0)
                    else:
                        if same:
                            area = q - seg + i - 1
                        else:
                            area = q - seg + (-1 if i == 0 else 0)

                    rel = (j1 * j1) >> 32
                    rel = area - 1 - ((area * rel) >> 32)

                    start_pos = 0
                    if p != 0:
                        start_pos = 0 if s == 3 else (s + 1) * seg
                    ref_index = (start_pos + rel) % q

                    here = b[lane][curr]
                    ref = b[ref_lane][ref_index]
                    before = b[lane][prev]
                    out = fill_block(before, ref, here, with_xor=(p != 0))
                    b[lane][curr] = out

                    curr += 1
                    prev += 1

    # RFC 9106 step 12: the final block is the XOR of the last column, not a
    # concatenation, and it is then run through H' once.
    last = b[0][q - 1]
    for lane in range(1, lanes):
        last = [x ^ y for x, y in zip(last, b[lane][q - 1])]
    return h_prime(from_words(last), tag_len)


def rfc_vectors():
    """RFC 9106 section 5: 32-byte password 0x01, 16-byte salt 0x02, and so on."""
    common = dict(
        password=b"\x01" * 32,
        salt=b"\x02" * 16,
        secret=b"\x03" * 8,
        ad=b"\x04" * 12,
        lanes=4,
        tag_len=32,
        memory=32,
        passes=3,
        version=0x13,
    )
    expected = {
        ARGON2D: "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
        ARGON2I: "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
        ARGON2ID: "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
    }
    ok = True
    for kind, want in expected.items():
        got = argon2(kind=kind, **common).hex()
        name = {0: "Argon2d", 1: "Argon2i", 2: "Argon2id"}[kind]
        flag = "ok  " if got == want else "FAIL"
        print(f"{flag} {name:9s} {got}")
        if got != want:
            print(f"     want      {want}")
            ok = False
    return ok


if __name__ == "__main__":
    if not rfc_vectors():
        sys.exit(1)

    print()
    print("extra cases for the MoonBit tests")
    cases = [
        # (name, kwargs)
        ("argon2id defaults", dict(kind=ARGON2ID, password=b"password", salt=b"somesalt", memory=8, lanes=1, passes=1, tag_len=32)),
        ("argon2i 64-byte tag", dict(kind=ARGON2I, password=b"password", salt=b"somesalt", memory=64, lanes=2, passes=2, tag_len=64)),
        ("argon2d long tag", dict(kind=ARGON2D, password=b"password", salt=b"somesalt", memory=32, lanes=1, passes=2, tag_len=72)),
        ("argon2id memory not a multiple of 4p", dict(kind=ARGON2ID, password=b"password", salt=b"somesalt", memory=25, lanes=3, passes=2, tag_len=32)),
        ("argon2id empty password", dict(kind=ARGON2ID, password=b"", salt=b"somesalt", memory=8, lanes=1, passes=1, tag_len=32)),
        ("argon2id wide tag", dict(kind=ARGON2ID, password=b"password", salt=b"somesalt", memory=64, lanes=4, passes=1, tag_len=128)),
    ]
    for name, kw in cases:
        print(f"{argon2(**kw).hex()}  {name}")
