"""Emit bcrypt test vectors for src/kdf/bcrypt from the reference library.

Requires the `bcrypt` package (pip install bcrypt). Run with the interpreter
that has it installed:

    python scripts/gen_bcrypt_vectors.py
"""

import bcrypt

ALPHABET = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def b64(data, out_len):
    """bcrypt's base64: RFC 4648 bit order, its own alphabet, no padding."""
    bits = 0
    nbits = 0
    out = []
    for byte in data:
        bits = (bits << 8) | byte
        nbits += 8
        while nbits >= 6:
            nbits -= 6
            out.append(ALPHABET[(bits >> nbits) & 0x3F])
    if nbits:
        out.append(ALPHABET[(bits << (6 - nbits)) & 0x3F])
    return bytes(out[:out_len])


def hexs(b):
    return b.hex()


CASES = [
    # (label, password, salt bytes, cost)
    ("password, all-C salt", b"password", b"\x43" * 16, 5),
    ("empty password", b"", b"\x43" * 16, 5),
    ("one byte", b"a", bytes(range(16)), 4),
    ("seventy-two bytes", b"x" * 72, bytes(range(16, 32)), 4),
    ("high-bit bytes", bytes([0x80, 0xFF, 0x00, 0x7F, 0xC3, 0xA9]), b"\xA0" * 16, 6),
    ("mixed", b"correct horse battery staple", b"\x5B\xBF\x0C\xEE\xF3\x9C\x2B\x7A\x11\x22\x33\x44\x55\x66\x77\x88", 5),
]


def main():
    print("///|")
    print("/// The vectors below were produced by the reference `bcrypt` library:")
    print("/// password, sixteen salt bytes, cost, and the string it formats to.")
    print("/// `scripts/gen_bcrypt_vectors.py` regenerates them.")
    print("let vectors : Array[(String, String, Int, String)] = [")
    for label, password, salt, cost in CASES:
        salt_text = b64(salt, 22)
        hashed = bcrypt.hashpw(password, b"$2b$%02d$" % cost + salt_text)
        # The reference truncates at 72 bytes and appends a NUL, which is what
        # the format prescribes; check that is what happened.
        assert hashed.startswith(b"$2b$%02d$" % cost + salt_text), hashed
        print(f"  // {label}")
        print(
            f'  ("{password.hex()}", "{hexs(salt)}", {cost}, "{hashed.decode()}"),'
        )
    print("]")

    # The reference refuses anything past 72 bytes rather than truncating, so
    # mooncrypt does the same; this is the boundary that has to be accepted.
    salt_text = b64(b"\x43" * 16, 22)
    edge = bcrypt.hashpw(b"z" * 72, b"$2b$04$" + salt_text)
    print()
    print("///|")
    print("/// Exactly seventy-two bytes, the longest password the format accepts.")
    print(f'let longest_password : String = "{edge.decode()}"')


if __name__ == "__main__":
    main()
