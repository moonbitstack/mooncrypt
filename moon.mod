name = "moonbitstack/mooncrypt"

version = "0.1.0"

readme = "README.md"

repository = "https://github.com/moonbitstack/mooncrypt"

license = "Apache-2.0"

keywords = [
  "crypto",
  "cryptography",
  "hash",
  "sha256",
  "hmac",
  "ed25519",
  "ecdsa",
  "rsa",
  "jwt",
  "moonbit",
]

description = "mooncrypt — cryptographic algorithms for MoonBit, one algorithm per package: SHA-1, SHA-2, MD5, HMAC, HKDF, PBKDF2, Ed25519, ECDSA P-256 and RSA PKCS#1 v1.5, on a small set of traits so a third algorithm drops in without touching the library."

preferred_target = "wasm-gc"

import {
  "moonbitstack/moonbase@0.4.0",
}
