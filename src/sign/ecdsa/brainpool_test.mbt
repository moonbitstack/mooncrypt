// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A deterministic entropy stream, so the generated keys are reproducible.
fn stream() -> @moonseed.Replay {
  let buf : Array[Byte] = []
  for i in 0..<512 {
    buf.push((i * 7 + 1).to_byte())
  }
  @moonseed.Replay::new(Bytes::from_array(buf))
}

///|
/// Each brainpool generator must satisfy its own curve equation, so a
/// transposed parameter fails here before it can fail a signature.
test "brainpool generators lie on their curves" {
  let curves = [
    @curve.BrainpoolP256r1,
    @curve.BrainpoolP384r1,
    @curve.BrainpoolP512r1,
  ]
  for c in curves {
    let q = @ec.params(c)
    assert_true(@ec.on_curve(c, q.gx, q.gy))
  }
}

///|
test "ECDSA signs and verifies on every brainpool curve" {
  let curves = [
    @curve.BrainpoolP256r1,
    @curve.BrainpoolP384r1,
    @curve.BrainpoolP512r1,
  ]
  let msg = b"brainpool round trip"[:]
  for c in curves {
    let key = @ecdsa.PrivateKey::generate(stream(), curve=c)
    let sig = key.sign(msg)
    assert_eq(sig.length(), 2 * c.size())
    assert_true(key.public().verify(msg, sig[:]))
  }
}

///|
test "ECDSA rejects a tampered brainpool signature" {
  let key = @ecdsa.PrivateKey::generate(stream(), curve=@curve.BrainpoolP256r1)
  let msg = b"brainpool round trip"[:]
  let sig = key.sign(msg)
  let buf = FixedArray::make(sig.length(), b'\x00')
  for i in 0..<sig.length() {
    buf[i] = sig[i]
  }
  buf[0] = (buf[0].to_int() ^ 1).to_byte()
  assert_false(key.public().verify(msg, buf.unsafe_reinterpret_as_bytes()[:]))
}
