// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn payload_key() -> Bytes {
  @base16.decode_lossy(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
}

///|
fn sealer() -> @stream.Stream {
  let aead = @chachapoly.ChaChaPoly::new(payload_key()[:]) catch {
    _ => abort("stream test: the payload key must be 32 bytes")
  }
  @stream.Stream::new(aead)
}

///|
test "STREAM round-trips a payload across chunk boundaries" {
  let s = sealer()
  // Three full chunks and a 3392-byte remainder, so four chunks in all.
  let plain = Bytes::make(200_000, b'\x2a')
  let body = s.seal(plain[:])
  assert_eq(body.length(), 200_000 + 4 * @chachapoly.tag)
  let opened = s.open(body[:]) catch {
    _ => abort("stream: a payload it body must open")
  }
  assert_true(@spec.eq(opened[:], plain[:]))
}

///|
test "STREAM seals an empty payload to just a tag" {
  let s = sealer()
  let body = s.seal(b""[:])
  assert_eq(body.length(), @chachapoly.tag)
  let opened = s.open(body[:]) catch {
    _ => abort("stream: an empty payload must open")
  }
  assert_eq(opened.length(), 0)
}

///|
test "STREAM marks a full final chunk" {
  let s = sealer()
  let plain = Bytes::make(@stream.chunk, b'\x05')
  let body = s.seal(plain[:])
  assert_eq(body.length(), @stream.chunk + @chachapoly.tag)
  let opened = s.open(body[:]) catch {
    _ => abort("stream: a full final chunk must open")
  }
  assert_true(@spec.eq(opened[:], plain[:]))
}

///|
test "STREAM rejects a flipped ciphertext byte" {
  let s = sealer()
  let plain = Bytes::make(1_000, b'\x07')
  let body = s.seal(plain[:])
  let buf = FixedArray::make(body.length(), b'\x00')
  for i in 0..<body.length() {
    buf[i] = body[i]
  }
  buf[0] = (buf[0].to_int() ^ 1).to_byte()
  let failed = try {
    let _ = s.open(buf.unsafe_reinterpret_as_bytes()[:])
    false
  } catch {
    _ => true
  }
  assert_true(failed)
}
