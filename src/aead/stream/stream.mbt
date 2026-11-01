// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The plaintext size of a full chunk: 64 KiB, as age fixes it.
pub let chunk : Int32 = 65536

///|
/// A STREAM sealer over ChaCha20-Poly1305, age's payload encryption.
///
/// The 16-byte payload nonce a file carries is used by the caller to derive the
/// key, not here: this type only turns one byte string into ordered, independent
/// chunks, so a long payload is authenticated a chunk at a time and can be read
/// or written without holding all of it.
struct Stream {
  aead : @chachapoly.ChaChaPoly
  chunk : Int32
}

///|
/// Wrap a payload cipher under a chunk size. Every chunk but the last holds
/// exactly `chunk` plaintext bytes; 64 KiB is what age uses.
pub fn Stream::new(
  aead : @chachapoly.ChaChaPoly,
  chunk~ : Int32 = 65536,
) -> Stream {
  guard chunk >= 1 else { abort("stream: a chunk of \{chunk} bytes is empty") }
  { aead, chunk, }
}

///|
/// The per-chunk nonce: an 11-byte big-endian counter and a final-chunk flag,
/// twelve bytes in all. The payload nonce is deliberately not mixed in — it
/// seeds the key, and the key already separates this file from any other.
fn chunk_nonce(counter : Int32, last : Bool) -> Bytes {
  let n = Array::make(12, b'\x00')
  let mut c = counter
  let mut i = 10
  while i >= 0 && c != 0 {
    n[i] = (c & 0xFF).to_byte()
    c = c >> 8
    i = i - 1
  }
  n[11] = if last { b'\x01' } else { b'\x00' }
  Bytes::from_array(n)
}

///|
/// Seal a payload: split it into chunks, seal each under its counter and final
/// flag, and concatenate. An empty payload still produces one empty final chunk,
/// which is the sixteen-byte tag and nothing else — so a zero-length body never
/// looks like an absent one.
pub fn Stream::seal(self : Stream, plain : BytesView) -> Bytes {
  let out : Array[Byte] = []
  let total = plain.length()
  if total == 0 {
    let ct = self.aead.seal(
      nonce=chunk_nonce(0, true),
      plain=b""[:],
      aad=b""[:],
    )
    for b in ct {
      out.push(b)
    }
    return Bytes::from_array(out)
  }
  let mut off = 0
  let mut counter = 0
  while off < total {
    let remaining = total - off
    let take = if remaining > self.chunk { self.chunk } else { remaining }
    let last = off + take >= total
    let ct = self.aead.seal(
      nonce=chunk_nonce(counter, last),
      plain=plain[off:off + take],
      aad=b""[:],
    )
    for b in ct {
      out.push(b)
    }
    off += take
    counter = counter + 1
  }
  Bytes::from_array(out)
}

///|
/// Open a sealed payload: split the ciphertext at `chunk + 16`-byte boundaries,
/// the last chunk taking whatever is left, and open each in turn. A ciphertext
/// too short to hold a tag, or any chunk that does not authenticate, raises —
/// so a truncated stream cannot pass for a complete one.
pub fn Stream::open(
  self : Stream,
  cipher : BytesView,
) -> Bytes raise @spec.Broken {
  let tag = @chachapoly.tag
  let block = self.chunk + tag
  let total = cipher.length()
  if total < tag {
    raise @spec.Tag
  }
  let chunks = (total + block - 1) / block
  let out : Array[Byte] = []
  for i in 0..<chunks {
    let off = i * block
    let len = if i == chunks - 1 { total - off } else { block }
    let last = i == chunks - 1
    let pt = self.aead.open(
      nonce=chunk_nonce(i, last),
      cipher=cipher[off:off + len],
      aad=b""[:],
    )
    for b in pt {
      out.push(b)
    }
  }
  Bytes::from_array(out)
}
