// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The timing table the README quotes, measured the same way: release build,
// native target, the best of several rounds. A shared machine's noise is
// one-sided, so the minimum over rounds is the closest thing to the cost of the
// operation itself.
//
//     moon run src/examples/timing --target native --release -- --bench

///|
/// The best of `rounds` runs of `count` calls, in microseconds per call.
fn best_of(rounds : Int32, count : Int32, op : () -> Unit) -> Double {
  for _ in 0..<3 {
    op()
  }
  let mut low = 1.0e18
  for _ in 0..<rounds {
    let start = @bench.monotonic_clock_start()
    for _ in 0..<count {
      op()
    }
    let elapsed = @bench.monotonic_clock_end(start) / count.to_double()
    if elapsed < low {
      low = elapsed
    }
  }
  low
}

///|
/// The best of `rounds` runs of `count` calls, as megabytes per second, for an
/// operation that eats the whole buffer each time.
fn best_rate(
  rounds : Int32,
  count : Int32,
  bytes_per_call : Int32,
  op : () -> Unit,
) -> Double {
  let us = best_of(rounds, count, op)
  bytes_per_call.to_double() / us
}

///|
fn line(name : String, value : Double, unit : String) -> Unit {
  println(pad(name, 30) + fixed2(value) + " " + unit)
}

///|
pub fn run_bench() -> Unit {
  let mib = 4 * 1024 * 1024
  let buffer = Bytes::make(mib, b'\x5a')
  let key = Bytes::make(32, b'\x2b')
  let nonce = Bytes::make(12, b'\x00')
  println("mooncrypt timings, native, release")
  println("")
  println(pad("operation", 30) + "   value")
  // Hashing and the two AEADs, in megabytes per second.
  let sha = best_rate(5, 1, mib, fn() {
    let h = @sha2.Hasher::new()
    h.write(buffer[:])
    ignore(h.finish())
  })
  line("SHA-256", sha, "MB/s")
  let chachapoly = @chachapoly.ChaChaPoly::new(key) catch {
    _ => abort("a thirty-two byte key was refused")
  }
  // A megabyte at a time: the seal allocates its output, so four would only
  // measure the allocator.
  let small = Bytes::make(1024 * 1024, b'\x5a')
  let cp = best_rate(5, 1, small.length(), fn() {
    ignore(chachapoly.seal(nonce~, plain=small[:]))
  })
  line("ChaCha20-Poly1305", cp, "MB/s")
  let gcm = @gcm.Gcm::new(@aes.Cipher::new(Bytes::make(16, b'\x01'))) catch {
    _ => abort("a sixteen-byte key was refused")
  }
  let aes_gcm = best_rate(5, 1, small.length(), fn() {
    ignore(gcm.seal(nonce~, plain=small[:]))
  })
  line("AES-128-GCM", aes_gcm, "MB/s")
  // The curve operations a handshake spends its time on, in microseconds.
  let ecdsa_key = @ecdsa.PrivateKey::generate(
    @moonseed.Replay::new(Bytes::make(512, b'\x42')),
  ) catch {
    _ => abort("the seeded source ran dry")
  }
  let message = b"the quick brown fox"[:]
  let sig = ecdsa_key.sign(message)
  let ecdsa_sign = best_of(9, 20, fn() { ignore(ecdsa_key.sign(message)) })
  line("ECDSA P-256 sign", ecdsa_sign, "us")
  let ecdsa_verify = best_of(9, 20, fn() {
    ignore(ecdsa_key.public().verify(message, sig[:]))
  })
  line("ECDSA P-256 verify", ecdsa_verify, "us")
  let ed_key = @ed25519.PrivateKey::of_secret(Bytes::make(32, b'\x07'))
  let ed_sig = ed_key.sign(message)
  let ed_sign = best_of(9, 20, fn() { ignore(ed_key.sign(message)) })
  line("Ed25519 sign", ed_sign, "us")
  let ed_verify = best_of(9, 20, fn() {
    ignore(ed_key.public().verify(message, ed_sig[:]))
  })
  line("Ed25519 verify", ed_verify, "us")
  let peer = Bytes::make(32, b'\x09')
  let secret = Bytes::make(32, b'\x11')
  let x_shared = best_of(9, 20, fn() { ignore(curve25519_target()(secret[:])) })
  line("X25519 shared", x_shared, "us")
  ignore(peer)
  let rsa = best_of(3, 3, fn() {
    ignore(rsa_target()(Bytes::make(256, b'\x02')[:]))
  })
  line("RSA-2048 private op", rsa, "us")
}
