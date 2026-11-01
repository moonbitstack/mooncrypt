// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A deterministic entropy stream, seeded so the two parties draw different
/// scalars but the exchange is reproducible.
fn stream(seed : Int32) -> @moonseed.Replay {
  let buf : Array[Byte] = []
  for i in 0..<256 {
    buf.push((i * 7 + seed).to_byte())
  }
  @moonseed.Replay::new(Bytes::from_array(buf))
}

///|
test "ECDH both sides agree on every brainpool curve" {
  let curves = [
    @curve.BrainpoolP256r1,
    @curve.BrainpoolP384r1,
    @curve.BrainpoolP512r1,
  ]
  for c in curves {
    let a = @ecdh.generate(stream(1), curve=c) catch {
      _ => abort("ecdh test: a generator must not exhaust")
    }
    let b = @ecdh.generate(stream(2), curve=c) catch {
      _ => abort("ecdh test: a generator must not exhaust")
    }
    let pa = @ecdh.public(a[:], curve=c) catch {
      _ => abort("ecdh test: a valid scalar must make a point")
    }
    let pb = @ecdh.public(b[:], curve=c) catch {
      _ => abort("ecdh test: a valid scalar must make a point")
    }
    let sa = @ecdh.shared(a[:], pb[:], curve=c) catch {
      _ => abort("ecdh test: a valid peer point must agree")
    }
    let sb = @ecdh.shared(b[:], pa[:], curve=c) catch {
      _ => abort("ecdh test: a valid peer point must agree")
    }
    assert_eq(@base16.encode(sa[:]), @base16.encode(sb[:]))
  }
}
