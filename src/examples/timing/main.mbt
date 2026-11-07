// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The constant-time measurement, runnable:
//
//     moon run src/examples/timing                    a quick pass
//     moon run src/examples/timing --target native --release -- --full
//
// The quick pass is what CI runs: enough samples to catch a gross leak, small
// enough to finish in seconds. `--full` is what the numbers in the README were
// taken with.

///|
fn pad(text : String, width : Int32) -> String {
  let mut out = text
  while out.length() < width {
    out = " " + out
  }
  out
}

///|
/// Two decimals, right-aligned, so a column of them lines up.
fn fixed2(v : Double) -> String {
  let scaled = (v * 100.0).round().to_int()
  let sign = if scaled < 0 { "-" } else { "" }
  let a = if scaled < 0 { -scaled } else { scaled }
  let frac = a % 100
  sign +
  (a / 100).to_string() +
  "." +
  (if frac < 10 { "0" } else { "" }) +
  frac.to_string()
}

///|
fn hex64(v : UInt64) -> String {
  let bytes : FixedArray[Byte] = FixedArray::make(8, b'\x00')
  for i in 0..<8 {
    bytes[i] = ((v >> (56 - 8 * i)) & 0xFFUL).to_byte()
  }
  @base16.encode(Bytes::from_array(bytes))
}

///|
fn report(readings : Array[Reading]) -> Unit {
  println("")
  println(
    pad("operation", 26) +
    pad("samples", 9) +
    pad("fixed us", 11) +
    pad("random us", 12) +
    pad("t", 9) +
    "  verdict",
  )
  for r in readings {
    let verdict = if r.leaks() { "LEAK" } else { "ok" }
    println(
      pad(r.name, 26) +
      pad(r.samples.to_string(), 9) +
      pad(fixed2(r.mean_fixed), 11) +
      pad(fixed2(r.mean_random), 12) +
      pad(fixed2(r.t), 9) +
      "  " +
      verdict +
      "  fold " +
      hex64(r.fold),
    )
  }
  println("")
  let leaked = readings.filter(fn(r) { r.leaks() }).length()
  if leaked == 0 {
    println(
      "No operation is past |t| = " +
      fixed2(t_threshold) +
      ": on this machine the timing does not follow the secret.",
    )
  } else {
    println(
      leaked.to_string() +
      " operation(s) past |t| = " +
      fixed2(t_threshold) +
      ": the timing follows the secret.",
    )
  }
}

///|
fn main {
  let args = @env.args()
  if args.contains("--bench") {
    run_bench()
    return
  }
  let full = args.contains("--full")
  // Per class. The slow operations get fewer samples because each one costs
  // milliseconds; the quick pass is the same shape at a fiftieth of the size.
  let (aes_n, p256_n, x25519_n, k1_n, rsa_n, rsa_crt_n) = if full {
    (100000, 4000, 4000, 4000, 300, 300)
  } else {
    (2000, 80, 80, 80, 6, 6)
  }
  println("mooncrypt constant-time measurement")
  println(
    "Two classes of samples per operation; |t| below " +
    fixed2(t_threshold) +
    " means the timing does not separate them.",
  )
  let readings : Array[Reading] = [
    measure("AES-128 encrypt", aes_n, 16, aes_target(), 1UL),
    measure("P-256 [k]G", p256_n, 32, p256_target(), 2UL),
    measure("secp256k1 [k]P", k1_n, 32, secp256k1_target(), 3UL),
    measure("Curve25519 shared", x25519_n, 32, curve25519_target(), 4UL),
    measure("RSA-2048 private op", rsa_n, 256, rsa_target(), 5UL),
    measure("RSA-2048 CRT private op", rsa_crt_n, 256, rsa_crt_target(), 6UL),
  ]
  report(readings)
}
