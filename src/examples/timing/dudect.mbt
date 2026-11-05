// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A two-class timing test, the shape dudect uses: run the operation on a fixed
// input and on random ones, alternating by a pseudorandom bit so both classes
// see the same machine conditions, then ask whether the two sets of timings are
// drawn from the same distribution.
//
// The statistic is Welch's t. Under the null hypothesis — the running time does
// not depend on the input — it is approximately standard normal, so a value
// past 4.5 is the threshold the tooling conventionally uses for "this leaks".
// Past it, a handful of samples decide one class over the other and the leak is
// visible from a distance; below it, the difference is inside the noise of the
// machine.

///|
/// The classification threshold: `|t|` below this is treated as no leak.
pub let t_threshold : Double = 4.5

///|
/// What one measurement found. `fold` is the checksum the operation's results
/// were folded into: two runs that disagree were not measuring the same thing.
pub(all) struct Reading {
  name : String
  samples : Int32
  t : Double
  mean_fixed : Double
  mean_random : Double
  fold : UInt64
}

///|
/// Whether the reading is past the threshold, in either direction: a class that
/// runs consistently faster is as much a signal as one that runs slower.
pub fn Reading::leaks(self : Reading) -> Bool {
  let t = if self.t < 0.0 { -self.t } else { self.t }
  t > t_threshold
}

///|
/// SplitMix64: enough to choose between two classes and to fill the input pool,
/// with no dependency on the platform's entropy — a measurement that cannot be
/// reproduced would not be worth running.
priv struct Mix {
  mut state : UInt64
}

///|
fn Mix::new(seed : UInt64) -> Mix {
  { state: seed, }
}

///|
fn Mix::next(self : Mix) -> UInt64 {
  self.state = self.state + 0x9E3779B97F4A7C15UL
  let mut z = self.state
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL
  z ^ (z >> 31)
}

///|
fn Mix::below(self : Mix, n : Int32) -> Int32 {
  (self.next() % n.to_uint64()).to_int()
}

///|
fn mean(xs : Array[Double]) -> Double {
  let mut sum = 0.0
  for x in xs {
    sum = sum + x
  }
  sum / xs.length().to_double()
}

///|
fn variance(xs : Array[Double], m : Double) -> Double {
  let mut sum = 0.0
  for x in xs {
    let d = x - m
    sum = sum + d * d
  }
  if xs.length() < 2 {
    0.0
  } else {
    sum / (xs.length() - 1).to_double()
  }
}

///|
/// Drop the slowest and fastest one percent of the pooled samples. A scheduling
/// hiccup or a page fault that lands in one class only would otherwise move the
/// means by more than the effect being looked for.
fn cropped(
  a : Array[Double],
  b : Array[Double],
) -> (Array[Double], Array[Double]) {
  let all = Array::make(a.length() + b.length(), 0.0)
  for i in 0..<a.length() {
    all[i] = a[i]
  }
  for i in 0..<b.length() {
    all[a.length() + i] = b[i]
  }
  all.sort()
  let cut = all.length() / 100
  let lo = all[cut]
  let hi = all[all.length() - 1 - cut]
  let keep = fn(xs : Array[Double]) -> Array[Double] {
    let out : Array[Double] = []
    for x in xs {
      if x >= lo && x <= hi {
        out.push(x)
      }
    }
    out
  }
  (keep(a), keep(b))
}

///|
/// Welch's t over the two classes: the difference of the means divided by the
/// standard error of that difference.
fn welch(fixed : Array[Double], random : Array[Double]) -> Double {
  let (a, b) = cropped(fixed, random)
  if a.length() < 2 || b.length() < 2 {
    return 0.0
  }
  let ma = mean(a)
  let mb = mean(b)
  let se = (variance(a, ma) / a.length().to_double() +
  variance(b, mb) / b.length().to_double()).sqrt()
  if se == 0.0 {
    0.0
  } else {
    (mb - ma) / se
  }
}

///|
/// Time `op` over `samples` fixed inputs and `samples` random ones, and report
/// the two sets against each other.
///
/// `input_len` is the length of the secret each call is given, and the top byte
/// of every input is zeroed so the value stays inside the range the operation
/// accepts — a rejected input would measure the rejection path instead.
pub fn measure(
  name : String,
  samples : Int32,
  input_len : Int32,
  op : (BytesView) -> Bytes,
  seed : UInt64,
) -> Reading {
  let rng = Mix::new(seed)
  // A pool of random inputs, drawn once: the point of the measurement is the
  // operation, not the generator the inputs come from.
  let pool = Array::make(16, Bytes::make(input_len, b'\x00'))
  for i in 0..<16 {
    let bytes : FixedArray[Byte] = FixedArray::make(input_len, b'\x00')
    for j in 0..<input_len {
      bytes[j] = (rng.next() & 0xFFUL).to_byte()
    }
    bytes[0] = b'\x00'
    pool[i] = Bytes::from_array(bytes)
  }
  let fixed_bytes : FixedArray[Byte] = FixedArray::make(input_len, b'\x01')
  fixed_bytes[0] = b'\x00'
  let fixed = Bytes::from_array(fixed_bytes)
  let fixed_times : Array[Double] = []
  let random_times : Array[Double] = []
  let mut fold = 0UL
  for _ in 0..<(2 * samples) {
    let bit = rng.below(2)
    let input = if bit == 0 { fixed } else { pool[rng.below(16)] }
    let start = @bench.monotonic_clock_start()
    let out = op(input[:])
    let elapsed = @bench.monotonic_clock_end(start)
    // The result is folded in so the call cannot be dropped as dead code, and
    // so two runs can be compared without printing megabytes.
    fold = fold ^ out[0].to_int().to_uint64()
    if bit == 0 {
      fixed_times.push(elapsed)
    } else {
      random_times.push(elapsed)
    }
  }
  {
    name,
    samples: fixed_times.length(),
    t: welch(fixed_times, random_times),
    mean_fixed: mean(fixed_times),
    mean_random: mean(random_times),
    fold,
  }
}
