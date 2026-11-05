// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The reseed interval the three generators share. SP 800-90A treats the
// counter as part of the state a caller must respect: an instantiated generator
// may serve a bounded number of requests before the entropy it was seeded with
// is considered spent, and every table in §10 caps that number.

///|
/// `2^48` requests, the cap SP 800-90A §10.1.1 and §10.2.1 put on every
/// generator here. Instantiation takes it as a default; a caller that reseeds
/// on its own schedule can pass something smaller.
pub let reseed_limit : UInt64 = 1UL << 48

///|
/// The generator was asked for output past its reseed interval. SP 800-90A
/// requires a reseed at that point rather than more output: past the interval
/// the state is no longer backed by the entropy it was instantiated with, and
/// continuing would silently return bytes from a generator that has been
/// stretched further than its security argument allows.
///
/// `limit` is the interval the generator was given.
pub(all) suberror Refused {
  Reseed(limit~ : UInt64)
}
