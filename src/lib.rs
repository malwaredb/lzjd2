// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../readme.md")]
#![deny(clippy::all)]
#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

/// LZJD hasher
pub mod lzjd;

/// Murmurhash3 hasher
pub mod murmur3;

/// Rabin Karp hasher
pub mod rabinkarp;
