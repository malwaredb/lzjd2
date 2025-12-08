// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

use core::hash::Hasher;

type RabinKarp = RollingRabinKarp<4>;

/// Rabin-Karp rolling hash for byte streams
pub struct RollingRabinKarp<const S: usize> {
    hash: u64,
    base_pow: u64,
    len: usize,
    window: [u8; S],
}

impl<const S: usize> RollingRabinKarp<S> {
    const BASE: u64 = 256;
    const MOD: u64 = 0xffff_ffff_ffff_fff1; // large 64-bit prime

    /// Create a new rolling hash
    pub fn new() -> Self {
        let mut base_pow = 1;
        for _ in 0..S - 1 {
            base_pow = (base_pow * Self::BASE) % Self::MOD;
        }

        Self {
            hash: 0,
            base_pow,
            len: 0,
            window: [0; S],
        }
    }

    /// Push a byte into the rolling window
    pub fn push(&mut self, byte: u8) {
        if self.len < S {
            self.len += 1;
        } else {
            self.window[self.len % S] = byte;
        }

        self.hash = (self.hash * Self::BASE + byte as u64) % Self::MOD;
        self.window[self.len] = byte;
    }

    /// Remove the oldest byte from the window
    fn pop(&mut self) {
        if self.len > 0 {
            let old = self.window[self.len];
            let remove = (old as u64 * self.base_pow) % Self::MOD;

            self.hash = if self.hash >= remove {
                self.hash - remove
            } else {
                self.hash + Self::MOD - remove
            };
            self.len -= 1;
        }
    }

    /// Get the current hash value
    #[inline]
    pub fn hash(&self) -> u64 {
        self.hash
    }

    /// Reset state
    pub fn reset(&mut self) {
        self.window = [0; S];
        self.hash = 0;
        self.len = 0;
    }

    /// Check if the window is full
    pub fn is_ready(&self) -> bool {
        self.len == S
    }
}

impl<const S: usize> Default for RollingRabinKarp<S> {
    fn default() -> Self {
        RollingRabinKarp::new()
    }
}

impl<const S: usize> Hasher for RollingRabinKarp<S> {
    fn finish(&self) -> u64 {
        self.hash
    }

    fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.push(*b);
        }
    }
}
