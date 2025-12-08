// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

use core::hash::Hasher;

#[inline]
fn rotl32(x: u32, r: u32) -> u32 {
    (x << r) | (x >> (32 - r))
}

#[inline]
fn rotl64(x: u64, r: u32) -> u64 {
    (x << r) | (x >> (64 - r))
}

#[inline]
fn fmix32(mut h: u32) -> u32 {
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h
}

#[inline]
fn fmix64(mut k: u64) -> u64 {
    k ^= k >> 33;
    k = k.wrapping_mul(0xff51afd7ed558ccd);
    k ^= k >> 33;
    k = k.wrapping_mul(0xc4ceb9fe1a85ec53);
    k ^= k >> 33;
    k
}

type Murmur32 = RollingMurmur32<4>;
type Murmur64 = RollingMurmur64<4>;

/// 32-bit Murmur3 hasher
pub struct RollingMurmur32<const S: usize> {
    hash: u32,
    window: [u8; S],
    len: usize,
    index: usize,
}

impl<const S: usize> RollingMurmur32<S> {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;

    /// Create a 32-bit Murmur3 hasher with a given seed
    pub fn new(seed: u32) -> Self {
        Self {
            hash: seed,
            window: [0; S],
            len: 0,
            index: 0,
        }
    }

    /// Push one byte into the rolling window (O(1))
    pub fn push(&mut self, byte: u8) {
        if self.len < S {
            self.inject(byte);
            self.window[self.index] = byte;
            self.index = (self.index + 1) % S;
            self.len += 1;
        } else {
            // Remove oldest
            let old = self.window[self.index];
            self.remove(old);

            // Insert new
            self.inject(byte);
            self.window[self.index] = byte;
            self.index = (self.index + 1) % S;
        }
    }

    /// Murmur-style inject
    #[inline]
    fn inject(&mut self, byte: u8) {
        let mut k = byte as u32;
        k = k.wrapping_mul(Self::C1);
        k = rotl32(k, 15);
        k = k.wrapping_mul(Self::C2);

        self.hash ^= k;
        self.hash = rotl32(self.hash, 13);
        self.hash = self.hash.wrapping_mul(5).wrapping_add(0xe654_6b64);
    }

    /// Inverse-mix removal (rolling-safe)
    #[inline]
    fn remove(&mut self, byte: u8) {
        let mut k = byte as u32;
        k = k.wrapping_mul(Self::C1);
        k = rotl32(k, 15);
        k = k.wrapping_mul(Self::C2);

        self.hash ^= k;
    }

    /// Current rolling hash (optionally finalized)
    #[inline]
    pub fn hash(&self) -> u32 {
        fmix32(self.hash ^ self.len as u32)
    }

    /// Check if the window is full
    #[inline]
    pub fn is_ready(&self) -> bool {
        self.len == S
    }

    /// Reset state
    pub fn reset(&mut self, seed: u32) {
        self.hash = seed;
        self.window = [0; S];
        self.len = 0;
        self.index = 0;
    }
}

impl<const S: usize> Default for RollingMurmur32<S> {
    fn default() -> Self {
        Self::new(0)
    }
}

impl<const S: usize> Hasher for RollingMurmur32<S> {
    fn finish(&self) -> u64 {
        self.hash as u64
    }

    fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.push(*b);
        }
    }
}

/// 64-bit Murmur3 hasher
pub struct RollingMurmur64<const S: usize> {
    hash: u64,
    window: [u8; S],
    len: usize,
    index: usize,
}

impl<const S: usize> RollingMurmur64<S> {
    const C1: u64 = 0x87c37b91114253d5;
    const C2: u64 = 0x4cf5ad432745937f;

    /// Create a 64-bit Murmur3 hasher with a given seed
    pub fn new(seed: u64) -> Self {
        Self {
            hash: seed,
            window: [0; S],
            len: 0,
            index: 0,
        }
    }

    /// Push a byte into the rolling window (O(1))
    #[inline]
    pub fn push(&mut self, byte: u8) {
        if self.len < S {
            self.inject(byte);
            self.window[self.index] = byte;
            self.index = (self.index + 1) % S;
            self.len += 1;
        } else {
            let old = self.window[self.index];
            self.remove(old);

            self.inject(byte);
            self.window[self.index] = byte;
            self.index = (self.index + 1) % S;
        }
    }

    /// Murmur-style inject
    #[inline]
    fn inject(&mut self, byte: u8) {
        let mut k = byte as u64;
        k = k.wrapping_mul(Self::C1);
        k = rotl64(k, 31);
        k = k.wrapping_mul(Self::C2);

        self.hash ^= k;
        self.hash = rotl64(self.hash, 27);
        self.hash = self.hash.wrapping_mul(5).wrapping_add(0x52dce729);
    }

    /// Inverse-safe rolling removal
    #[inline]
    fn remove(&mut self, byte: u8) {
        let mut k = byte as u64;
        k = k.wrapping_mul(Self::C1);
        k = rotl64(k, 31);
        k = k.wrapping_mul(Self::C2);

        self.hash ^= k;
    }

    /// Get finalized rolling hash
    #[inline]
    pub fn hash(&self) -> u64 {
        fmix64(self.hash ^ self.len as u64)
    }

    /// Check if the window is full
    #[inline]
    pub fn is_ready(&self) -> bool {
        self.len == S
    }

    /// Reset state
    pub fn reset(&mut self, seed: u64) {
        self.hash = seed;
        self.window = [0; S];
        self.len = 0;
        self.index = 0;
    }
}

impl<const S: usize> Default for RollingMurmur64<S> {
    fn default() -> Self {
        Self::new(0)
    }
}

impl<const S: usize> Hasher for RollingMurmur64<S> {
    fn finish(&self) -> u64 {
        self.hash
    }

    fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.push(*b);
        }
    }
}
