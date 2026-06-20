// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

use core::hash::Hasher;

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
    k = k.wrapping_mul(0xff51_afd7_ed55_8ccd);
    k ^= k >> 33;
    k = k.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    k ^= k >> 33;
    k
}

pub(crate) type Murmur32 = RollingMurmur32<4>;
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
    #[must_use]
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
    pub fn inject(&mut self, byte: u8) {
        let mut k = u32::from(byte);
        k = k.wrapping_mul(Self::C1);
        k = k.rotate_left(15);
        k = k.wrapping_mul(Self::C2);

        self.hash ^= k;
        self.hash = self.hash.rotate_left(13);
        self.hash = self.hash.wrapping_mul(5).wrapping_add(0xe654_6b64);
    }

    /// Inverse-mix removal (rolling-safe)
    #[inline]
    fn remove(&mut self, byte: u8) {
        let mut k = u32::from(byte);
        k = k.wrapping_mul(Self::C1);
        k = k.rotate_left(15);
        k = k.wrapping_mul(Self::C2);

        self.hash ^= k;
    }

    /// Current rolling hash (optionally finalized)
    #[inline]
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn hash(&self) -> u32 {
        fmix32(self.hash ^ self.len as u32)
    }

    /// Check if the window is full
    #[inline]
    #[must_use]
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
        u64::from(self.hash)
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
    const C1: u64 = 0x87c3_7b91_1142_53d5;
    const C2: u64 = 0x4cf5_ad43_2745_937f;

    /// Create a 64-bit Murmur3 hasher with a given seed
    #[must_use]
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
        let mut k = u64::from(byte);
        k = k.wrapping_mul(Self::C1);
        k = k.rotate_left(31);
        k = k.wrapping_mul(Self::C2);

        self.hash ^= k;
        self.hash = self.hash.rotate_left(27);
        self.hash = self.hash.wrapping_mul(5).wrapping_add(0x52dc_e729);
    }

    /// Inverse-safe rolling removal
    #[inline]
    fn remove(&mut self, byte: u8) {
        let mut k = u64::from(byte);
        k = k.wrapping_mul(Self::C1);
        k = k.rotate_left(31);
        k = k.wrapping_mul(Self::C2);

        self.hash ^= k;
    }

    /// Get finalized rolling hash
    #[inline]
    #[must_use]
    pub fn hash(&self) -> u64 {
        fmix64(self.hash ^ self.len as u64)
    }

    /// Check if the window is full
    #[inline]
    #[must_use]
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
