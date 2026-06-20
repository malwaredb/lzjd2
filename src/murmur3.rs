// SPDX-License-Identifier: Apache-2.0

#[inline]
fn fmix32(mut h: u32) -> u32 {
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h
}

/// Standard `MurmurHash3` (x86, 32-bit) — matches jLZJD / `murmurhash3_x86_32`.
///
/// Processes `data` in 4-byte little-endian blocks, handles a 0–3 byte tail,
/// then finalises with `h ^= len; fmix32(h)`.  Seed 0 is the default used by jLZJD.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn murmur3_x86_32(data: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;

    let len = data.len();
    let n_blocks = len / 4;
    let mut h1 = seed;

    for i in 0..n_blocks {
        let k_bytes = [data[4 * i], data[4 * i + 1], data[4 * i + 2], data[4 * i + 3]];
        let mut k1 = u32::from_le_bytes(k_bytes);
        k1 = k1.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h1 ^= k1;
        h1 = h1.rotate_left(13).wrapping_mul(5).wrapping_add(0xe654_6b64);
    }

    let tail = &data[n_blocks * 4..];
    let mut k1: u32 = 0;
    if tail.len() == 3 {
        k1 ^= u32::from(tail[2]) << 16;
    }
    if tail.len() >= 2 {
        k1 ^= u32::from(tail[1]) << 8;
    }
    if !tail.is_empty() {
        k1 ^= u32::from(tail[0]);
        k1 = k1.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h1 ^= k1;
    }

    h1 ^= len as u32;
    fmix32(h1)
}
