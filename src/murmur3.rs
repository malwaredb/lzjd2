// SPDX-License-Identifier: Apache-2.0

const C1: u32 = 0xcc9e_2d51;
const C2: u32 = 0x1b87_3593;

#[inline]
fn fmix32(mut h: u32) -> u32 {
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h
}

/// Mix one complete little-endian 32-bit block into the running hash state.
///
/// Exposed within the crate so the LZJD digest builder can hash growing
/// prefixes incrementally instead of re-scanning each slice from scratch.
#[inline]
pub(crate) fn mix_block(mut h1: u32, mut k1: u32) -> u32 {
    k1 = k1.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
    h1 ^= k1;
    h1.rotate_left(13).wrapping_mul(5).wrapping_add(0xe654_6b64)
}

/// Finalise a Murmur3 hash given the running block state, the 0–3 byte tail,
/// and the total input length. Does not mutate `h1`, so callers may reuse the
/// running state across many prefix lengths.
#[inline]
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn finalize(mut h1: u32, tail: &[u8], len: usize) -> u32 {
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

/// Standard `MurmurHash3` (x86, 32-bit) — matches jLZJD / `murmurhash3_x86_32`.
///
/// Processes `data` in 4-byte little-endian blocks, handles a 0–3 byte tail,
/// then finalises with `h ^= len; fmix32(h)`.  Seed 0 is the default used by jLZJD.
#[must_use]
pub fn murmur3_x86_32(data: &[u8], seed: u32) -> u32 {
    let len = data.len();
    let mut h1 = seed;

    let mut blocks = data.chunks_exact(4);
    for block in &mut blocks {
        let k1 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
        h1 = mix_block(h1, k1);
    }

    finalize(h1, blocks.remainder(), len)
}
