// SPDX-License-Identifier: Apache-2.0

use crate::murmur3::murmur3_x86_32;

use std::collections::HashSet;

use base64::{engine::general_purpose, Engine as _};

/// LZJD digest builder/configuration
pub struct Lzjd {
    /// number of k smallest hashes to keep (digest size)
    pub k: usize,
    /// seed for the `MurmurHash3` hashing
    pub seed: u32,
}

impl Default for Lzjd {
    fn default() -> Self {
        Self { k: 1024, seed: 0 }
    }
}

impl Lzjd {
    /// Create new LZJD config with given k and seed
    #[must_use]
    pub fn new(k: usize, seed: u32) -> Self {
        Self { k, seed }
    }

    /// Build an LZJD digest from input bytes using `MurmurHash3_x86_32`.
    ///
    /// Returns a `Vec<u32>` of exactly `k` entries: the k-smallest hash values (sorted
    /// ascending as signed i32, matching jLZJD), zero-padded when the input yields fewer
    /// than `k` unique LZ78 phrases.
    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    pub fn digest_from_bytes(&self, data: &[u8]) -> Vec<u32> {
        let n = data.len();
        let mut seen: HashSet<u32> = HashSet::new();
        let mut hashes: Vec<u32> = Vec::new();
        let mut start = 0usize;

        while start < n {
            let mut added = false;
            for end in (start + 1)..=n {
                let h = murmur3_x86_32(&data[start..end], self.seed);
                if seen.insert(h) {
                    hashes.push(h);
                    start = end;
                    added = true;
                    break;
                }
            }
            if !added {
                start += 1;
            }
        }

        hashes.sort_unstable_by_key(|&v| v as i32);
        if hashes.len() > self.k {
            hashes.truncate(self.k);
        } else {
            hashes.resize(self.k, 0);
        }
        hashes
    }

    /// Compute approximate Jaccard similarity between two LZJD digests (both sorted).
    ///
    /// Both inputs should be sorted ascending as signed i32 and represent the k-smallest
    /// hashes of the original sets.  Returns a value in `[0.0, 1.0]`.
    #[must_use]
    #[allow(clippy::cast_possible_wrap, clippy::cast_precision_loss, clippy::comparison_chain)]
    pub fn similarity_from_digests(a: &[u32], b: &[u32]) -> f64 {
        let mut i = 0usize;
        let mut j = 0usize;
        let mut inter = 0usize;

        while i < a.len() && j < b.len() {
            if a[i] == b[j] {
                inter += 1;
                i += 1;
                j += 1;
            } else if (a[i] as i32) < (b[j] as i32) {
                i += 1;
            } else {
                j += 1;
            }
        }

        let union = a.len() + b.len() - inter;
        if union == 0 {
            0.0
        } else {
            inter as f64 / union as f64
        }
    }

    /// Convenience: compute digest and similarity between two raw byte inputs
    #[must_use]
    pub fn similarity_bytes(&self, a: &[u8], b: &[u8]) -> f64 {
        let da = self.digest_from_bytes(a);
        let db = self.digest_from_bytes(b);
        Self::similarity_from_digests(&da, &db)
    }

    /// Convert an LZJD digest to a base64-encoded string (jLZJD-compatible format).
    ///
    /// Each `u32` entry is written as a big-endian i32 (matching Java's default byte order),
    /// producing a fixed-size array of `k` 4-byte values including any zero-padding.
    #[must_use]
    pub fn lzjd_digest_to_base64(digest: &[u32]) -> String {
        let mut bytes = Vec::with_capacity(digest.len() * 4);
        for &h in digest {
            bytes.extend_from_slice(&h.to_be_bytes());
        }
        general_purpose::STANDARD.encode(bytes)
    }

    /// Create a LZJD digest from a base64-encoded string (jLZJD-compatible format).
    ///
    /// Reads big-endian i32 values, preserving zero-padded entries.
    ///
    /// # Errors
    ///
    /// Returns an error if the base64 string is invalid or not a multiple of 4 bytes.
    pub fn lzjd_digest_from_base64(b64: &str) -> Result<Vec<u32>, String> {
        let bytes = general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| format!("Base64 decode failed: {e}"))?;

        if bytes.len() % 4 != 0 {
            return Err("Invalid LZJD Base64 length (not multiple of 4)".into());
        }

        let mut digest = Vec::with_capacity(bytes.len() / 4);
        for chunk in bytes.chunks_exact(4) {
            let h = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            digest.push(h);
        }

        Ok(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn small_digest() {
        let lz = Lzjd::new(16, 0);
        let data = b"abracadabra abracadabra";
        let digest = lz.digest_from_bytes(data);
        assert!(digest.len() <= 16);
        // subsequent call same input yields same digest
        let digest2 = lz.digest_from_bytes(data);
        assert_eq!(digest, digest2);
    }

    #[test]
    fn similarity_exact() {
        let lz = Lzjd::new(256, 0);
        let s1 = b"the quick brown fox jumps over the lazy dog";
        let s2 = b"the quick brown fox jumps over the lazy dog";
        let sim = lz.similarity_bytes(s1, s2);
        eprintln!("similarity: {sim}");
        assert!((sim - 1.0).abs() < 1e-12);
    }

    #[test]
    fn similarity() {
        let lz = Lzjd::new(256, 0);
        let s1 = b"the quick brown Fox jumps over the lazy dog";
        let s2 = b"the quick brown fox jumps over the lazy dog_";
        let sim = lz.similarity_bytes(s1, s2);
        assert!(sim >= 0.9);
    }

    #[test]
    fn roundtrip_lzjd() {
        let lz = Lzjd::default();

        let data = b"the quick brown fox jumps over the lazy dog";

        // Build digest
        let digest = lz.digest_from_bytes(data);

        // Save to Base64
        let b64 = Lzjd::lzjd_digest_to_base64(&digest);
        println!("Base64 LZJD: {b64}");

        // Load from Base64
        let decoded = Lzjd::lzjd_digest_from_base64(&b64).unwrap();

        // Verify exact match
        assert_eq!(digest, decoded);
    }

    #[rstest]
    #[case(include_str!("../testdata/lorem_ipsum_5.txt"), include_str!("../testdata/lorem_ipsum_5.lzjd.txt"))]
    #[case(include_str!("../testdata/lorem_ipsum_6.txt"), include_str!("../testdata/lorem_ipsum_6.lzjd.txt"))]
    #[case(include_str!("../testdata/lorem_ipsum_10.txt"), include_str!("../testdata/lorem_ipsum_10.lzjd.txt"))]
    #[test]
    fn lorem_ipsum(#[case] data: &str, #[case] expected_hash: &str) {
        let lz = Lzjd::new(1024, 0);
        let digest = lz.digest_from_bytes(data.as_bytes());
        let lzjd_hash = Lzjd::lzjd_digest_to_base64(&digest);
        assert_eq!(lzjd_hash, expected_hash);

        let decoded = Lzjd::lzjd_digest_from_base64(expected_hash).unwrap();
        assert_eq!(digest, decoded);

        let similarity = Lzjd::similarity_from_digests(&digest, &decoded);
        assert_eq!(format!("{similarity:.2}"), "1.00");
    }
}
