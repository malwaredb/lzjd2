// SPDX-License-Identifier: Apache-2.0

use crate::murmur3::murmur3_x86_32;

use std::collections::HashSet;

use base64::{engine::general_purpose, Engine as _};

/// LZJD digest builder/configuration
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lzjd {
    /// number of k smallest hashes to keep (digest size)
    k: usize,

    /// seed for the `MurmurHash3` hashing
    seed: u32,
}

impl Default for Lzjd {
    #[inline]
    fn default() -> Self {
        Self { k: 1024, seed: 0 }
    }
}

impl Lzjd {
    /// Create a new Lzjd hasher with given size and seed
    #[inline]
    #[must_use]
    pub fn new(k: usize, seed: u32) -> Self {
        Self { k, seed }
    }

    /// Build an [`LzDigest`] digest from input bytes. Two digests can be used to find similarity,
    /// or a digest can be saved to a string.
    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    pub fn digest_from_bytes(&self, data: &[u8]) -> LzDigest {
        let n = data.len();
        let mut seen = HashSet::new();
        let mut hashes = Vec::new();
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
        if hashes.len() != self.k {
            hashes.resize(self.k, 0);
        }

        LzDigest { digest: hashes }
    }

    /// Convenience: compute digest and similarity between two raw byte inputs
    #[inline]
    #[must_use]
    pub fn similarity_bytes(&self, a: &[u8], b: &[u8]) -> f32 {
        let da = self.digest_from_bytes(a);
        let db = self.digest_from_bytes(b);
        da.similarity(&db)
    }
}

/// LZJD digest
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct LzDigest {
    digest: Vec<u32>,
}

impl LzDigest {
    /// Convert an LZJD digest from base64 to an [`LzDigest`]
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not valid base64 or if the decoded length is not a multiple of 4.
    pub fn from_string(s: &str) -> Result<Self, String> {
        let bytes = general_purpose::STANDARD
            .decode(s)
            .map_err(|e| format!("Base64 decode failed: {e}"))?;

        if bytes.len() % 4 != 0 {
            return Err("Invalid LZJD Base64 length (not multiple of 4)".into());
        }

        let mut digest = Vec::with_capacity(bytes.len() / 4);
        for chunk in bytes.chunks_exact(4) {
            let h = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            digest.push(h);
        }

        Ok(Self { digest })
    }

    /// Compute approximate Jaccard similarity between two LZJD digests.
    ///
    /// Returns a value in `[0.0, 1.0]`.
    #[must_use]
    #[allow(
        clippy::cast_possible_wrap,
        clippy::cast_precision_loss,
        clippy::comparison_chain
    )]
    pub fn similarity(&self, other: &Self) -> f32 {
        let mut i = 0usize;
        let mut j = 0usize;
        let mut inter = 0usize;

        while i < self.digest.len() && j < other.digest.len() {
            if self.digest[i] == other.digest[j] {
                inter += 1;
                i += 1;
                j += 1;
            } else if (self.digest[i] as i32) < (other.digest[j] as i32) {
                i += 1;
            } else {
                j += 1;
            }
        }

        let union = self.digest.len() + other.digest.len() - inter;
        if union == 0 {
            0.0
        } else {
            inter as f32 / union as f32
        }
    }
}

impl From<LzDigest> for String {
    fn from(d: LzDigest) -> Self {
        d.to_string()
    }
}

impl From<&LzDigest> for String {
    fn from(d: &LzDigest) -> Self {
        d.to_string()
    }
}

impl From<&[u8]> for LzDigest {
    fn from(data: &[u8]) -> Self {
        Lzjd::default().digest_from_bytes(data)
    }
}

impl std::fmt::Display for LzDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut bytes = Vec::with_capacity(self.digest.len() * 4);
        for h in &self.digest {
            bytes.extend_from_slice(&h.to_be_bytes());
        }
        write!(f, "{}", general_purpose::STANDARD.encode(bytes))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for LzDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for LzDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        LzDigest::from_string(&s).map_err(serde::de::Error::custom)
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
        assert!(digest.digest.len() <= 16);
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
        let b64 = digest.to_string();
        println!("Base64 LZJD: {b64}");

        // Load from Base64
        let decoded = LzDigest::from_string(&b64).unwrap();

        // Verify exact match
        assert_eq!(digest, decoded);
    }

    #[rstest]
    #[case(include_bytes!("../testdata/lorem_ipsum_5.txt"), include_str!("../testdata/lorem_ipsum_5.lzjd.txt"))]
    #[case(include_bytes!("../testdata/lorem_ipsum_6.txt"), include_str!("../testdata/lorem_ipsum_6.lzjd.txt"))]
    #[case(include_bytes!("../testdata/lorem_ipsum_10.txt"), include_str!("../testdata/lorem_ipsum_10.lzjd.txt"))]
    #[case(include_bytes!("../testdata/random.bin"), include_str!("../testdata/random.bin.lzjd.txt"))]
    #[test]
    fn lorem_ipsum(#[case] data: &[u8], #[case] expected_hash: &str) {
        let lz = Lzjd::new(1024, 0);
        let digest = lz.digest_from_bytes(data);
        let lzjd_hash = digest.to_string();
        assert_eq!(lzjd_hash, expected_hash);

        let decoded = LzDigest::from_string(expected_hash).unwrap();
        assert_eq!(digest, decoded);

        let similarity = digest.similarity(&decoded);
        assert_eq!(format!("{similarity:.2}"), "1.00");
    }
}
