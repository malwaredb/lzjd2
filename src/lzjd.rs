// SPDX-License-Identifier: Apache-2.0

use crate::murmur3::{RollingMurmur32, RollingMurmur64};

use std::hash::Hasher;
use std::collections::HashSet;

use base64::{engine::general_purpose, Engine as _};

/// LZJD digest builder/configuration
pub struct Lzjd {
    /// number of k smallest hashes to keep (digest size)
    pub k: usize,
    /// seed for the MurmurHash3 hashing
    pub seed: u32,
}

impl Default for Lzjd {
    fn default() -> Self {
        Self { k: 1024, seed: 0 }
    }
}

impl Lzjd {
    /// Create new LZJD config with given k and seed
    pub fn new(k: usize, seed: u32) -> Self {
        Self { k, seed }
    }

    /// Build an LZSet-like digest from input bytes.
    ///
    /// Returns a Vec<u32> of length <= k containing the smallest unique hash values,
    /// sorted ascending. If fewer than k unique hashes were produced, the result
    /// will be shorter.
    pub fn digest_from_bytes(&self, data: &[u8]) -> Vec<u32> {
        let n = data.len();
        // store seen hashes (set of hashes added to the LZ set)
        let mut seen: HashSet<u32> = HashSet::new();

        // store unique hashes in a Vec (we'll extract k smallest at the end)
        let mut hashes: Vec<u32> = Vec::new();

        let mut start = 0usize;
        // 'end' starts at start+1 per the algorithm: substrings are [start..end)

        let mut hasher = RollingMurmur32::<4>::new(self.seed);
        while start < n {
            let mut end = start + 1;
            let mut added = false;

            while end <= n {
                hasher.reset(self.seed);
                let slice = &data[start..end];
                hasher.write(slice);
                let h = hasher.hash();

                if !seen.contains(&h) {
                    // new substring: add its hash
                    seen.insert(h);
                    hashes.push(h);
                    // advance the start to end and reset desired length
                    start = end;
                    added = true;
                    break;
                } else {
                    // substring seen before, try a longer substring
                    end += 1;
                }
            }

            if !added {
                // If end ran past n and we never added a new substring, increment start by 1
                // to avoid infinite loop. This only happens when remaining substrings all
                // produce hashes that were seen before — move forward by 1.
                start += 1;
            }
        }

        // Now we have the set (in 'hashes', but may contain duplicates if hash collisions caused an
        // equal u32 that was inserted earlier? We used seen HashSet so duplicates shouldn't be present.)
        // Extract k smallest unique values.
        hashes.sort_unstable();
        hashes.truncate(self.k);
        hashes
    }

    /// Build dual digest: (Vec<u32>, Vec<u64>) both sorted ascending and truncated to k
    pub fn dual_digest_from_bytes(&self, data: &[u8]) -> (Vec<u32>, Vec<u64>) {
        let n = data.len();
        let mut seen32: HashSet<u32> = HashSet::new();
        let mut seen64: HashSet<u64> = HashSet::new();

        let mut hashes32: Vec<u32> = Vec::new();
        let mut hashes64: Vec<u64> = Vec::new();

        let mut start = 0usize;
        let mut hasher32 = RollingMurmur32::<4>::new(self.seed);
        let mut hasher64 = RollingMurmur64::<8>::new(self.seed as u64);
        while start < n {
            let mut end = start + 1;
            let mut added = false;

            while end <= n {
                let slice = &data[start..end];
                // 32-bit hash (assumes murmur3_32 is present)
                hasher32.reset(self.seed);
                hasher32.write(slice);
                let h32 = hasher32.hash();
                // 64-bit: use first u64 from x64_128
                hasher64.reset(self.seed as u64);
                hasher64.write(slice);
                let h64 = hasher64.hash();

                if !seen32.contains(&h32) || !seen64.contains(&h64) {
                    // Insert into both seen sets (attempt to keep both unique collections)
                    if !seen32.contains(&h32) {
                        seen32.insert(h32);
                        hashes32.push(h32);
                    }
                    if !seen64.contains(&h64) {
                        seen64.insert(h64);
                        hashes64.push(h64);
                    }

                    start = end;
                    added = true;
                    break;
                } else {
                    end += 1;
                }
            }

            if !added {
                start += 1;
            }
        }

        hashes32.sort_unstable();
        hashes32.truncate(self.k);

        hashes64.sort_unstable();
        hashes64.truncate(self.k);

        (hashes32, hashes64)
    }

    /// Compute approximate Jaccard similarity between two LZJD digests (both sorted).
    ///
    /// Both inputs should be sorted ascending and represent the k-smallest hashes of the original sets.
    /// Returns a value in [0.0, 1.0].
    pub fn similarity_from_digests(a: &[u32], b: &[u32]) -> f64 {
        let mut i = 0usize;
        let mut j = 0usize;
        let mut inter = 0usize;

        while i < a.len() && j < b.len() {
            if a[i] == b[j] {
                inter += 1;
                i += 1;
                j += 1;
            } else if a[i] < b[j] {
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

    /// Similarity on 64-bit digests
    pub fn similarity_from_digests64(a: &[u64], b: &[u64]) -> f64 {
        let mut i = 0usize;
        let mut j = 0usize;
        let mut inter = 0usize;
        while i < a.len() && j < b.len() {
            if a[i] == b[j] {
                inter += 1; i += 1; j += 1;
            } else if a[i] < b[j] {
                i += 1;
            } else {
                j += 1;
            }
        }
        let union = a.len() + b.len() - inter;
        if union == 0 { 0.0 } else { inter as f64 / union as f64 }
    }

    /// Convenience: compute digest and similarity between two raw byte inputs
    pub fn similarity_bytes(&self, a: &[u8], b: &[u8]) -> f64 {
        let da = self.digest_from_bytes(a);
        let db = self.digest_from_bytes(b);
        Self::similarity_from_digests(&da, &db)
    }

    /// Combined similarity: weighted average of 32-bit and 64-bit similarities.
    /// weight64 in [0.0..1.0] is the relative weight given to the 64-bit similarity.
    pub fn combined_similarity(a32: &[u32], b32: &[u32], a64: &[u64], b64: &[u64], weight64: f64) -> f64 {
        let s32 = Self::similarity_from_digests(a32, b32);
        let s64 = Self::similarity_from_digests64(a64, b64);
        let w64 = weight64.clamp(0.0, 1.0);
        let w32 = 1.0 - w64;
        w32 * s32 + w64 * s64
    }

    /// Convert an LZJD digest to a base64-encoded string.
    pub fn lzjd_digest_to_base64(digest: &[u32]) -> String {
        // Convert u32 -> little-endian bytes
        let mut bytes = Vec::with_capacity(digest.len() * 4);
        for &h in digest {
            bytes.extend_from_slice(&h.to_le_bytes());
        }

        general_purpose::STANDARD.encode(bytes)
    }

    /// Create a LZJD digest from a base64-encoded string.
    pub fn lzjd_digest_from_base64(b64: &str) -> Result<Vec<u32>, String> {
        let bytes = general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| format!("Base64 decode failed: {e}"))?;

        if bytes.len() % 4 != 0 {
            return Err("Invalid LZJD Base64 length (not multiple of 4)".into());
        }

        let mut digest = Vec::with_capacity(bytes.len() / 4);
        for chunk in bytes.chunks_exact(4) {
            let h = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            digest.push(h);
        }

        Ok(digest)
    }

    /// Encode dual digest to Base64:
    /// layout: [u32_count: u32 LE][u32 values (LE)*][u64_count: u32 LE][u64 values (LE)*]
    pub fn encode_dual_to_base64(u32s: &[u32], u64s: &[u64]) -> String {
        let mut bytes = Vec::with_capacity(4 + u32s.len()*4 + 4 + u64s.len()*8);
        // counts as u32 little-endian
        bytes.extend_from_slice(&(u32s.len() as u32).to_le_bytes());
        for &v in u32s {
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        bytes.extend_from_slice(&(u64s.len() as u32).to_le_bytes());
        for &v in u64s {
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        general_purpose::STANDARD.encode(bytes)
    }

    /// Decode Base64 into dual digest (Vec<u32>, Vec<u64>)
    pub fn decode_dual_from_base64(s: &str) -> Result<(Vec<u32>, Vec<u64>), String> {
        let bytes = general_purpose::STANDARD.decode(s).map_err(|e| format!("Base64 decode failed: {e}"))?;
        if bytes.len() < 8 {
            return Err("Encoded dual digest too short".into());
        }
        let mut offset = 0usize;
        // read u32 count
        let count32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        offset += 4;
        if bytes.len() < offset + count32*4 + 4 {
            return Err("Invalid length for u32 entries".into());
        }
        let mut u32s = Vec::with_capacity(count32);
        for _ in 0..count32 {
            let v = u32::from_le_bytes([bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3]]);
            u32s.push(v);
            offset += 4;
        }
        // read u64 count
        let count64 = u32::from_le_bytes([bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3]]) as usize;
        offset += 4;
        if bytes.len() != offset + count64*8 {
            return Err("Invalid length for u64 entries".into());
        }
        let mut u64s = Vec::with_capacity(count64);
        for _ in 0..count64 {
            let v = u64::from_le_bytes([
                bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3],
                bytes[offset+4], bytes[offset+5], bytes[offset+6], bytes[offset+7],
            ]);
            u64s.push(v);
            offset += 8;
        }
        Ok((u32s, u64s))
    }
}

#[cfg(test)]
mod tests {
    use malwaredb_lzjd::crc32::CRC32BuildHasher;
    use malwaredb_lzjd::LZDict;
    use super::*;

    #[test]
    fn test_small_digest() {
        let lz = Lzjd::new(16, 0);
        let data = b"abracadabra abracadabra";
        let digest = lz.digest_from_bytes(data);
        assert!(digest.len() <= 16);
        // subsequent call same input yields same digest
        let digest2 = lz.digest_from_bytes(data);
        assert_eq!(digest, digest2);
    }

    #[test]
    fn test_similarity() {
        let lz = Lzjd::new(256, 0);
        let s1 = b"the quick brown fox jumps over the lazy dog";
        let s2 = b"the quick brown fox jumps over the lazy dog";
        let sim = lz.similarity_bytes(s1, s2);
        assert!((sim - 1.0).abs() < 1e-12);
    }

    #[test]
    fn test_lzjd() {
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

    #[test]
    fn test_dual_digest_roundtrip() {
        let lz = Lzjd::new(32, 0);
        let data = b"abracadabra abracadabra";
        let (d32, d64) = lz.dual_digest_from_bytes(data);

        let enc = Lzjd::encode_dual_to_base64(&d32, &d64);
        let (rd32, rd64) = Lzjd::decode_dual_from_base64(&enc).unwrap();
        assert_eq!(d32, rd32);
        assert_eq!(d64, rd64);
    }

    #[test]
    fn test_similarity_combined() {
        let lz = Lzjd::new(256, 0);
        let s1 = b"the quick brown fox jumps over the lazy dog";
        let s2 = b"the quick brown fox jumps over the lazy dog";
        let (a32, a64) = lz.dual_digest_from_bytes(s1);
        let (b32, b64) = lz.dual_digest_from_bytes(s2);
        let comb = Lzjd::combined_similarity(&a32, &b32, &a64, &b64, 0.5);
        assert!((comb - 1.0).abs() < 1e-12);
    }

    #[test]
    fn lorem_ipsum() {
        const LOREM_IPSUM_5: &str = include_str!("../testdata/lorem_ipsum_5.txt");
        const LOREM_IPSUM_LZJD: &str = include_str!("../testdata/lorem_ipsum_5.lzjd.txt");

        let lz = Lzjd::new(1024, 0);
        let digest = lz.digest_from_bytes(LOREM_IPSUM_5.as_bytes());
        let lzjd_hash = Lzjd::lzjd_digest_to_base64(&digest);

        //assert_eq!(lzjd_hash, LOREM_IPSUM_LZJD);

        let decoded = Lzjd::lzjd_digest_from_base64(LOREM_IPSUM_LZJD).unwrap();
        //assert_eq!(digest, decoded);

        let simarlity = Lzjd::similarity_from_digests(&digest, &decoded);
        assert_eq!(format!("{:.2}", simarlity), "1.00");
    }

    #[test]
    fn lorem_ipsum_dual() {
        const LOREM_IPSUM_5: &str = include_str!("../testdata/lorem_ipsum_5.txt");
        const LOREM_IPSUM_LZJD: &str = include_str!("../testdata/lorem_ipsum_5.lzjd.txt");

        let lz = Lzjd::new(1024, 0);
        let (digest32_gen, digest64_gen) = lz.dual_digest_from_bytes(LOREM_IPSUM_5.as_bytes());
        let (digest32_decoded, digest64_decoded) = Lzjd::decode_dual_from_base64(LOREM_IPSUM_LZJD).unwrap();

        let simarlity = Lzjd::combined_similarity(&digest32_gen, &digest32_decoded, &digest64_gen, &digest64_decoded, 0.5);
        assert_eq!(format!("{:.2}", simarlity), "1.00");
    }

    #[test]
    fn lorem_ipsem_mdb_lzjd() {
        const LOREM_IPSUM_5: &str = include_str!("../testdata/lorem_ipsum_5.txt");
        const LOREM_IPSUM_LZJD: &str = include_str!("../testdata/lorem_ipsum_5.lzjd.txt");

        let lz = Lzjd::new(1024, 0);
        let digest = lz.digest_from_bytes(LOREM_IPSUM_5.as_bytes());
        let new_hash = Lzjd::lzjd_digest_to_base64(&digest);

        let old_hash = LZDict::from_base64_string(LOREM_IPSUM_LZJD).unwrap();
        assert_eq!(LOREM_IPSUM_LZJD, format!("{old_hash}"));
        assert_eq!(new_hash, format!("{old_hash}"));

        let build_hasher = CRC32BuildHasher;
        let lz_dict = LZDict::from_bytes_stream(LOREM_IPSUM_5.as_bytes().iter().cloned(), &build_hasher);
        let old_sim = lz_dict.jaccard_similarity(&old_hash);
        assert_eq!(format!("{:.2}", old_sim), "1.00");
    }
}