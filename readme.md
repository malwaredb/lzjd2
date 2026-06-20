[![Lint](https://github.com/malwaredb/lzjd2/actions/workflows/lint.yml/badge.svg)](https://github.com/malwaredb/lzjd2/actions/workflows/lint.yml)
[![Crates.io Version](https://img.shields.io/crates/v/malwaredb-lzjd2)](https://crates.io/crates/malwaredb-lzjd2)

## Lempel-Ziv Jaccard Distance

Rust implementation of Lempel-Ziv Jaccard Distance by [Edward Raff](https://github.com/EdwardRaff/jLZJD).

## Using it

Add this to your `Cargo.toml`:
```toml
[dependencies]
malwaredb-lzjd2 = "0.0.1"
```

One-liner to get a hash:
```rust
use malwaredb_lzjd2::lzjd::LzDigest;

let contents: Vec<u8> = b"Hello, world!".to_vec();
let lzjd_str = LzDigest::from(contents.as_ref()).to_string();
```

Compare hashes:
```rust
use malwaredb_lzjd2::lzjd::LzDigest;

let data1: Vec<u8> = b"Hello, world!".to_vec();
let data2: Vec<u8> = b"Hola amigo!".to_vec();

let lzjd1 = LzDigest::from(data1.as_ref());
let lzjd2 = LzDigest::from(data2.as_ref());

assert!(lzjd1.similarity(&lzjd2) > 0.5);
```
