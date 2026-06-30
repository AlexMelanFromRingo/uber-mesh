//! Content-addressed store: maps `Cid` → bytes, self-certifying (FR-011).
//!
//! Every object is keyed by `BLAKE3(content)`, so a receiver can verify retrieved bytes against the
//! id before trusting them. This is the local cache the blob request/response protocol serves from.

use std::collections::HashMap;

use umesh_crypto::hash::Cid;

/// A bounded-by-caller in-memory content store.
#[derive(Default)]
pub struct ContentStore {
    map: HashMap<[u8; 32], Vec<u8>>,
}

impl ContentStore {
    /// Empty store.
    pub fn new() -> Self {
        ContentStore::default()
    }

    /// Insert content, returning its `Cid`. Idempotent for identical content.
    pub fn put(&mut self, data: Vec<u8>) -> Cid {
        let cid = Cid::of(&data);
        self.map.insert(*cid.as_bytes(), data);
        cid
    }

    /// Fetch content by `Cid`.
    pub fn get(&self, cid: &Cid) -> Option<&[u8]> {
        self.map.get(cid.as_bytes()).map(|v| v.as_slice())
    }

    /// Whether the store holds `cid`.
    pub fn has(&self, cid: &Cid) -> bool {
        self.map.contains_key(cid.as_bytes())
    }

    /// Number of stored objects.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_roundtrip_and_verify() {
        let mut s = ContentStore::new();
        let cid = s.put(b"hello mesh".to_vec());
        assert!(s.has(&cid));
        assert_eq!(s.get(&cid), Some(&b"hello mesh"[..]));
        // The Cid genuinely certifies the content.
        assert!(cid.verifies(s.get(&cid).unwrap()));
    }

    #[test]
    fn unknown_cid_absent() {
        let s = ContentStore::new();
        assert_eq!(s.get(&Cid::of(b"nope")), None);
        assert!(s.is_empty());
    }

    #[test]
    fn dedup_identical_content() {
        let mut s = ContentStore::new();
        let a = s.put(b"x".to_vec());
        let b = s.put(b"x".to_vec());
        assert_eq!(a, b);
        assert_eq!(s.len(), 1);
    }
}
