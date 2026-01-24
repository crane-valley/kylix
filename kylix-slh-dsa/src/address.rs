//! ADRS (Address) structure for domain separation in SLH-DSA.
//!
//! The 32-byte ADRS structure is used to provide domain separation for all
//! hash function calls in SLH-DSA. Different address types have different
//! field layouts as specified in FIPS 205, Tables 2-8.

use zeroize::Zeroize;

/// ADRS type constants as defined in FIPS 205, Table 1.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdrsType {
    /// WOTS+ hash address (used in chain computation).
    WotsHash = 0,
    /// WOTS+ public key compression address.
    WotsPk = 1,
    /// Merkle tree node address.
    Tree = 2,
    /// FORS tree address.
    ForsTree = 3,
    /// FORS public key compression address.
    ForsPk = 4,
    /// WOTS+ PRF address (secret key generation).
    WotsPrf = 5,
    /// FORS PRF address (secret key generation).
    ForsPrf = 6,
}

/// 32-byte ADRS structure for domain separation.
///
/// The ADRS structure layout varies by type:
///
/// Common fields (all types):
/// - Bytes 0-3: Layer address (big-endian u32)
/// - Bytes 4-15: Tree address (big-endian, up to 12 bytes)
/// - Bytes 16-19: Type (big-endian u32)
///
/// WOTS+ specific (WotsHash, WotsPk, WotsPrf):
/// - Bytes 20-23: Key pair address
/// - Bytes 24-27: Chain address (WotsHash only)
/// - Bytes 28-31: Hash address (WotsHash only)
///
/// Tree/FORS specific (Tree, ForsTree, ForsPk, ForsPrf):
/// - Bytes 20-23: Key pair address (ForsPrf, ForsTree, ForsPk)
/// - Bytes 24-27: Tree height
/// - Bytes 28-31: Tree index
#[derive(Clone, Copy, Zeroize)]
pub struct Address {
    bytes: [u8; 32],
}

impl Default for Address {
    fn default() -> Self {
        Self::new()
    }
}

impl Address {
    /// Create a new zeroed address.
    #[must_use]
    pub const fn new() -> Self {
        Self { bytes: [0u8; 32] }
    }

    /// Create an address from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Get the raw bytes of the address.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Get a mutable reference to the raw bytes.
    pub fn as_bytes_mut(&mut self) -> &mut [u8; 32] {
        &mut self.bytes
    }

    // =========================================================================
    // Common field accessors (bytes 0-19)
    // =========================================================================

    /// Set the layer address (bytes 0-3, big-endian u32).
    pub fn set_layer(&mut self, layer: u32) {
        self.bytes[0..4].copy_from_slice(&layer.to_be_bytes());
    }

    /// Get the layer address.
    #[must_use]
    pub fn layer(&self) -> u32 {
        u32::from_be_bytes([self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]])
    }

    /// Set the tree address (bytes 4-15, big-endian).
    /// Uses the lower 12 bytes to store up to 96-bit tree index.
    pub fn set_tree(&mut self, tree: u64) {
        // Store in bytes 8-15 (lower 64 bits), leaving bytes 4-7 as zero
        self.bytes[4..8].copy_from_slice(&[0u8; 4]);
        self.bytes[8..16].copy_from_slice(&tree.to_be_bytes());
    }

    /// Get the tree address (lower 64 bits).
    #[must_use]
    pub fn tree(&self) -> u64 {
        u64::from_be_bytes([
            self.bytes[8],
            self.bytes[9],
            self.bytes[10],
            self.bytes[11],
            self.bytes[12],
            self.bytes[13],
            self.bytes[14],
            self.bytes[15],
        ])
    }

    /// Set the address type (bytes 16-19, big-endian u32).
    ///
    /// FIPS 205's setTypeAndClear operation clears only the fields that become
    /// "Unused" in the new type. Different types share some fields:
    /// - Key Pair Address (bytes 20-23): used by WOTS_HASH, WOTS_PK, WOTS_PRF, FORS types
    /// - Chain Address (bytes 24-27): used by WOTS_HASH, WOTS_PRF
    /// - etc.
    ///
    /// When changing type, we clear bytes 24-31 but preserve bytes 20-23 (key pair)
    /// for types that use it. The caller should explicitly set any fields needed.
    pub fn set_type(&mut self, adrs_type: AdrsType) {
        let keypair = self.keypair();
        self.bytes[16..20].copy_from_slice(&(adrs_type as u32).to_be_bytes());
        // Clear bytes 20-31 when changing type
        self.bytes[20..32].fill(0);
        // Restore key pair address for types that use it
        match adrs_type {
            AdrsType::WotsHash
            | AdrsType::WotsPk
            | AdrsType::WotsPrf
            | AdrsType::ForsTree
            | AdrsType::ForsPk
            | AdrsType::ForsPrf => {
                self.set_keypair(keypair);
            }
            AdrsType::Tree => {
                // Tree type doesn't use key pair address (bytes 20-23 are Unused)
            }
        }
    }

    /// Get the address type.
    #[must_use]
    pub fn adrs_type(&self) -> u32 {
        u32::from_be_bytes([
            self.bytes[16],
            self.bytes[17],
            self.bytes[18],
            self.bytes[19],
        ])
    }

    // =========================================================================
    // WOTS+ specific fields (bytes 20-31)
    // =========================================================================

    /// Set the key pair address (bytes 20-23, big-endian u32).
    /// Used by: WotsHash, WotsPk, WotsPrf, ForsTree, ForsPk, ForsPrf
    pub fn set_keypair(&mut self, keypair: u32) {
        self.bytes[20..24].copy_from_slice(&keypair.to_be_bytes());
    }

    /// Get the key pair address.
    #[must_use]
    pub fn keypair(&self) -> u32 {
        u32::from_be_bytes([
            self.bytes[20],
            self.bytes[21],
            self.bytes[22],
            self.bytes[23],
        ])
    }

    /// Set the chain address (bytes 24-27, big-endian u32).
    /// Used by: WotsHash
    pub fn set_chain(&mut self, chain: u32) {
        self.bytes[24..28].copy_from_slice(&chain.to_be_bytes());
    }

    /// Get the chain address.
    #[must_use]
    pub fn chain(&self) -> u32 {
        u32::from_be_bytes([
            self.bytes[24],
            self.bytes[25],
            self.bytes[26],
            self.bytes[27],
        ])
    }

    /// Set the hash address (bytes 28-31, big-endian u32).
    /// Used by: WotsHash
    pub fn set_hash(&mut self, hash: u32) {
        self.bytes[28..32].copy_from_slice(&hash.to_be_bytes());
    }

    /// Get the hash address.
    #[must_use]
    pub fn hash(&self) -> u32 {
        u32::from_be_bytes([
            self.bytes[28],
            self.bytes[29],
            self.bytes[30],
            self.bytes[31],
        ])
    }

    // =========================================================================
    // Tree/FORS specific fields (bytes 24-31)
    // =========================================================================

    /// Set the tree height (bytes 24-27, big-endian u32).
    /// Used by: Tree, ForsTree
    pub fn set_tree_height(&mut self, height: u32) {
        self.bytes[24..28].copy_from_slice(&height.to_be_bytes());
    }

    /// Get the tree height.
    #[must_use]
    pub fn tree_height(&self) -> u32 {
        u32::from_be_bytes([
            self.bytes[24],
            self.bytes[25],
            self.bytes[26],
            self.bytes[27],
        ])
    }

    /// Set the tree index (bytes 28-31, big-endian u32).
    /// Used by: Tree, ForsTree
    pub fn set_tree_index(&mut self, index: u32) {
        self.bytes[28..32].copy_from_slice(&index.to_be_bytes());
    }

    /// Get the tree index.
    #[must_use]
    pub fn tree_index(&self) -> u32 {
        u32::from_be_bytes([
            self.bytes[28],
            self.bytes[29],
            self.bytes[30],
            self.bytes[31],
        ])
    }

    // =========================================================================
    // Convenience methods for creating specific address types
    // =========================================================================

    /// Create a WOTS+ hash address.
    #[must_use]
    pub fn wots_hash(layer: u32, tree: u64, keypair: u32, chain: u32, hash: u32) -> Self {
        let mut adrs = Self::new();
        adrs.set_layer(layer);
        adrs.set_tree(tree);
        adrs.set_type(AdrsType::WotsHash);
        adrs.set_keypair(keypair);
        adrs.set_chain(chain);
        adrs.set_hash(hash);
        adrs
    }

    /// Create a WOTS+ public key address.
    #[must_use]
    pub fn wots_pk(layer: u32, tree: u64, keypair: u32) -> Self {
        let mut adrs = Self::new();
        adrs.set_layer(layer);
        adrs.set_tree(tree);
        adrs.set_type(AdrsType::WotsPk);
        adrs.set_keypair(keypair);
        adrs
    }

    /// Create a WOTS+ PRF address.
    #[must_use]
    pub fn wots_prf(layer: u32, tree: u64, keypair: u32, chain: u32) -> Self {
        let mut adrs = Self::new();
        adrs.set_layer(layer);
        adrs.set_tree(tree);
        adrs.set_type(AdrsType::WotsPrf);
        adrs.set_keypair(keypair);
        adrs.set_chain(chain);
        adrs
    }

    /// Create a tree node address.
    #[must_use]
    pub fn tree_node(layer: u32, tree: u64, height: u32, index: u32) -> Self {
        let mut adrs = Self::new();
        adrs.set_layer(layer);
        adrs.set_tree(tree);
        adrs.set_type(AdrsType::Tree);
        adrs.set_tree_height(height);
        adrs.set_tree_index(index);
        adrs
    }

    /// Create a FORS tree address.
    #[must_use]
    pub fn fors_tree(layer: u32, tree: u64, keypair: u32, height: u32, index: u32) -> Self {
        let mut adrs = Self::new();
        adrs.set_layer(layer);
        adrs.set_tree(tree);
        adrs.set_type(AdrsType::ForsTree);
        adrs.set_keypair(keypair);
        adrs.set_tree_height(height);
        adrs.set_tree_index(index);
        adrs
    }

    /// Create a FORS public key address.
    #[must_use]
    pub fn fors_pk(layer: u32, tree: u64, keypair: u32) -> Self {
        let mut adrs = Self::new();
        adrs.set_layer(layer);
        adrs.set_tree(tree);
        adrs.set_type(AdrsType::ForsPk);
        adrs.set_keypair(keypair);
        adrs
    }

    /// Create a FORS PRF address.
    #[must_use]
    pub fn fors_prf(layer: u32, tree: u64, keypair: u32, height: u32, index: u32) -> Self {
        let mut adrs = Self::new();
        adrs.set_layer(layer);
        adrs.set_tree(tree);
        adrs.set_type(AdrsType::ForsPrf);
        adrs.set_keypair(keypair);
        adrs.set_tree_height(height);
        adrs.set_tree_index(index);
        adrs
    }

    /// Copy the address with a different type.
    /// Clears type-specific fields (bytes 20-31).
    #[must_use]
    pub fn with_type(&self, adrs_type: AdrsType) -> Self {
        let mut copy = *self;
        copy.set_type(adrs_type);
        copy
    }
}

impl core::fmt::Debug for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Address")
            .field("layer", &self.layer())
            .field("tree", &self.tree())
            .field("type", &self.adrs_type())
            .field("keypair", &self.keypair())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_new() {
        let adrs = Address::new();
        assert_eq!(adrs.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_layer_address() {
        let mut adrs = Address::new();
        adrs.set_layer(0x12345678);
        assert_eq!(adrs.layer(), 0x12345678);
        assert_eq!(&adrs.bytes[0..4], &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_tree_address() {
        let mut adrs = Address::new();
        adrs.set_tree(0x0102030405060708);
        assert_eq!(adrs.tree(), 0x0102030405060708);
    }

    #[test]
    fn test_type_clears_trailing_bytes() {
        // Test Tree type: clears all fields (bytes 20-31)
        let mut adrs = Address::new();
        adrs.set_keypair(0xFFFFFFFF);
        adrs.set_chain(0xFFFFFFFF);
        adrs.set_hash(0xFFFFFFFF);

        adrs.set_type(AdrsType::Tree);

        // Tree type doesn't use key pair, so all bytes 20-31 should be cleared
        assert_eq!(adrs.keypair(), 0);
        assert_eq!(adrs.tree_height(), 0);
        assert_eq!(adrs.tree_index(), 0);
    }

    #[test]
    fn test_type_preserves_keypair_for_wots_types() {
        // Test WotsHash type: preserves key pair, clears chain/hash
        let mut adrs = Address::new();
        adrs.set_keypair(0x12345678);
        adrs.set_chain(0xFFFFFFFF);
        adrs.set_hash(0xFFFFFFFF);

        adrs.set_type(AdrsType::WotsHash);

        // Key pair should be preserved, chain/hash should be cleared
        assert_eq!(adrs.keypair(), 0x12345678);
        assert_eq!(adrs.chain(), 0);
        assert_eq!(adrs.hash(), 0);
    }

    #[test]
    fn test_type_preserves_keypair_for_fors_types() {
        // Test ForsTree type: preserves key pair, clears tree_height/tree_index
        let mut adrs = Address::new();
        adrs.set_keypair(0xABCDEF01);
        adrs.set_tree_height(0xFFFFFFFF);
        adrs.set_tree_index(0xFFFFFFFF);

        adrs.set_type(AdrsType::ForsTree);

        // Key pair should be preserved, tree_height/tree_index should be cleared
        assert_eq!(adrs.keypair(), 0xABCDEF01);
        assert_eq!(adrs.tree_height(), 0);
        assert_eq!(adrs.tree_index(), 0);
    }

    #[test]
    fn test_wots_hash_address() {
        let adrs = Address::wots_hash(1, 2, 3, 4, 5);
        assert_eq!(adrs.layer(), 1);
        assert_eq!(adrs.tree(), 2);
        assert_eq!(adrs.adrs_type(), AdrsType::WotsHash as u32);
        assert_eq!(adrs.keypair(), 3);
        assert_eq!(adrs.chain(), 4);
        assert_eq!(adrs.hash(), 5);
    }

    #[test]
    fn test_fors_tree_address() {
        let adrs = Address::fors_tree(0, 100, 5, 3, 7);
        assert_eq!(adrs.layer(), 0);
        assert_eq!(adrs.tree(), 100);
        assert_eq!(adrs.adrs_type(), AdrsType::ForsTree as u32);
        assert_eq!(adrs.keypair(), 5);
        assert_eq!(adrs.tree_height(), 3);
        assert_eq!(adrs.tree_index(), 7);
    }
}
