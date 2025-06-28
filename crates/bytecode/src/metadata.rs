use core::fmt;
use primitives::{b256, bytes, Address, Bytes, B256};

/// Hash of EF44 bytes that is used for EXTCODEHASH when called from legacy bytecode.
pub const METADATA_MAGIC_HASH: B256 =
    b256!("0x85160e14613bd11c0e87050b7f84bbea3095f7f0ccd58026f217fdff9043c16b");

/// Version Magic in u16 form
pub const METADATA_MAGIC: u16 = 0xEF44;

/// Magic number in array form
pub static METADATA_MAGIC_BYTES: Bytes = bytes!("ef44");

/// First version of metadata
pub const METADATA_VERSION: u8 = 0;

/// Metadata representation
///
/// Format consist of:
/// `0xEF44` (MAGIC) + `0x00` (VERSION) + 20 bytes of address.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Metadata {
    /// Address of the delegated account.
    pub delegated_address: Address,
    /// Version. Currently only version 0 is supported.
    pub version: u8,
    /// Data.
    pub data: Bytes,
}

impl Metadata {
    /// Creates a new metadata representation or returns None if the metadata is invalid.
    #[inline]
    pub fn new_raw(metadata: Bytes) -> Result<Self, MetadataDecodeError> {
        if metadata.len() != 23 {
            return Err(MetadataDecodeError::InvalidLength);
        }
        if !metadata.starts_with(&METADATA_MAGIC_BYTES) {
            return Err(MetadataDecodeError::InvalidMagic);
        }

        // Only supported version is version 0.
        if metadata[2] != METADATA_VERSION {
            return Err(MetadataDecodeError::UnsupportedVersion);
        }

        Ok(Self {
            delegated_address: Address::new(metadata[3..].try_into().unwrap()),
            version: METADATA_VERSION,
            data: metadata,
        })
    }

    /// Creates a new metadata representation with the given address.
    pub fn new(address: Address) -> Self {
        let mut metadata = METADATA_MAGIC_BYTES.to_vec();
        metadata.push(METADATA_VERSION);
        metadata.extend(&address);
        Self {
            delegated_address: address,
            version: METADATA_VERSION,
            data: metadata.into(),
        }
    }

    /// Returns the raw metadata with version MAGIC number.
    #[inline]
    pub fn metadata(&self) -> &Bytes {
        &self.data
    }

    /// Returns the address of the delegated contract.
    #[inline]
    pub fn address(&self) -> Address {
        self.delegated_address
    }
}

/// Bytecode errors
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MetadataDecodeError {
    /// Invalid length of the raw bytecode
    ///
    /// It should be 23 bytes.
    InvalidLength,
    /// Invalid magic number
    ///
    /// All metadata should start with the magic number 0xEF44.
    InvalidMagic,
    /// Unsupported version
    ///
    /// Only supported version is version 0x00
    UnsupportedVersion,
}

impl fmt::Display for MetadataDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::InvalidLength => "Metadata is not 23 bytes long",
            Self::InvalidMagic => "Metadata is not starting with 0xEF44",
            Self::UnsupportedVersion => "Unsupported Metadata version.",
        };
        f.write_str(s)
    }
}

impl core::error::Error for MetadataDecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_bytes_hash_check() {
        let result = keccak_hash::keccak(&METADATA_MAGIC_BYTES);
        assert_eq!(METADATA_MAGIC_HASH.as_slice(), result.as_bytes());
    }

    #[test]
    fn sanity_decode() {
        let metadata = bytes!("ef44deadbeef");
        assert_eq!(
            Metadata::new_raw(metadata),
            Err(MetadataDecodeError::InvalidLength)
        );

        let metadata = bytes!("ef4401deadbeef00000000000000000000000000000000");
        assert_eq!(
            Metadata::new_raw(metadata),
            Err(MetadataDecodeError::UnsupportedVersion)
        );

        let metadata = bytes!("ef4400deadbeef00000000000000000000000000000000");
        let address = metadata[3..].try_into().unwrap();
        assert_eq!(
            Metadata::new_raw(metadata.clone()),
            Ok(Metadata {
                delegated_address: address,
                version: 0,
                data: metadata,
            })
        );
    }

    #[test]
    fn create_metadata_from_address() {
        let address = Address::new([0x01; 20]);
        let bytecode = Metadata::new(address);
        assert_eq!(bytecode.delegated_address, address);
        assert_eq!(
            bytecode.data,
            bytes!("ef44000101010101010101010101010101010101010101")
        );
    }
}
