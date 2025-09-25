use crate::{
    SensitiveBytes,
    defs::{CiphersuiteId, ProtocolVersion},
    group::{KeyPackageRef, extensions::Extension},
    messages::MlsMessage,
    tree::leaf_node::LeafNode,
};

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct KeyPackageTBS<'a> {
    pub version: &'a ProtocolVersion,
    pub cipher_suite: &'a CiphersuiteId,
    pub init_key: &'a [u8],
    pub leaf_node: &'a LeafNode,
    pub extensions: &'a [Extension],
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    zeroize::Zeroize,
    zeroize::ZeroizeOnDrop,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyPackage {
    #[zeroize(skip)]
    pub version: ProtocolVersion,
    #[zeroize(skip)]
    pub cipher_suite: CiphersuiteId,
    pub init_key: SensitiveBytes,
    #[zeroize(skip)]
    pub leaf_node: LeafNode,
    #[zeroize(skip)]
    pub extensions: Vec<Extension>,
    pub signature: SensitiveBytes,
}

impl KeyPackage {
    pub fn to_tbs(&self) -> KeyPackageTBS<'_> {
        KeyPackageTBS {
            version: &self.version,
            cipher_suite: &self.cipher_suite,
            init_key: &self.init_key,
            leaf_node: &self.leaf_node,
            extensions: &self.extensions,
        }
    }

    pub fn into_message(self) -> MlsMessage {
        MlsMessage {
            version: ProtocolVersion::default(),
            content: crate::messages::MlsMessageContent::KeyPackage(self),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyPackageWithRef {
    pub keypackage_ref: KeyPackageRef,
    pub keypackage: KeyPackage,
}
