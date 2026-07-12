use crate::{
    SensitiveBytes,
    defs::{CiphersuiteId, ProtocolVersion},
    group::{KeyPackageRef, extensions::Extension},
    messages::MlsMessage,
    tree::leaf_node::LeafNode,
};

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct KeyPackageTBS<'a> {
    pub version: &'a ProtocolVersion,
    pub cipher_suite: &'a CiphersuiteId,
    pub init_key: &'a [u8],
    pub leaf_node: &'a LeafNode<'a>,
    pub extensions: &'a [Extension<'a>],
}

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll, zeroize::Zeroize, zeroize::ZeroizeOnDrop,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyPackage<'a> {
    #[zeroize(skip)]
    pub version: ProtocolVersion,
    #[zeroize(skip)]
    pub cipher_suite: CiphersuiteId,
    pub init_key: SensitiveBytes<'a>,
    #[zeroize(skip)]
    pub leaf_node: LeafNode<'a>,
    #[zeroize(skip)]
    pub extensions: Vec<Extension<'a>>,
    pub signature: SensitiveBytes<'a>,
}

impl<'a> KeyPackage<'a> {
    pub fn to_tbs(&'a self) -> KeyPackageTBS<'a> {
        KeyPackageTBS {
            version: &self.version,
            cipher_suite: &self.cipher_suite,
            init_key: &self.init_key,
            leaf_node: &self.leaf_node,
            extensions: &self.extensions,
        }
    }

    pub fn into_message(self) -> MlsMessage<'a> {
        MlsMessage {
            version: ProtocolVersion::default(),
            content: crate::messages::MlsMessageContent::KeyPackage(self),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyPackageWithRef<'a> {
    pub keypackage_ref: KeyPackageRef<'a>,
    pub keypackage: KeyPackage<'a>,
}
