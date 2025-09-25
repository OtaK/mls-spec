pub mod hashes;
pub mod leaf_node;

use crate::{
    SensitiveBytes,
    crypto::{HpkeCiphertext, HpkePublicKey},
    defs::LeafIndex,
    tree::{hashes::ParentNodeHash, leaf_node::LeafNode},
};

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Default,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSerialize,
    tls_codec::TlsSize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RatchetTree(Vec<Option<TreeNode>>);

impl RatchetTree {
    pub fn into_inner(self) -> Vec<Option<TreeNode>> {
        self.0
    }
}

impl From<Vec<Option<TreeNode>>> for RatchetTree {
    fn from(value: Vec<Option<TreeNode>>) -> Self {
        Self(value)
    }
}

impl std::ops::Deref for RatchetTree {
    type Target = [Option<TreeNode>];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

pub type TreeHash = SensitiveBytes;

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ParentNode {
    pub encryption_key: HpkePublicKey,
    pub parent_hash: ParentNodeHash,
    pub unmerged_leaves: Vec<LeafIndex>,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum NodeType {
    Reserved = 0x00,
    Leaf = 0x01,
    Parent = 0x02,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
#[allow(clippy::large_enum_variant)]
pub enum TreeNode {
    #[tls_codec(discriminant = "NodeType::Leaf")]
    LeafNode(LeafNode),
    #[tls_codec(discriminant = "NodeType::Parent")]
    ParentNode(ParentNode),
}

impl From<LeafNode> for TreeNode {
    fn from(value: LeafNode) -> Self {
        Self::LeafNode(value)
    }
}

impl From<ParentNode> for TreeNode {
    fn from(value: ParentNode) -> Self {
        Self::ParentNode(value)
    }
}

impl TreeNode {
    pub fn as_leaf_node(&self) -> Option<&LeafNode> {
        if let Self::LeafNode(leaf_node) = &self {
            Some(leaf_node)
        } else {
            None
        }
    }

    pub fn as_leaf_node_mut(&mut self) -> Option<&mut LeafNode> {
        if let Self::LeafNode(leaf_node) = self {
            Some(leaf_node)
        } else {
            None
        }
    }

    pub fn as_parent_node(&self) -> Option<&ParentNode> {
        if let Self::ParentNode(parent_node) = &self {
            Some(parent_node)
        } else {
            None
        }
    }

    pub fn as_parent_node_mut(&mut self) -> Option<&mut ParentNode> {
        if let Self::ParentNode(parent_node) = self {
            Some(parent_node)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
#[repr(u8)]
pub enum TreeNodeRef<'a> {
    #[tls_codec(discriminant = "NodeType::Leaf")]
    LeafNode(&'a LeafNode),
    #[tls_codec(discriminant = "NodeType::Parent")]
    ParentNode(&'a ParentNode),
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UpdatePathNode {
    pub encryption_key: HpkePublicKey,
    pub encrypted_path_secret: Vec<HpkeCiphertext>,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UpdatePath {
    pub leaf_node: LeafNode,
    pub nodes: Vec<UpdatePathNode>,
}
