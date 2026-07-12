pub mod hashes;
pub mod leaf_node;

use crate::{
    SensitiveBytes,
    crypto::{HpkeCiphertext, HpkePublicKey},
    defs::LeafIndex,
    tree::{hashes::ParentNodeHash, leaf_node::LeafNode},
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct RatchetTree<'a>(Vec<Option<TreeNode<'a>>>);

impl<'a> RatchetTree<'a> {
    pub fn into_inner(self) -> Vec<Option<TreeNode<'a>>> {
        self.0
    }
}

impl<'a> From<Vec<Option<TreeNode<'a>>>> for RatchetTree<'a> {
    fn from(value: Vec<Option<TreeNode<'a>>>) -> Self {
        Self(value)
    }
}

impl<'a> std::ops::Deref for RatchetTree<'a> {
    type Target = [Option<TreeNode<'a>>];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

pub type TreeHash<'a> = SensitiveBytes<'a>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ParentNode<'a> {
    pub encryption_key: HpkePublicKey<'a>,
    pub parent_hash: ParentNodeHash<'a>,
    pub unmerged_leaves: Vec<LeafIndex>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(
    feature = "serde",
    derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr)
)]
#[repr(u8)]
pub enum NodeType {
    Reserved = 0x00,
    Leaf = 0x01,
    Parent = 0x02,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
#[allow(clippy::large_enum_variant)]
pub enum TreeNode<'a> {
    #[tlspl(discriminant = "NodeType::Leaf")]
    LeafNode(LeafNode<'a>),
    #[tlspl(discriminant = "NodeType::Parent")]
    ParentNode(ParentNode<'a>),
}

impl<'a> From<LeafNode<'a>> for TreeNode<'a> {
    fn from(value: LeafNode<'a>) -> Self {
        Self::LeafNode(value)
    }
}

impl<'a> From<ParentNode<'a>> for TreeNode<'a> {
    fn from(value: ParentNode<'a>) -> Self {
        Self::ParentNode(value)
    }
}

impl<'a> TreeNode<'a> {
    pub fn as_leaf_node(&self) -> Option<&LeafNode<'a>> {
        if let Self::LeafNode(leaf_node) = &self {
            Some(leaf_node)
        } else {
            None
        }
    }

    pub fn as_leaf_node_mut(&mut self) -> Option<&mut LeafNode<'a>> {
        if let Self::LeafNode(leaf_node) = self {
            Some(leaf_node)
        } else {
            None
        }
    }

    pub fn as_parent_node(&self) -> Option<&ParentNode<'a>> {
        if let Self::ParentNode(parent_node) = &self {
            Some(parent_node)
        } else {
            None
        }
    }

    pub fn as_parent_node_mut(&mut self) -> Option<&mut ParentNode<'a>> {
        if let Self::ParentNode(parent_node) = self {
            Some(parent_node)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UpdatePathNode<'a> {
    pub encryption_key: HpkePublicKey<'a>,
    pub encrypted_path_secret: Vec<HpkeCiphertext<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UpdatePath<'a> {
    pub leaf_node: LeafNode<'a>,
    pub nodes: Vec<UpdatePathNode<'a>>,
}
