pub mod hashes;
pub mod leaf_node;

use std::collections::BTreeSet;

use crate::{
    SensitiveBytes,
    crypto::{HpkeCiphertext, HpkePublicKey},
    defs::LeafIndex,
    tree::{hashes::ParentNodeHash, leaf_node::LeafNode},
};

pub trait RatchetTreeItem<'a>: PartialEq + Default + std::fmt::Debug + 'a {
    fn as_treenode(&self) -> Option<&TreeNode<'a>>;
    fn is_blank(&self) -> bool;
    fn unmerged_leaves(&self) -> Option<impl Iterator<Item = &u32>>;
    fn add_unmerged_leaf(&mut self, leaf_idx: LeafIndex);
    fn remove_unmerged_leaf(&mut self, leaf_idx: LeafIndex);
    fn replace_treenode(&mut self, node: TreeNode<'a>) -> Option<TreeNode<'a>>;
    fn blank(&mut self) -> bool;
}

impl<'a> RatchetTreeItem<'a> for Option<TreeNode<'a>> {
    #[inline]
    fn as_treenode(&self) -> Option<&TreeNode<'a>> {
        self.as_ref()
    }

    #[inline]
    fn is_blank(&self) -> bool {
        self.is_none()
    }

    fn unmerged_leaves(&self) -> Option<impl Iterator<Item = &u32>> {
        if let Some(TreeNode::ParentNode(parent_node)) = self {
            Some(parent_node.unmerged_leaves.iter())
        } else {
            None
        }
    }

    #[inline]
    fn add_unmerged_leaf(&mut self, leaf_idx: LeafIndex) {
        if let Some(TreeNode::ParentNode(parent_node)) = self {
            parent_node.unmerged_leaves.insert(leaf_idx);
        }
    }

    #[inline]
    fn remove_unmerged_leaf(&mut self, leaf_idx: LeafIndex) {
        if let Some(TreeNode::ParentNode(parent_node)) = self {
            parent_node.unmerged_leaves.remove(&leaf_idx);
        }
    }

    #[inline]
    fn replace_treenode(&mut self, node: TreeNode<'a>) -> Option<TreeNode<'a>> {
        self.replace(node)
    }

    #[inline]
    fn blank(&mut self) -> bool {
        self.take().is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RatchetTree<'a, N: RatchetTreeItem<'a> = Option<TreeNode<'a>>> {
    inner: Vec<N>,
    _boo: std::marker::PhantomData<&'a ()>,
}

impl<'a, N: RatchetTreeItem<'a>> RatchetTree<'a, N> {
    pub fn into_inner(self) -> Vec<N> {
        self.inner
    }
}

impl<'a> From<Vec<Option<TreeNode<'a>>>> for RatchetTree<'a> {
    fn from(inner: Vec<Option<TreeNode<'a>>>) -> Self {
        Self {
            inner,
            _boo: Default::default(),
        }
    }
}

impl<'a, N: RatchetTreeItem<'a>> std::ops::Deref for RatchetTree<'a, N> {
    type Target = Vec<N>;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref()
    }
}

impl<'a, N: RatchetTreeItem<'a>> std::ops::DerefMut for RatchetTree<'a, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.as_mut()
    }
}

pub type TreeHash<'a> = SensitiveBytes<'a>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ParentNode<'a> {
    pub encryption_key: HpkePublicKey<'a>,
    pub parent_hash: ParentNodeHash<'a>,
    pub unmerged_leaves: BTreeSet<LeafIndex>,
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
