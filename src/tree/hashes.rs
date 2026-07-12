use crate::{
    SensitiveBytes,
    defs::LeafIndex,
    tree::{NodeType, ParentNode, leaf_node::LeafNode},
};

pub type ParentNodeHash<'a> = SensitiveBytes<'a>;
pub type NodeHash<'a> = SensitiveBytes<'a>;

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
pub struct ParentNodeHashInput<'a> {
    pub parent_node: Option<&'a ParentNode<'a>>,
    pub left_hash: &'a [u8],
    pub right_hash: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
pub struct LeafNodeHashInput<'a> {
    pub leaf_index: &'a LeafIndex,
    pub leaf_node: Option<&'a LeafNode<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
#[repr(u8)]
pub enum TreeHashInput<'a> {
    #[tlspl(discriminant = "NodeType::Leaf")]
    Leaf(LeafNodeHashInput<'a>),
    #[tlspl(discriminant = "NodeType::Parent")]
    Parent(ParentNodeHashInput<'a>),
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
pub struct ParentHashInput<'a> {
    pub encryption_key: &'a [u8],
    pub parent_hash: &'a [u8],
    pub original_sibling_tree_hash: &'a [u8],
}
