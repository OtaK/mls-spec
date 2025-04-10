use crate::{
    SensitiveBytes,
    defs::LeafIndex,
    tree::{NodeType, ParentNode, leaf_node::LeafNode},
};

pub type ParentNodeHash = SensitiveBytes;
pub type NodeHash = SensitiveBytes;

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
pub struct ParentNodeHashInput<'a> {
    pub parent_node: Option<&'a ParentNode>,
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub left_hash: &'a [u8],
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub right_hash: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
pub struct LeafNodeHashInput<'a> {
    pub leaf_index: &'a LeafIndex,
    pub leaf_node: Option<&'a LeafNode>,
}

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
#[repr(u8)]
pub enum TreeHashInput<'a> {
    #[tls_codec(discriminant = "NodeType::Leaf")]
    Leaf(LeafNodeHashInput<'a>),
    #[tls_codec(discriminant = "NodeType::Parent")]
    Parent(ParentNodeHashInput<'a>),
}

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
pub struct ParentHashInput<'a> {
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub encryption_key: &'a [u8],
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub parent_hash: &'a [u8],
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub original_sibling_tree_hash: &'a [u8],
}
