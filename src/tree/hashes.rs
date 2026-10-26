use crate::{
    SensitiveBytes,
    defs::LeafIndex,
    tree::{NodeType, ParentNode, leaf_node::LeafNode},
};

pub type ParentNodeHash<'a> = SensitiveBytes<'a>;
pub type NodeHash<'a> = SensitiveBytes<'a>;

/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-7.8>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     optional<ParentNode> parent_node;
///     opaque left_hash<V>;
///     opaque right_hash<V>;
/// } ParentNodeHashInput;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
pub struct ParentNodeHashInput<'a> {
    pub parent_node: Option<&'a ParentNode<'a>>,
    pub left_hash: &'a [u8],
    pub right_hash: &'a [u8],
}

/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-7.8>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     uint32 leaf_index;
///     optional<LeafNode> leaf_node;
/// } LeafNodeHashInput;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
pub struct LeafNodeHashInput<'a> {
    pub leaf_index: LeafIndex,
    pub leaf_node: Option<&'a LeafNode<'a>>,
}

/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-7.8>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///   NodeType node_type;
///   select (TreeHashInput.node_type) {
///     case leaf:   LeafNodeHashInput leaf_node;
///     case parent: ParentNodeHashInput parent_node;
///   };
/// } TreeHashInput;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
#[repr(u8)]
pub enum TreeHashInput<'a> {
    #[tlspl(discriminant = "NodeType::Leaf")]
    Leaf(LeafNodeHashInput<'a>),
    #[tlspl(discriminant = "NodeType::Parent")]
    Parent(ParentNodeHashInput<'a>),
}

/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-7.9>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     HPKEPublicKey encryption_key;
///     opaque parent_hash<V>;
///     opaque original_sibling_tree_hash<V>;
/// } ParentHashInput;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
pub struct ParentHashInput<'a> {
    pub encryption_key: &'a [u8],
    pub parent_hash: &'a [u8],
    pub original_sibling_tree_hash: &'a [u8],
}
