use crate::{
    SensitiveBytes, defs::LeafIndex, group::welcome::Welcome, messages::MlsMessage, tree::TreeNode,
};

///
/// ```notrust,ignore
/// struct {
///     opaque hash_value;
/// } CopathHash;
/// ```
///
#[derive(Debug, Clone, PartialEq, Eq, Default, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CopathHash<'a> {
    pub hash_value: SensitiveBytes<'a>,
}

///
/// ```notrust,ignore
/// struct {
///   uint32 leaf_index;
///   uint32 n_leaves;
///   optional<Node> direct_path_nodes<V>;
///   CopathHash copath_hashes<V>;
/// } MembershipProof;
/// ```
///
#[derive(Debug, Clone, PartialEq, Eq, Default, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MembershipProof<'a> {
    pub leaf_index: LeafIndex,
    pub n_leaves: u32,
    pub direct_path_nodes: Vec<Option<TreeNode<'a>>>,
    pub copath_hashes: Vec<CopathHash<'a>>,
}

///
/// ```notrust,ignore
/// struct {
///     T message;
///     MembershipProof sender_membership_proof;
/// } SenderAuthenticatedMessage<T>;
/// ```
///
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SenderAuthenticatedMessage<'a, T> {
    pub message: T,
    pub sender_membership_proof: MembershipProof<'a>,
}

///
/// ```notrust,ignore
/// struct {
///     SenderAuthenticated<Welcome> welcome;
///     MembershipProof joiner_membership_proof;
/// } AnnotatedWelcome;
/// ```
///
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AnnotatedWelcome<'a> {
    pub welcome: SenderAuthenticatedMessage<'a, Welcome<'a>>,
    pub joiner_membership_proof: MembershipProof<'a>,
}

///
/// ```notrust,ignore
/// struct {
///     MLSMessage commit;
///     optional<MembershipProof> sender_membership_proof;
///
///     opaque tree_hash_after<V>;
///     optional<uint32> resolution_index;
///
///     MembershipProof sender_membership_proof_after;
///     MembershipProof receiver_membership_proof_after;
/// } AnnotatedCommit;
/// ```
///
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AnnotatedCommit<'a> {
    pub commit: MlsMessage<'a>,
    pub sender_membership_proof: Option<MembershipProof<'a>>,
    pub tree_hash_after: SensitiveBytes<'a>,
    pub resolution_index: Option<u32>,
    pub sender_membership_proof_after: MembershipProof<'a>,
    pub receiver_membership_proof_after: MembershipProof<'a>,
}
