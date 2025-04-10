use crate::{
    defs::LeafIndex, group::welcome::Welcome, messages::MlsMessage, tree::TreeNode, SensitiveBytes,
};

///
/// ```notrust,ignore
/// struct {
///     opaque hash_value;
/// } CopathHash;
/// ```
///
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Default,
    tls_codec::TlsSize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSerialize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CopathHash {
    pub hash_value: SensitiveBytes,
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
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Default,
    tls_codec::TlsSize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSerialize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MembershipProof {
    pub leaf_index: LeafIndex,
    pub n_leaves: u32,
    pub direct_path_nodes: Vec<Option<TreeNode>>,
    pub copath_hashes: Vec<CopathHash>,
}

///
/// ```notrust,ignore
/// struct {
///     T message;
///     MembershipProof sender_membership_proof;
/// } SenderAuthenticatedMessage;
/// ```
///
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    tls_codec::TlsSize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSerialize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SenderAuthenticatedMessage<T: tls_codec::Serialize + tls_codec::Deserialize> {
    pub message: T,
    pub sender_membership_proof: MembershipProof,
}

///
/// ```notrust,ignore
/// struct {
///     SenderAuthenticated<Welcome> welcome;
///     MembershipProof joiner_membership_proof;
/// } AnnotatedWelcome;
/// ```
///
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    tls_codec::TlsSize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSerialize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AnnotatedWelcome {
    pub welcome: SenderAuthenticatedMessage<Welcome>,
    pub joiner_membership_proof: MembershipProof,
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
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    tls_codec::TlsSize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSerialize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AnnotatedCommit {
    pub commit: MlsMessage,
    pub sender_membership_proof: Option<MembershipProof>,
    pub tree_hash_after: SensitiveBytes,
    pub resolution_index: Option<u32>,
    pub sender_membership_proof_after: MembershipProof,
    pub receiver_membership_proof_after: MembershipProof,
}
