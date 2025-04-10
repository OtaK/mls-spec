use crate::{
    group::{proposals::Proposal, ProposalRef},
    tree::UpdatePath,
};

/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4-3>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// enum {
///   reserved(0),
///   proposal(1),
///   reference(2),
///   (255)
/// } ProposalOrRefType;
/// ```
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum ProposalOrRefType {
    Reserved = 0x00,
    Proposal = 0x01,
    Reference = 0x02,
}

/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4-3>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///   ProposalOrRefType type;
///   select (ProposalOrRef.type) {
///     case proposal:  Proposal proposal;
///     case reference: ProposalRef reference;
///   };
/// } ProposalOrRef;
/// ```
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
#[repr(u8)]
#[allow(clippy::large_enum_variant)]
pub enum ProposalOrRef {
    #[tls_codec(discriminant = "ProposalOrRefType::Proposal")]
    Proposal(Proposal),
    #[tls_codec(discriminant = "ProposalOrRefType::Reference")]
    Reference(ProposalRef),
}

/// A MLS Commit contains the modifications applied to a group
/// for an epoch N to epoch N + 1 transition
///
/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4-3>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     ProposalOrRef proposals<V>;
///     optional<UpdatePath> path;
/// } Commit;
/// ```
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
pub struct Commit {
    pub proposals: Vec<ProposalOrRef>,
    pub path: Option<UpdatePath>,
}
