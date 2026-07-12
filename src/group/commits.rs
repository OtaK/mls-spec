use crate::{
    group::{ProposalRef, proposals::Proposal},
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(
    feature = "serde",
    derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr)
)]
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
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
#[allow(clippy::large_enum_variant)]
pub enum ProposalOrRef<'a> {
    #[tlspl(discriminant = "ProposalOrRefType::Proposal")]
    Proposal(Proposal<'a>),
    #[tlspl(discriminant = "ProposalOrRefType::Reference")]
    Reference(ProposalRef<'a>),
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
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Commit<'a> {
    pub proposals: Vec<ProposalOrRef<'a>>,
    pub path: Option<UpdatePath<'a>>,
}
