use std::borrow::Cow;

use crate::{group::extensions::Extension, tree::RatchetTree};

/// <https://www.ietf.org/archive/id/draft-ietf-mls-ratchet-tree-options-01.html#section-3.1>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     opaque domain<V>;
/// } Domain;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Domain<'a> {
    pub domain: Cow<'a, str>,
}

/// <https://www.ietf.org/archive/id/draft-ietf-mls-ratchet-tree-options-01.html#section-3.1>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     Domain domains<V>
/// } DomainList;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DomainList<'a> {
    pub domains: Vec<Domain<'a>>,
}

/// <https://www.ietf.org/archive/id/draft-ietf-mls-ratchet-tree-options-01.html#section-3.1>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// DomainList ratchet_tree_source_domains;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct RatchetTreeSourceDomainsExtension<'a>(pub DomainList<'a>);

pub const EXTENSION_RATCHET_TREE_SOURCE_DOMAINS: u16 = 0xF4C0;

/// <https://www.ietf.org/archive/id/draft-ietf-mls-ratchet-tree-options-01.html#section-3>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// enum {
///   reserved(0),
///   full(1),
///   httpsUri(2),
///   outOfBand(3),
///   distributionService(4),
///   (255)
/// } RatchetTreeRepresentation;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, thalassa::TlsplAll)]
#[repr(u8)]
#[cfg_attr(
    feature = "serde",
    derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr)
)]
pub enum RatchetTreeRepresentation {
    Reserved = 0x00,
    Full = 0x01,
    HttpsUri = 0x02,
    OutOfBand = 0x03,
    DistributionService = 0x04,
}

/// <https://www.ietf.org/archive/id/draft-ietf-mls-ratchet-tree-options-01.html#section-3>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///   RatchetTreeRepresentation representation;
///   select (representation) {
///     case full:
///       Node ratchet_tree<V>;
///     case httpsUrl:
///       /* an HTTPS URL */
///       opaque ratchet_tree_url<V>;
///     case outOfBand:
///       struct {};
///     case distributionService:
///       struct {};
///   };
/// } RatchetTreeOption;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RatchetTreeOption<'a> {
    #[tlspl(discriminant = "RatchetTreeRepresentation::Full")]
    Full { ratchet_tree: RatchetTree<'a> },
    #[tlspl(discriminant = "RatchetTreeRepresentation::HttpsUri")]
    HttpsUri { ratchet_tree_url: Cow<'a, str> },
    #[tlspl(discriminant = "RatchetTreeRepresentation::OutOfBand")]
    OutOfBand,
    #[tlspl(discriminant = "RatchetTreeRepresentation::DistributionService")]
    DistributionService,
}

/// <https://www.ietf.org/archive/id/draft-ietf-mls-ratchet-tree-options-01.html#section-4>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// enum {
///   no_ratchet_tree(0),
///   present(1),
///   removed(2),
///   added(3),
///   (255)
/// } RatchetTreePresence;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, thalassa::TlsplAll)]
#[repr(u8)]
#[cfg_attr(
    feature = "serde",
    derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr)
)]
pub enum RatchetTreePresence {
    NoRatchetTree = 0x00,
    Present = 0x01,
    Removed = 0x02,
    Added = 0x03,
}

/// <https://www.ietf.org/archive/id/draft-ietf-mls-ratchet-tree-options-01.html#section-4>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///   RatchetTreePresence ratchet_tree_presence;
///   /* GroupInfo extensions excluding ratchet_tree */
///   Extension group_info_extensions<V>;
///   opaque signature<V>;
/// } PartialGroupInfo;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PartialGroupInfo<'a> {
    pub ratchet_tree_presence: RatchetTreePresence,
    pub group_info_extensions: Vec<Extension<'a>>,
    pub signature: Cow<'a, [u8]>,
}
