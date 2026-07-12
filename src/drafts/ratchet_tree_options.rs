use std::borrow::Cow;

use crate::{group::extensions::Extension, tree::RatchetTree};

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Domain<'a> {
    pub domain: Cow<'a, str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DomainList<'a> {
    pub domains: Vec<Domain<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct RatchetTreeSourceDomainsExtension<'a>(pub DomainList<'a>);

pub const EXTENSION_RATCHET_TREE_SOURCE_DOMAINS: u16 = 0xF4C0;

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

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PartialGroupInfo<'a> {
    pub ratchet_tree_presence: RatchetTreePresence,
    pub group_info_extensions: Vec<Extension<'a>>,
    pub signature: Cow<'a, [u8]>,
}
