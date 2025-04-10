use crate::{group::extensions::Extension, tree::RatchetTree};

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

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RatchetTreeOption {
    #[tls_codec(discriminant = "RatchetTreeRepresentation::Full")]
    Full { ratchet_tree: RatchetTree },
    #[tls_codec(discriminant = "RatchetTreeRepresentation::HttpsUri")]
    HttpsUri {
        #[tls_codec(with = "crate::tlspl::string")]
        ratchet_tree_url: String,
        #[tls_codec(with = "crate::tlspl::bytes")]
        tree_signature: Vec<u8>,
    },
    #[tls_codec(discriminant = "RatchetTreeRepresentation::OutOfBand")]
    OutOfBand {
        #[tls_codec(with = "crate::tlspl::bytes")]
        tree_signature: Vec<u8>,
    },
    #[tls_codec(discriminant = "RatchetTreeRepresentation::DistributionService")]
    DistributionService,
}

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
pub struct PartialGroupInfo {
    pub ratchet_tree_presence: RatchetTreePresence,
    pub group_info_extensions: Vec<Extension>,
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub signature: Vec<u8>,
}
