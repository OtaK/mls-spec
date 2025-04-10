use crate::{
    defs::{CiphersuiteId, Epoch},
    group::GroupId,
};

use super::mls_extensions::safe_application::{Component, ComponentId};

pub const COMPONENT_ID: ComponentId = 0xFCBE_0000; // TODO: Waiting for IANA registration
static_assertions::const_assert!(
    *super::mls_extensions::COMPONENT_RESERVED_PRIVATE_RANGE.start() <= COMPONENT_ID
        && COMPONENT_ID <= *super::mls_extensions::COMPONENT_RESERVED_PRIVATE_RANGE.end()
);

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    tls_codec::TlsSize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSerialize,
)]
#[cfg_attr(
    feature = "serde",
    derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr)
)]
#[repr(u8)]
pub enum HpqMode {
    #[default]
    ConfidentialityOnly = 0,
    ConfidentialityAndAuthenticity = 1,
}

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
pub struct HpqMlsInfo {
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub traditional_session_group_id: GroupId,
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub post_quantum_session_group_id: GroupId,
    pub mode: HpqMode,
    pub traditional_cipher_suite: CiphersuiteId,
    pub post_quantum_cipher_suite: CiphersuiteId,
    pub traditional_epoch: Epoch,
    pub post_quantum_epoch: Epoch,
}

impl Component for HpqMlsInfo {
    fn component_id() -> ComponentId {
        COMPONENT_ID
    }
}
