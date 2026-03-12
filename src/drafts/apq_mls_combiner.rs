use crate::{
    defs::{CiphersuiteId, Epoch},
    group::{GroupId, group_info::GroupInfo, welcome::Welcome},
    key_package::KeyPackage,
    messages::{PrivateMessage, PublicMessage},
};

use super::mls_extensions::safe_application::{Component, ComponentId};

pub const COMPONENT_ID: ComponentId = 0x0006;

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
#[repr(u8)] // TLSPL `bool` is a u8, here we use an enum to make it a bit nicer to use
pub enum APQMode {
    #[default]
    ConfidentialityOnly = 0x00,
    ConfidentialityAndAuthenticity = 0x01,
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
pub struct APQInfo {
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub traditional_session_group_id: GroupId,
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub post_quantum_session_group_id: GroupId,
    pub mode: APQMode,
    pub traditional_cipher_suite: CiphersuiteId,
    pub post_quantum_cipher_suite: CiphersuiteId,
    pub traditional_epoch: Epoch,
    pub post_quantum_epoch: Epoch,
}

impl Component for APQInfo {
    fn component_id() -> ComponentId {
        COMPONENT_ID
    }
}

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
#[repr(u8)]
pub enum APQInfoUpdateData {
    #[tls_codec(discriminant = 0x00)]
    FullUpdate { new_apq_info: APQInfo },
    #[tls_codec(discriminant = 0x01)]
    NewTraditionalEpoch { epoch: Epoch },
    #[tls_codec(discriminant = 0x02)]
    NewPostQuantumEpoch { epoch: Epoch },
}

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
pub struct APQKeyPackage {
    pub traditional_key_package: KeyPackage,
    pub post_quantum_key_package: KeyPackage,
}

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
pub struct APQPublicMessage {
    pub traditional_message: PublicMessage,
    pub post_quantum_message: PublicMessage,
}

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
pub struct APQPrivateMessage {
    pub traditional_message: PrivateMessage,
    pub post_quantum_message: PrivateMessage,
}

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
pub struct APQWelcome {
    pub traditional_welcome: Welcome,
    pub post_quantum_welcome: Welcome,
}

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
pub struct APQGroupInfo {
    pub traditional_group_info: GroupInfo,
    pub post_quantum_group_info: GroupInfo,
}

#[cfg(feature = "draft-mahy-mls-ratchet-tree-options")]
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
pub struct APQPartialGroupInfo {
    pub traditional_group_info: crate::drafts::ratchet_tree_options::PartialGroupInfo,
    pub post_quantum_group_info: crate::drafts::ratchet_tree_options::PartialGroupInfo,
}
