use crate::{
    defs::{CiphersuiteId, Epoch},
    group::{GroupId, group_info::GroupInfo, welcome::Welcome},
    key_package::KeyPackage,
    messages::{PrivateMessage, PublicMessage},
};

use super::mls_extensions::safe_application::{Component, ComponentId};

pub const COMPONENT_ID: ComponentId = 0x0006;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, thalassa::TlsplAll)]
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

#[derive(Debug, Clone, PartialEq, Eq, Default, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct APQInfo<'a> {
    pub traditional_session_group_id: GroupId<'a>,
    pub post_quantum_session_group_id: GroupId<'a>,
    pub mode: APQMode,
    pub traditional_cipher_suite: CiphersuiteId,
    pub post_quantum_cipher_suite: CiphersuiteId,
    pub traditional_epoch: Epoch,
    pub post_quantum_epoch: Epoch,
}

impl<'a> Component<'a> for APQInfo<'a> {
    fn component_id() -> ComponentId {
        COMPONENT_ID
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum APQInfoUpdateData<'a> {
    #[tlspl(discriminant = 0x00)]
    FullUpdate { new_apq_info: APQInfo<'a> },
    #[tlspl(discriminant = 0x01)]
    NewTraditionalEpoch { new_traditional_epoch: Epoch },
    #[tlspl(discriminant = 0x02)]
    NewPostQuantumEpoch { new_post_quantum_epoch: Epoch },
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct APQKeyPackage<'a> {
    pub traditional_key_package: KeyPackage<'a>,
    pub post_quantum_key_package: KeyPackage<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct APQPublicMessage<'a> {
    pub traditional_message: PublicMessage<'a>,
    pub post_quantum_message: PublicMessage<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct APQPrivateMessage<'a> {
    pub traditional_message: PrivateMessage<'a>,
    pub post_quantum_message: PrivateMessage<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct APQWelcome<'a> {
    pub traditional_welcome: Welcome<'a>,
    pub post_quantum_welcome: Welcome<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct APQGroupInfo<'a> {
    pub traditional_group_info: GroupInfo<'a>,
    pub post_quantum_group_info: GroupInfo<'a>,
}

#[cfg(feature = "draft-ietf-mls-ratchet-tree-options")]
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct APQPartialGroupInfo<'a> {
    pub traditional_group_info: crate::drafts::ratchet_tree_options::PartialGroupInfo<'a>,
    pub post_quantum_group_info: crate::drafts::ratchet_tree_options::PartialGroupInfo<'a>,
}
