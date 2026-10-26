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

/// <https://www.ietf.org/archive/id/draft-ietf-mls-combiner-02.html#section-6>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct{
///     opaque t_session_group_id<V>;
///     opaque PQ_session_group_id<V>;
///     bool mode;
///     CipherSuite t_cipher_suite;
///     CipherSuite pq_cipher_suite;
///     uint64 t_epoch;
///     uint64 pq_epoch;
/// } APQInfo
/// ```
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

/// <https://www.ietf.org/archive/id/draft-ietf-mls-combiner-02.html#section-6.1>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// enum {
///   full(0),
///   t_epoch(1),
///   pq_epoch(2),
///   (255)
/// } APQInfoUpdate
///
/// struct {
///   APQInfoUpdate update;
///   select (APQInfoUpdate.update)
///     case full:
///        APQInfo new_apq_info;
///     case t_epoch:
///        uint64 new_t_epoch;
///     case pq_epoch:
///        uint64 new_pq_epoch;
/// } APQInfoUpdateData
/// ```
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

/// <https://www.ietf.org/archive/id/draft-ietf-mls-combiner-02.html#section-7>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///   KeyPackage t_key_package;
///   KeyPackage pq_key_package;
/// } APQKeyPackage
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct APQKeyPackage<'a> {
    pub traditional_key_package: KeyPackage<'a>,
    pub post_quantum_key_package: KeyPackage<'a>,
}

/// <https://www.ietf.org/archive/id/draft-ietf-mls-combiner-02.html#section-7>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///   MLSPublicMessage t_message;
///   MLSPublicMessage pq_message;
/// } APQPublicMessage
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct APQPublicMessage<'a> {
    pub traditional_message: PublicMessage<'a>,
    pub post_quantum_message: PublicMessage<'a>,
}

/// <https://www.ietf.org/archive/id/draft-ietf-mls-combiner-02.html#section-7>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///   MLSPrivateMessage t_message;
///   MLSPrivateMessage pq_message;
/// } APQPrivateMessage
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct APQPrivateMessage<'a> {
    pub traditional_message: PrivateMessage<'a>,
    pub post_quantum_message: PrivateMessage<'a>,
}

/// <https://www.ietf.org/archive/id/draft-ietf-mls-combiner-02.html#section-7>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///   Welcome t_welcome;
///   Welcome pq_welcome;
/// } APQWelcome
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct APQWelcome<'a> {
    pub traditional_welcome: Welcome<'a>,
    pub post_quantum_welcome: Welcome<'a>,
}

/// <https://www.ietf.org/archive/id/draft-ietf-mls-combiner-02.html#section-7>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///   GroupInfo t_group_info;
///   GroupInfo pq_group_info;
/// } APQGroupInfo
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct APQGroupInfo<'a> {
    pub traditional_group_info: GroupInfo<'a>,
    pub post_quantum_group_info: GroupInfo<'a>,
}

/// <https://www.ietf.org/archive/id/draft-ietf-mls-combiner-02.html#section-7>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///   PartialGroupInfo t_group_info;
///   PartialGroupInfo pq_group_info;
/// } APQPartialGroupInfo
/// ```
#[cfg(feature = "draft-ietf-mls-ratchet-tree-options")]
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct APQPartialGroupInfo<'a> {
    pub traditional_group_info: crate::drafts::ratchet_tree_options::PartialGroupInfo<'a>,
    pub post_quantum_group_info: crate::drafts::ratchet_tree_options::PartialGroupInfo<'a>,
}
