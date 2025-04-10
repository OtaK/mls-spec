use crate::{
    defs::{labels::KdfLabelKind, Epoch, LeafIndex},
    group::GroupId,
    SensitiveBytes,
};

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
pub struct TargetedMessage {
    pub group_id: GroupId,
    pub epoch: Epoch,
    pub recipient_leaf_index: LeafIndex,
    pub authenticated_data: SensitiveBytes,
    pub encrypted_sender_auth_data: SensitiveBytes,
    pub hpke_ciphertext: SensitiveBytes,
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
// ? Nit - what is the actual type of this thing?
#[repr(u8)]
pub enum TargetedMessageAuthScheme {
    HpkeAuthPsk = 0x00,
    SignatureHpkePsk = 0x01,
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
pub struct TargetedMessageSenderAuthData {
    pub sender_leaf_index: LeafIndex,
    pub authentication_scheme: TargetedMessageAuthScheme,
    pub signature: SensitiveBytes,
    pub kem_output: SensitiveBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
pub struct TargetedMessageTBM<'a> {
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub group_id: &'a [u8],
    pub epoch: &'a Epoch,
    pub recipient_leaf_index: &'a LeafIndex,
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub authenticated_data: &'a [u8],
    pub sender_auth_data: &'a TargetedMessageSenderAuthData,
}

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
pub struct TargetedMessageTBS<'a> {
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub group_id: &'a [u8],
    pub epoch: &'a Epoch,
    pub recipient_leaf_index: &'a LeafIndex,
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub authenticated_data: &'a [u8],
    pub sender_leaf_index: &'a LeafIndex,
    pub authentication_scheme: &'a TargetedMessageAuthScheme,
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub kem_output: &'a [u8],
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub hpke_ciphertext: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
pub struct TargetedMessagePreSharedKeyId<'a> {
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub group_id: &'a [u8],
    pub epoch: &'a Epoch,
}

impl TargetedMessagePreSharedKeyId<'_> {
    pub const LABEL: KdfLabelKind = KdfLabelKind::TargetedMessagePsk;
}

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
pub struct TargetedMessageSenderAuthDataAAD<'a> {
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub group_id: &'a [u8],
    pub epoch: &'a Epoch,
    pub recipient_leaf_index: &'a LeafIndex,
}
