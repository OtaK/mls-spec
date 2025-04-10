use crate::{
    defs::{labels::KdfLabelKind, CiphersuiteId, Epoch, ProtocolVersion, WireFormat},
    group::{extensions::Extension, ExternalSender, GroupId, RequiredCapabilities},
    messages::FramedContent,
    tree::TreeHash,
    SensitiveBytes,
};

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Default,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GroupContext {
    pub version: ProtocolVersion,
    pub cipher_suite: CiphersuiteId,
    #[tls_codec(with = "crate::tlspl::bytes")]
    group_id: GroupId,
    pub epoch: u64,
    pub tree_hash: TreeHash,
    pub confirmed_transcript_hash: TranscriptHash,
    pub extensions: Vec<Extension>,
}

impl GroupContext {
    /// Allows for initialization with an arbitrary group id
    pub fn with_group_id(group_id: GroupId) -> Self {
        Self {
            group_id,
            ..Default::default()
        }
    }

    // 8.1 -> The `group_id` field is constant
    pub fn group_id(&self) -> &[u8] {
        &self.group_id
    }

    pub fn external_senders(&self) -> &[ExternalSender] {
        self.extensions
            .iter()
            .find_map(|ext| {
                if let Extension::ExternalSenders(ext_senders) = ext {
                    Some(ext_senders.as_slice())
                } else {
                    None
                }
            })
            .unwrap_or_default()
    }

    pub fn required_capabilities(&self) -> Option<&RequiredCapabilities> {
        self.extensions.iter().find_map(|ext| {
            if let Extension::RequiredCapabilities(required_caps) = ext {
                Some(required_caps)
            } else {
                None
            }
        })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum EpochSecretExport {
    SenderDataSecret,
    EncryptionSecret,
    ExporterSecret,
    ExternalSecret,
    ConfirmationKey,
    MembershipKey,
    ResumptionPsk,
    EpochAuthenticator,
    #[cfg(feature = "draft-kohbrok-mls-associated-parties")]
    AssociatedPartiesSecret,
}

impl From<EpochSecretExport> for KdfLabelKind {
    fn from(value: EpochSecretExport) -> Self {
        match value {
            EpochSecretExport::SenderDataSecret => KdfLabelKind::SenderData,
            EpochSecretExport::EncryptionSecret => KdfLabelKind::Encryption,
            EpochSecretExport::ExporterSecret => KdfLabelKind::Exporter,
            EpochSecretExport::ExternalSecret => KdfLabelKind::External,
            EpochSecretExport::ConfirmationKey => KdfLabelKind::Confirm,
            EpochSecretExport::MembershipKey => KdfLabelKind::Membership,
            EpochSecretExport::ResumptionPsk => KdfLabelKind::Resumption,
            EpochSecretExport::EpochAuthenticator => KdfLabelKind::Authentication,
            #[cfg(feature = "draft-kohbrok-mls-associated-parties")]
            EpochSecretExport::AssociatedPartiesSecret => KdfLabelKind::AssociatedPartyEpochSecret,
        }
    }
}

pub type TranscriptHash = SensitiveBytes;

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ConfirmedTranscriptHashInput<'a> {
    pub wire_format: &'a WireFormat,
    pub content: &'a FramedContent,
    pub signature: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct InterimTranscriptHashInput<'a> {
    pub confirmation_tag: &'a [u8],
}

impl<'a> From<&'a [u8]> for InterimTranscriptHashInput<'a> {
    fn from(confirmation_tag: &'a [u8]) -> Self {
        Self { confirmation_tag }
    }
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum PskType {
    Reserved = 0x00,
    External = 0x01,
    Resumption = 0x02,
    #[cfg(feature = "draft-ietf-mls-extensions")]
    Application = 0x03,
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum ResumptionPskUsage {
    Reserved = 0x00,
    Application = 0x01,
    ReInit = 0x02,
    Branch = 0x03,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
    zeroize::Zeroize,
    zeroize::ZeroizeOnDrop,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum PreSharedKeyIdPskType {
    #[tls_codec(discriminant = "PskType::External")]
    External(ExternalPsk),
    #[tls_codec(discriminant = "PskType::Resumption")]
    Resumption(ResumptionPsk),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[tls_codec(discriminant = "PskType::Application")]
    Application(ApplicationPsk),
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
    zeroize::Zeroize,
    zeroize::ZeroizeOnDrop,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExternalPsk {
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub psk_id: Vec<u8>,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
    zeroize::Zeroize,
    zeroize::ZeroizeOnDrop,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResumptionPsk {
    #[zeroize(skip)]
    pub usage: ResumptionPskUsage,
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub psk_group_id: Vec<u8>,
    pub psk_epoch: Epoch,
}

#[cfg(feature = "draft-ietf-mls-extensions")]
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
    zeroize::Zeroize,
    zeroize::ZeroizeOnDrop,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ApplicationPsk {
    #[zeroize(skip)]
    pub component_id: crate::drafts::mls_extensions::safe_application::ComponentId,
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub psk_id: Vec<u8>,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
    zeroize::Zeroize,
    zeroize::ZeroizeOnDrop,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PreSharedKeyId {
    pub psktype: PreSharedKeyIdPskType,
    pub psk_nonce: SensitiveBytes,
}

impl PreSharedKeyId {
    pub fn with_default_nonce(&self) -> Self {
        Self {
            psktype: self.psktype.clone(),
            psk_nonce: SensitiveBytes::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct PskLabel<'a> {
    pub id: &'a PreSharedKeyId,
    pub index: u16,
    pub count: u16,
}
