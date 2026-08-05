use std::borrow::Cow;

use crate::{
    SensitiveBytes,
    defs::{CiphersuiteId, Epoch, ProtocolVersion, WireFormat, labels::KdfLabelKind},
    group::{ExternalSender, GroupId, RequiredCapabilities, extensions::Extension},
    messages::FramedContent,
    tree::TreeHash,
};

#[derive(Debug, Clone, PartialEq, Eq, Default, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GroupContext<'a> {
    pub version: ProtocolVersion,
    pub cipher_suite: CiphersuiteId,
    group_id: GroupId<'a>,
    pub epoch: u64,
    pub tree_hash: TreeHash<'a>,
    pub confirmed_transcript_hash: TranscriptHash<'a>,
    pub extensions: Vec<Extension<'a>>,
}

impl<'a> GroupContext<'a> {
    /// Allows for initialization with an arbitrary group id
    pub fn with_group_id(group_id: GroupId<'a>) -> Self {
        Self {
            group_id,
            ..Default::default()
        }
    }

    // 8.1 -> The `group_id` field is constant
    pub fn group_id(&self) -> &[u8] {
        &self.group_id
    }

    pub fn external_senders(&self) -> &[ExternalSender<'a>] {
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

    #[cfg(feature = "draft-ietf-mls-extensions")]
    pub fn app_data_dict(
        &self,
    ) -> Option<&crate::drafts::mls_extensions::safe_application::ApplicationDataDictionary<'_>>
    {
        self.extensions.iter().find_map(|ext| {
            if let Extension::ApplicationData(add) = ext {
                Some(add)
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

pub type TranscriptHash<'a> = SensitiveBytes<'a>;

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSize, thalassa::TlsplSerialize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ConfirmedTranscriptHashInput<'a> {
    pub wire_format: &'a WireFormat,
    pub content: &'a FramedContent<'a>,
    pub signature: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSize, thalassa::TlsplSerialize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct InterimTranscriptHashInput<'a> {
    pub confirmation_tag: &'a [u8],
}

impl<'a> From<&'a [u8]> for InterimTranscriptHashInput<'a> {
    fn from(confirmation_tag: &'a [u8]) -> Self {
        Self { confirmation_tag }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(
    feature = "serde",
    derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr)
)]
#[repr(u8)]
pub enum PskType {
    Reserved = 0x00,
    External = 0x01,
    Resumption = 0x02,
    #[cfg(feature = "draft-ietf-mls-extensions")]
    Application = 0x03,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(
    feature = "serde",
    derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr)
)]
#[repr(u8)]
pub enum ResumptionPskUsage {
    Reserved = 0x00,
    Application = 0x01,
    ReInit = 0x02,
    Branch = 0x03,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum PreSharedKeyIdPskType<'a> {
    #[tlspl(discriminant = "PskType::External")]
    External(ExternalPsk<'a>),
    #[tlspl(discriminant = "PskType::Resumption")]
    Resumption(ResumptionPsk<'a>),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[tlspl(discriminant = "PskType::Application")]
    Application(ApplicationPsk<'a>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExternalPsk<'a> {
    pub psk_id: Cow<'a, [u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResumptionPsk<'a> {
    pub usage: ResumptionPskUsage,
    pub psk_group_id: GroupId<'a>,
    pub psk_epoch: Epoch,
}

#[cfg(feature = "draft-ietf-mls-extensions")]
#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ApplicationPsk<'a> {
    pub component_id: crate::drafts::mls_extensions::safe_application::ComponentId,
    pub psk_id: Cow<'a, [u8]>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll, zeroize::Zeroize, zeroize::ZeroizeOnDrop,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PreSharedKeyId<'a> {
    #[zeroize(skip)]
    pub psktype: PreSharedKeyIdPskType<'a>,
    pub psk_nonce: SensitiveBytes<'a>,
}

impl PreSharedKeyId<'_> {
    pub fn with_default_nonce(&self) -> Self {
        Self {
            psktype: self.psktype.clone(),
            psk_nonce: SensitiveBytes::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSize, thalassa::TlsplSerialize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct PskLabel<'a> {
    pub id: PreSharedKeyId<'a>,
    pub index: u16,
    pub count: u16,
}
