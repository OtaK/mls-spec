use crate::ToPrefixedLabel;

/// Labels for MLS DSA signature/verification.
///
/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.2-4>
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, strum::IntoStaticStr, strum::EnumString, strum::Display,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum SignatureLabel {
    FramedContentTBS,
    LeafNodeTBS,
    KeyPackageTBS,
    GroupInfoTBS,
    #[cfg(feature = "draft-ietf-mls-extensions")]
    TargetedMessagesTBS,
    #[cfg(feature = "draft-ietf-mls-extensions")]
    ComponentOperationLabel,
    #[cfg(feature = "draft-kohbrok-mls-associated-parties")]
    AssociatedPartyEntryTBS,
    #[cfg(feature = "test-vectors")]
    #[strum(serialize = "SignWithLabel")]
    TestVectorSignWithLabel,
}

impl ToPrefixedLabel for SignatureLabel {}

/// Labels for MLS HPKE contexts.
///
/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.3-2>
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    strum::IntoStaticStr,
    strum::EnumString,
    strum::Display,
    strum::AsRefStr,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum PublicKeyEncryptionLabel {
    UpdatePathNode,
    Welcome,
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[strum(serialize = "Application")]
    SafeApp,
    #[cfg(feature = "draft-mahy-mls-semiprivatemessage")]
    SemiPrivateMessageReceiver,
    #[cfg(feature = "test-vectors")]
    #[strum(serialize = "EncryptWithLabel")]
    TestVectorEncryptWithLabel,
}

impl ToPrefixedLabel for PublicKeyEncryptionLabel {}

/// Labels for MLS `HashReference`s, such as `KeyPackageRef`s or `ProposalRef`s
///
/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-5.2>
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, strum::IntoStaticStr, strum::EnumString, strum::Display,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum HashReferenceKind {
    #[strum(serialize = "KeyPackage Reference")]
    KeyPackageRef,
    #[strum(serialize = "Proposal Reference")]
    ProposalRef,
    #[cfg(feature = "test-vectors")]
    #[strum(serialize = "RefHash")]
    TestVectorRefHash,
}

impl ToPrefixedLabel for HashReferenceKind {}

/// Labels for MLS KDF derivations (i.e. domain separation)
///
/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-8-13>
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    strum::IntoStaticStr,
    strum::EnumString,
    strum::Display,
    strum::AsRefStr,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
#[strum(serialize_all = "lowercase")]
pub enum KdfLabelKind {
    Joiner,
    Welcome,
    Epoch,
    Init,
    #[strum(serialize = "sender data")]
    SenderData,
    Encryption,
    Exported,
    Exporter,
    External,
    Confirm,
    Membership,
    Resumption,
    Authentication,
    Application,
    Handshake,
    Tree,
    Nonce,
    Key,
    Secret,
    Path,
    Node,
    #[strum(serialize = "derived psk")]
    DerivedPsk,
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[strum(serialize = "targeted message psk")]
    TargetedMessagePsk,
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[strum(serialize = "targeted message sender auth data")]
    TargetedMessageSenderAuthData,
    #[cfg(feature = "draft-kohbrok-mls-associated-parties")]
    #[strum(serialize = "ap_epoch")]
    AssociatedPartyKeyScheduleEpochSecret,
    #[cfg(feature = "draft-kohbrok-mls-associated-parties")]
    #[strum(serialize = "ap_exporter")]
    AssociatedPartyKeyScheduleExporterSecret,
    #[cfg(feature = "draft-kohbrok-mls-associated-parties")]
    #[strum(serialize = "AP Secret")]
    AssociatedPartyEpochSecret,
    #[cfg(feature = "draft-kohbrok-mls-associated-parties")]
    #[strum(serialize = "AP Exporter Secret")]
    AssociatedPartySecret,
    #[cfg(feature = "draft-kohbrok-mls-associated-parties")]
    #[strum(serialize = "AP Commit Secret")]
    AssociatedPartyCommitSecret,
    #[cfg(feature = "draft-kohbrok-mls-associated-parties")]
    #[strum(serialize = "AP Commit Secret ID")]
    AssociatedPartyCommitSecretId,
    #[cfg(feature = "draft-kohbrok-mls-associated-parties")]
    #[strum(serialize = "AP Commit Base Secret")]
    AssociatedPartyCommitBaseSecret,
    #[cfg(feature = "draft-ietf-mls-combiner")]
    #[strum(serialize = "hpqmls_export")]
    HpqMlsExport,
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[strum(serialize = "ApplicationExport {component_id} {label}")]
    ApplicationExport {
        component_id: crate::drafts::mls_extensions::safe_application::ComponentId,
        label: String,
    },
    #[cfg(feature = "test-vectors")]
    #[strum(serialize = "DeriveTreeSecret")]
    TestVectorDeriveTreeSecret,
    #[cfg(feature = "test-vectors")]
    #[strum(serialize = "DeriveSecret")]
    TestVectorDeriveSecret,
    #[cfg(feature = "test-vectors")]
    #[strum(serialize = "ExpandWithLabel")]
    TestVectorExpandWithLabel,
    #[strum(serialize = "{0}")]
    Arbitrary(String),
}

#[cfg(feature = "draft-ietf-mls-extensions")]
impl KdfLabelKind {
    #[must_use]
    pub fn to_application_export(
        &self,
        component_id: crate::drafts::mls_extensions::safe_application::ComponentId,
    ) -> Self {
        Self::ApplicationExport {
            component_id,
            label: self.to_string(),
        }
    }
}

impl ToPrefixedLabel for KdfLabelKind {
    fn to_prefixed_string(&self, protocol_version: crate::defs::ProtocolVersion) -> String {
        format!("{protocol_version} {self}")
    }
}
