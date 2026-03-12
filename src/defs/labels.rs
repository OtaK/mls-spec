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
    #[cfg(feature = "draft-ietf-mls-targeted-messages")]
    TargetedMessagesTBS,
    #[cfg(feature = "draft-ietf-mls-extensions")]
    CredentialBindingTBS,
    #[cfg(feature = "draft-kohbrok-mls-associated-parties")]
    AssociatedPartyEntryTBS,
    #[cfg(feature = "draft-mahy-mls-private-external")]
    ExternalEncryptionInfoTBS,
    #[cfg(feature = "draft-kohbrok-mls-leaf-operation-intents")]
    LeafOperationIntentTBS,
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
    #[cfg(feature = "draft-mahy-mls-semiprivatemessage")]
    SemiPrivateMessageReceiver,
    #[cfg(feature = "draft-mahy-mls-private-external")]
    PrivateExternalMessageContent,
    #[cfg(feature = "draft-ietf-mls-targeted-messages")]
    TargetedMessageData,
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
    #[cfg(feature = "draft-kohbrok-mls-leaf-operation-intents")]
    #[strum(serialize = "LeafNode Reference")]
    LeafNodeRef,
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
    #[cfg(feature = "draft-mahy-mls-new-content-types")]
    Status,
    #[cfg(feature = "draft-mahy-mls-new-content-types")]
    Ephemeral,
    Tree,
    Nonce,
    Key,
    Secret,
    Path,
    Node,
    #[strum(serialize = "derived psk")]
    DerivedPsk,
    #[cfg(feature = "draft-ietf-mls-targeted-messages")]
    #[strum(serialize = "targeted message psk")]
    TargetedMessagePsk,
    #[cfg(feature = "draft-ietf-mls-targeted-messages")]
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
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[strum(serialize = "application_export")]
    ApplicationExportSecret,
    #[cfg(feature = "draft-mahy-mls-private-external")]
    #[strum(serialize = "external encryption")]
    ExternalEncryption,
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

impl ToPrefixedLabel for KdfLabelKind {
    fn to_prefixed_string(&self, protocol_version: crate::defs::ProtocolVersion) -> String {
        format!("{protocol_version} {self}")
    }
}
