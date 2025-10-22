use crate::macros::impl_spec_enum;

pub mod labels;

pub type LeafIndex = u32;
pub type SenderIndex = u32;
pub type Generation = u32;
pub type Epoch = u64;

pub const MLS_MIME_TYPE: &str = "message/mls";

/// MLS GREASE values to check implementation robustness
///
/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-13.5>
pub const GREASE_VALUES: [u16; 15] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA,
];

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
    strum::IntoStaticStr,
    strum::Display,
    strum::EnumString,
)]
#[cfg_attr(
    feature = "serde",
    derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr)
)]
#[repr(u16)]
#[non_exhaustive]
pub enum ProtocolVersion {
    Reserved = 0x0000,
    #[strum(serialize = "MLS 1.0")]
    #[default]
    Mls10 = 0x0001,
}

impl ProtocolVersion {
    #[must_use]
    pub fn all_without_spec_default() -> Vec<Self> {
        vec![Self::Mls10]
    }
}

impl_spec_enum! {
    CiphersuiteId(u16);
    serde_repr "u16";
    reserved_priv 0xF000..=0xFFFF => crate::MlsSpecError::InvalidPrivateRangeCiphersuite;
    default_range None;
    SPEC_RESERVED = 0x0000,
    MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519 = 0x0001,
    MLS_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002,
    MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519 = 0x0003,
    MLS_256_DHKEMX448_AES256GCM_SHA512_ED448 = 0x0004,
    MLS_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0005,
    MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_ED448 = 0x0006,
    MLS_256_DHKEMP384_AES256GCM_SHA384_P384 = 0x0007
}

impl Default for CiphersuiteId {
    fn default() -> Self {
        Self(Self::MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519)
    }
}

impl_spec_enum! {
    ExtensionType(u16);
    serde_repr "u16";
    reserved_priv 0xF000..=0xFFFF => crate::MlsSpecError::InvalidPrivateRangeExtensionType;
    default_range Some(0x0001..=0x0005);
    SPEC_RESERVED = 0x0000,
    APPLICATION_ID = 0x0001,
    RATCHET_TREE = 0x0002,
    REQUIRED_CAPABILITIES = 0x0003,
    EXTERNAL_PUB = 0x0004,
    EXTERNAL_SENDERS = 0x0005,
    #[cfg(feature = "draft-ietf-mls-extensions")]
    APPLICATION_DATA_DICTIONARY = crate::drafts::mls_extensions::EXTENSION_APP_DATA_DICT,
    #[cfg(feature = "draft-ietf-mls-extensions")]
    SUPPORTED_WIRE_FORMATS = crate::drafts::mls_extensions::EXTENSION_SUPPORTED_WIRE_FORMATS,
    #[cfg(feature = "draft-ietf-mls-extensions")]
    REQUIRED_WIRE_FORMATS = crate::drafts::mls_extensions::EXTENSION_REQUIRED_WIRE_FORMATS,
    #[cfg(feature = "draft-ietf-mls-extensions")]
    TARGETED_MESSAGES_CAPABILITY = crate::drafts::mls_extensions::EXTENSION_TARGETED_MESSAGES_CAPABILITY,
    #[cfg(feature = "draft-mahy-mls-ratchet-tree-options")]
    RATCHET_TREE_SOURCE_DOMAINS = crate::drafts::ratchet_tree_options::EXTENSION_RATCHET_TREE_SOURCE_DOMAINS
}

impl Default for ExtensionType {
    fn default() -> Self {
        Self(Self::SPEC_RESERVED)
    }
}

impl_spec_enum! {
    ProposalType(u16);
    serde_repr "u16";
    reserved_priv 0xF000..=0xFFFF => crate::MlsSpecError::InvalidPrivateRangeProposalType;
    default_range Some(0x0001..=0x0007);
    SPEC_RESERVED = 0x0000,
    ADD = 0x0001,
    UPDATE = 0x0002,
    REMOVE = 0x0003,
    PSK = 0x0004,
    REINIT = 0x0005,
    EXTERNAL_INIT = 0x0006,
    GROUP_CONTEXT_EXTENSIONS = 0x0007,
    #[cfg(feature = "draft-ietf-mls-extensions")]
    APP_DATA_UPDATE = crate::drafts::mls_extensions::PROPOSAL_APP_DATA_UPDATE,
    #[cfg(feature = "draft-ietf-mls-extensions")]
    APP_EPHEMERAL = crate::drafts::mls_extensions::PROPOSAL_APP_EPHEMERAL,
    #[cfg(feature = "draft-ietf-mls-extensions")]
    SELF_REMOVE = crate::drafts::mls_extensions::PROPOSAL_SELF_REMOVE
}

impl ProposalType {
    #[inline]
    pub fn is_allowed_in_external_proposals(&self) -> bool {
        #[allow(unused_mut)]
        let mut allowed = matches!(
            self.0,
            Self::ADD | Self::REMOVE | Self::PSK | Self::REINIT | Self::GROUP_CONTEXT_EXTENSIONS
        );

        #[cfg(feature = "draft-ietf-mls-extensions")]
        {
            allowed |= matches!(self.0, Self::APP_DATA_UPDATE | Self::APP_EPHEMERAL);
        }

        allowed
    }

    #[inline]
    pub fn needs_update_path(&self) -> bool {
        #[allow(unused_mut)]
        let mut needs_update_path = matches!(
            self.0,
            Self::UPDATE | Self::REMOVE | Self::EXTERNAL_INIT | Self::GROUP_CONTEXT_EXTENSIONS
        );

        #[cfg(feature = "draft-ietf-mls-extensions")]
        {
            needs_update_path |= matches!(self.0, Self::SELF_REMOVE);
        }

        needs_update_path
    }
}

impl_spec_enum! {
    CredentialType(u16);
    serde_repr "u16";
    reserved_priv 0xF000..=0xFFFF => crate::MlsSpecError::InvalidPrivateRangeCredentialType;
    default_range None;
    SPEC_RESERVED = 0x0000,
    BASIC = 0x0001,
    X509 = 0x0002,
    #[cfg(feature = "draft-ietf-mls-extensions")]
    MULTI_CREDENTIAL = crate::drafts::mls_extensions::multi_credentials::MULTI_CREDENTIAL,
    #[cfg(feature = "draft-ietf-mls-extensions")]
    WEAK_MULTI_CREDENTIAL= crate::drafts::mls_extensions::multi_credentials::WEAK_MULTI_CREDENTIAL,
    #[cfg(feature = "draft-mahy-mls-sd-cwt-credential")]
    SD_CWT_CREDENTIAL = crate::drafts::sd_cwt_credential::CREDENTIAL_SD_CWT,
    #[cfg(feature = "draft-mahy-mls-sd-cwt-credential")]
    SD_JWT_CREDENTIAL = crate::drafts::sd_cwt_credential::CREDENTIAL_SD_JWT
}

impl Default for CredentialType {
    fn default() -> Self {
        Self(Self::BASIC)
    }
}

impl_spec_enum! {
    WireFormat(u16);
    serde_repr "u16";
    reserved_priv 0xF000..=0xFFFF => crate::MlsSpecError::InvalidPrivateRangeWireFormat;
    default_range None;
    SPEC_RESERVED = 0x0000,
    MLS_PUBLIC_MESSAGE = 0x0001,
    MLS_PRIVATE_MESSAGE = 0x0002,
    MLS_WELCOME = 0x0003,
    MLS_GROUP_INFO = 0x0004,
    MLS_KEY_PACKAGE = 0x0005,
    #[cfg(feature = "draft-ietf-mls-extensions")]
    MLS_TARGETED_MESSAGE = crate::drafts::mls_extensions::WIRE_FORMAT_MLS_TARGETED_MESSAGE,
    #[cfg(feature = "draft-mahy-mls-semiprivatemessage")]
    MLS_SEMIPRIVATE_MESSAGE = crate::drafts::semiprivate_message::WIRE_FORMAT_MLS_SEMIPRIVATE_MESSAGE,
    #[cfg(feature = "draft-mularczyk-mls-splitcommit")]
    MLS_SPLIT_COMMIT = crate::drafts::split_commit::WIRE_FORMAT_MLS_SPLIT_COMMIT,
    #[cfg(feature = "draft-pham-mls-additional-wire-formats")]
    MLS_MESSAGE_WITHOUT_AAD = crate::drafts::additional_wire_formats::WIRE_FORMAT_MLS_MESSAGE_WITHOUT_AAD
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
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Capabilities {
    pub versions: Vec<ProtocolVersion>,
    pub ciphersuites: Vec<CiphersuiteId>,
    pub extensions: Vec<ExtensionType>,
    pub proposals: Vec<ProposalType>,
    pub credentials: Vec<CredentialType>,
}
