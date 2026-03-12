use crate::{
    SensitiveBytes,
    crypto::{
        HpkeCiphertext, HpkePublicKey, HpkePublicKeyRef, SignaturePublicKey, SignaturePublicKeyRef,
    },
    defs::{CiphersuiteId, Epoch, ProtocolVersion, WireFormat},
    drafts::mls_extensions::safe_application::{self, ComponentId},
    group::{GroupId, GroupIdRef},
    messages::ContentType,
};

pub const WIRE_FORMAT_MLS_PRIVATE_EXTERNAL_MESSAGE: u16 = 0xF4E9; // TODO: IANA attribution
static_assertions::const_assert!(
    *WireFormat::RESERVED_PRIVATE_USE_RANGE.start() <= WIRE_FORMAT_MLS_PRIVATE_EXTERNAL_MESSAGE
        && WIRE_FORMAT_MLS_PRIVATE_EXTERNAL_MESSAGE
            <= *WireFormat::RESERVED_PRIVATE_USE_RANGE.end()
);

pub const ROOT_PRIVATE_SIGNATURE_ID: ComponentId = 0xF15E;
static_assertions::const_assert!(
    *super::mls_extensions::COMPONENT_RESERVED_PRIVATE_RANGE.start() <= ROOT_PRIVATE_SIGNATURE_ID
        && ROOT_PRIVATE_SIGNATURE_ID
            <= *super::mls_extensions::COMPONENT_RESERVED_PRIVATE_RANGE.end()
);
pub const EXT_ENCRYPTION_INFO_ID: ComponentId = 0xFEE1;
static_assertions::const_assert!(
    *super::mls_extensions::COMPONENT_RESERVED_PRIVATE_RANGE.start() <= ROOT_PRIVATE_SIGNATURE_ID
        && ROOT_PRIVATE_SIGNATURE_ID
            <= *super::mls_extensions::COMPONENT_RESERVED_PRIVATE_RANGE.end()
);

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
pub struct RootPrivateSignature {
    pub root_private_signature_key: SensitiveBytes,
}

impl safe_application::Component for RootPrivateSignature {
    fn component_id() -> ComponentId {
        ROOT_PRIVATE_SIGNATURE_ID
    }
}

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSize, tls_codec::TlsSerialize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ExternalEncryptionInfoTBS<'a> {
    pub version: &'a ProtocolVersion,
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub group_id: GroupIdRef<'a>,
    pub epoch: &'a Epoch,
    pub ciphersuite: &'a CiphersuiteId,
    pub external_encryption_public_key: HpkePublicKeyRef<'a>,
    pub root_public_signature_key: SignaturePublicKeyRef<'a>,
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
pub struct ExternalEncryptionInfo {
    pub ciphersuite: CiphersuiteId,
    pub external_encryption_public_key: HpkePublicKey,
    pub root_public_signature_key: SignaturePublicKey,
    pub external_encryption_signature: SensitiveBytes,
}

impl safe_application::Component for ExternalEncryptionInfo {
    fn component_id() -> ComponentId {
        EXT_ENCRYPTION_INFO_ID
    }
}

impl ExternalEncryptionInfo {
    pub fn to_tbs<'a>(
        &'a self,
        version: &'a ProtocolVersion,
        group_id: GroupIdRef<'a>,
        epoch: &'a Epoch,
    ) -> ExternalEncryptionInfoTBS<'a> {
        ExternalEncryptionInfoTBS {
            version,
            group_id,
            epoch,
            ciphersuite: &self.ciphersuite,
            external_encryption_public_key: &self.external_encryption_public_key,
            root_public_signature_key: &self.root_public_signature_key,
        }
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
pub struct PrivateExternalMessageContext;

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
pub struct PrivateExternalMessage {
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub group_id: GroupId,
    pub epoch: Epoch,
    pub content_type: ContentType,
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub authenticated_data: Vec<u8>,
    pub encrypted_public_message: HpkeCiphertext,
}
