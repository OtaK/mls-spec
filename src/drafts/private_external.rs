use std::borrow::Cow;

use crate::{
    SensitiveBytes,
    crypto::{HpkeCiphertext, HpkePublicKey, SignaturePublicKey},
    defs::{CiphersuiteId, Epoch, ProtocolVersion, WireFormat},
    drafts::mls_extensions::safe_application::{self, ComponentId},
    group::GroupId,
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
    *super::mls_extensions::COMPONENT_RESERVED_PRIVATE_RANGE.start() <= EXT_ENCRYPTION_INFO_ID
        && EXT_ENCRYPTION_INFO_ID
            <= *super::mls_extensions::COMPONENT_RESERVED_PRIVATE_RANGE.end()
);

/// <https://www.ietf.org/archive/id/draft-mahy-mls-private-external-01.html#section-3.2>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     opaque root_private_signature_key<V>;
/// } RootPrivateSignature;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RootPrivateSignature<'a> {
    pub root_private_signature_key: SensitiveBytes<'a>,
}

impl<'a> safe_application::Component<'a> for RootPrivateSignature<'a> {
    fn component_id() -> ComponentId {
        ROOT_PRIVATE_SIGNATURE_ID
    }
}

/// <https://www.ietf.org/archive/id/draft-mahy-mls-private-external-01.html#section-3.2>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     ProtocolVersion version = mls10;
///     opaque group_id<V>;
///     uint64 epoch;
///     CipherSuite ciphersuite;
///     HPKEPublicKey external_encryption_public_key;
///     SignaturePublicKey root_public_signature_key;
/// } ExternalEncryptionInfoTBS;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSize, thalassa::TlsplSerialize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ExternalEncryptionInfoTBS<'a> {
    pub version: &'a ProtocolVersion,
    pub group_id: &'a GroupId<'a>,
    pub epoch: &'a Epoch,
    pub ciphersuite: &'a CiphersuiteId,
    pub external_encryption_public_key: &'a HpkePublicKey<'a>,
    pub root_public_signature_key: &'a SignaturePublicKey<'a>,
}

/// <https://www.ietf.org/archive/id/draft-mahy-mls-private-external-01.html#section-3.2>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     CipherSuite ciphersuite;
///     HPKEPublicKey external_encryption_public_key;
///     SignaturePublicKey root_public_signature_key;
///     /* SignWithLabel(root_private_signature_key, */
///     /*    "ExternalEncryptionInfoTBS", ExternalEncryptionInfoTBS) */
///     opaque external_encryption_signature<V>;
/// } ExternalEncryptionInfo;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExternalEncryptionInfo<'a> {
    pub ciphersuite: CiphersuiteId,
    pub external_encryption_public_key: HpkePublicKey<'a>,
    pub root_public_signature_key: SignaturePublicKey<'a>,
    pub external_encryption_signature: SensitiveBytes<'a>,
}

impl<'a> safe_application::Component<'a> for ExternalEncryptionInfo<'a> {
    fn component_id() -> ComponentId {
        EXT_ENCRYPTION_INFO_ID
    }
}

impl<'a> ExternalEncryptionInfo<'a> {
    pub fn to_tbs(
        &'a self,
        version: &'a ProtocolVersion,
        group_id: &'a GroupId<'a>,
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

/// <https://www.ietf.org/archive/id/draft-mahy-mls-private-external-01.html#section-3.3>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
/// } PrivateExternalMessageContext;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PrivateExternalMessageContext;

/// <https://www.ietf.org/archive/id/draft-mahy-mls-private-external-01.html#section-3.3>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     opaque group_id<V>;
///     uint64 epoch;
///     ContentType content_type;
///     opaque authenticated_data<V>;
///     HPKECiphertext encrypted_public_message;
/// } PrivateExternalMessage;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PrivateExternalMessage<'a> {
    pub group_id: GroupId<'a>,
    pub epoch: Epoch,
    pub content_type: ContentType,
    pub authenticated_data: Cow<'a, [u8]>,
    pub encrypted_public_message: HpkeCiphertext<'a>,
}
