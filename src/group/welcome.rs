use crate::{
    SensitiveBytes,
    crypto::HpkeCiphertext,
    defs::{CiphersuiteId, ProtocolVersion},
    group::KeyPackageRef,
    key_schedule::PreSharedKeyId,
    messages::{MlsMessage, MlsMessageContent},
};

/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.3.1>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///   opaque path_secret<V>;
/// } PathSecret;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PathSecret<'a> {
    pub path_secret: SensitiveBytes<'a>,
}

/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.3.1>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///   opaque joiner_secret<V>;
///   optional<PathSecret> path_secret;
///   PreSharedKeyID psks<V>;
/// } GroupSecrets;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GroupSecrets<'a> {
    pub joiner_secret: SensitiveBytes<'a>,
    pub path_secret: Option<PathSecret<'a>>,
    pub psks: Vec<PreSharedKeyId<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
pub struct GroupSecretsRef<'a> {
    pub joiner_secret: &'a [u8],
    pub path_secret: Option<&'a [u8]>,
    pub psks: &'a [PreSharedKeyId<'a>],
}

/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.3.1>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///   KeyPackageRef new_member;
///   HPKECiphertext encrypted_group_secrets;
/// } EncryptedGroupSecrets;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EncryptedGroupSecrets<'a> {
    pub new_member: KeyPackageRef<'a>,
    pub encrypted_group_secrets: HpkeCiphertext<'a>,
}

/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.3.1>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///   CipherSuite cipher_suite;
///   EncryptedGroupSecrets secrets<V>;
///   opaque encrypted_group_info<V>;
/// } Welcome;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Welcome<'a> {
    pub cipher_suite: CiphersuiteId,
    pub secrets: Vec<EncryptedGroupSecrets<'a>>,
    pub encrypted_group_info: SensitiveBytes<'a>,
}

impl<'a> Welcome<'a> {
    pub fn into_mls_message(self, protocol_version: ProtocolVersion) -> MlsMessage<'a> {
        MlsMessage {
            version: protocol_version,
            content: MlsMessageContent::Welcome(self),
        }
    }
}
