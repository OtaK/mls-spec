use crate::{
    crypto::HpkeCiphertext,
    defs::{CiphersuiteId, ProtocolVersion},
    group::KeyPackageRef,
    key_schedule::PreSharedKeyId,
    messages::{MlsMessage, MlsMessageContent},
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
pub struct PathSecret {
    pub path_secret: SensitiveBytes,
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
pub struct GroupSecrets {
    pub joiner_secret: SensitiveBytes,
    pub path_secret: Option<PathSecret>,
    pub psks: Vec<PreSharedKeyId>,
}

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
pub struct GroupSecretsRef<'a> {
    pub joiner_secret: &'a [u8],
    pub path_secret: Option<&'a [u8]>,
    pub psks: &'a [PreSharedKeyId],
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
pub struct EncryptedGroupSecrets {
    pub new_member: KeyPackageRef,
    pub encrypted_group_secrets: HpkeCiphertext,
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
pub struct Welcome {
    pub cipher_suite: CiphersuiteId,
    pub secrets: Vec<EncryptedGroupSecrets>,
    pub encrypted_group_info: SensitiveBytes,
}

impl Welcome {
    pub fn into_mls_message(self, protocol_version: ProtocolVersion) -> MlsMessage {
        MlsMessage {
            version: protocol_version,
            content: MlsMessageContent::Welcome(self),
        }
    }
}
