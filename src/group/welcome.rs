use crate::{
    SensitiveBytes,
    crypto::HpkeCiphertext,
    defs::{CiphersuiteId, ProtocolVersion},
    group::KeyPackageRef,
    key_schedule::PreSharedKeyId,
    messages::{MlsMessage, MlsMessageContent},
};

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PathSecret<'a> {
    pub path_secret: SensitiveBytes<'a>,
}

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

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EncryptedGroupSecrets<'a> {
    pub new_member: KeyPackageRef<'a>,
    pub encrypted_group_secrets: HpkeCiphertext<'a>,
}

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
