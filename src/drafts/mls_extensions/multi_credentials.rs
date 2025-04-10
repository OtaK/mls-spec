use crate::{
    credential::Credential,
    crypto::{SignaturePublicKey, SignaturePublicKeyRef},
    defs::CiphersuiteId,
    SensitiveBytes,
};

pub const MULTI_CREDENTIAL: u16 = 0x0003;
pub const WEAK_MULTI_CREDENTIAL: u16 = 0x0004;

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
pub struct CredentialBinding {
    pub cipher_suite: CiphersuiteId,
    pub credential: Credential,
    pub credential_key: SignaturePublicKey,
    pub signature: SensitiveBytes,
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
pub struct MultiCredential {
    pub bindings: Vec<CredentialBinding>,
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
pub struct WeakMultiCredential {
    pub bindings: Vec<CredentialBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct CredentialBindingTBS<'a> {
    pub cipher_suite: &'a CiphersuiteId,
    pub credential: &'a Credential,
    pub credential_key: SignaturePublicKeyRef<'a>,
    pub signature_key: SignaturePublicKeyRef<'a>,
}
