use crate::defs::CredentialType;

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
    Hash,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BasicCredential {
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub identity: Vec<u8>,
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
pub struct Certificate {
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub cert_data: Vec<u8>,
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
pub struct X509Credential {
    pub certificates: Vec<Certificate>,
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
#[repr(u16)]
pub enum Credential {
    #[tls_codec(discriminant = "CredentialType::BASIC")]
    Basic(BasicCredential),
    #[tls_codec(discriminant = "CredentialType::X509")]
    X509(X509Credential),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[tls_codec(discriminant = "CredentialType::MULTI_CREDENTIAL")]
    MultiCredential(crate::drafts::mls_extensions::multi_credentials::MultiCredential),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[tls_codec(discriminant = "CredentialType::WEAK_MULTI_CREDENTIAL")]
    WeakMultiCredential(crate::drafts::mls_extensions::multi_credentials::WeakMultiCredential),
    #[cfg(feature = "draft-mahy-mls-sd-cwt-credential")]
    #[tls_codec(discriminant = "CredentialType::SD_CWT_CREDENTIAL")]
    SdCwtCredential(crate::drafts::sd_cwt_credential::SdCwtCredential),
    #[cfg(feature = "draft-mahy-mls-sd-cwt-credential")]
    #[tls_codec(discriminant = "CredentialType::SD_JWT_CREDENTIAL")]
    SdJwtCredential(crate::drafts::sd_cwt_credential::SdJwtCredential),
}

impl Credential {
    pub fn basic(identity: Vec<u8>) -> Self {
        Self::Basic(BasicCredential { identity })
    }
}

impl From<&Credential> for CredentialType {
    fn from(value: &Credential) -> Self {
        match value {
            Credential::Basic(_) => CredentialType::BASIC,
            Credential::X509(_) => CredentialType::X509,
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Credential::MultiCredential(_) => CredentialType::MULTI_CREDENTIAL,
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Credential::WeakMultiCredential(_) => CredentialType::WEAK_MULTI_CREDENTIAL,
            #[cfg(feature = "draft-mahy-mls-sd-cwt-credential")]
            Credential::SdCwtCredential(_) => CredentialType::SD_CWT_CREDENTIAL,
            #[cfg(feature = "draft-mahy-mls-sd-cwt-credential")]
            Credential::SdJwtCredential(_) => CredentialType::SD_JWT_CREDENTIAL,
        }
        .try_into()
        // SAFETY: We only handle known, safe values so this cannot fail
        .unwrap()
    }
}
