use std::borrow::Cow;

use crate::defs::CredentialType;

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BasicCredential<'a> {
    pub identity: Cow<'a, [u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Certificate<'a> {
    pub cert_data: Cow<'a, [u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct X509Credential<'a> {
    pub certificates: Vec<Certificate<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u16)]
pub enum Credential<'a> {
    #[tlspl(discriminant = "CredentialType::BASIC")]
    Basic(BasicCredential<'a>),
    #[tlspl(discriminant = "CredentialType::X509")]
    X509(X509Credential<'a>),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[tlspl(discriminant = "CredentialType::MULTI_CREDENTIAL")]
    MultiCredential(crate::drafts::mls_extensions::multi_credentials::MultiCredential<'a>),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[tlspl(discriminant = "CredentialType::WEAK_MULTI_CREDENTIAL")]
    WeakMultiCredential(crate::drafts::mls_extensions::multi_credentials::WeakMultiCredential<'a>),
    #[cfg(feature = "draft-mahy-mls-sd-cwt-credential")]
    #[tlspl(discriminant = "CredentialType::SD_CWT_CREDENTIAL")]
    SdCwtCredential(crate::drafts::sd_cwt_credential::SdCwtCredential<'a>),
    #[cfg(feature = "draft-mahy-mls-sd-cwt-credential")]
    #[tlspl(discriminant = "CredentialType::SD_JWT_CREDENTIAL")]
    SdJwtCredential(crate::drafts::sd_cwt_credential::SdJwtCredential<'a>),
}

impl Credential<'_> {
    pub fn basic(identity: Vec<u8>) -> Self {
        Self::Basic(BasicCredential {
            identity: Cow::Owned(identity),
        })
    }
}

impl<'a> From<&'a Credential<'a>> for CredentialType {
    fn from(value: &'a Credential) -> Self {
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
    }
}
