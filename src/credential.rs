use std::borrow::Cow;

use crate::defs::CredentialType;

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BasicCredential<'a> {
    pub identity: Cow<'a, [u8]>,
}

/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-5.3>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     opaque cert_data<V>;
/// } Certificate;
/// ```
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

/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-5.3>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     CredentialType credential_type;
///     select (Credential.credential_type) {
///         case basic:
///             opaque identity<V>;
///
///         case x509:
///             Certificate certificates<V>;
///     };
/// } Credential;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u16)]
pub enum Credential<'a> {
    #[tlspl(discriminant = CredentialType::BASIC.as_repr())]
    Basic(BasicCredential<'a>),
    #[tlspl(discriminant = CredentialType::X509.as_repr())]
    X509(X509Credential<'a>),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[tlspl(discriminant = CredentialType::MULTI_CREDENTIAL.as_repr())]
    MultiCredential(crate::drafts::mls_extensions::multi_credentials::MultiCredential<'a>),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[tlspl(discriminant = CredentialType::WEAK_MULTI_CREDENTIAL.as_repr())]
    WeakMultiCredential(crate::drafts::mls_extensions::multi_credentials::WeakMultiCredential<'a>),
    #[cfg(feature = "draft-mahy-mls-sd-cwt-credential")]
    #[tlspl(discriminant = CredentialType::SD_CWT_CREDENTIAL.as_repr())]
    SdCwtCredential(crate::drafts::sd_cwt_credential::SdCwtCredential<'a>),
    #[cfg(feature = "draft-mahy-mls-sd-cwt-credential")]
    #[tlspl(discriminant = CredentialType::SD_JWT_CREDENTIAL.as_repr())]
    SdJwtCredential(crate::drafts::sd_cwt_credential::SdJwtCredential<'a>),
}

impl Credential<'_> {
    pub fn to_owned<'out>(&self) -> Credential<'out> {
        match self {
            Credential::Basic(basic_credential) => {
                Credential::basic(basic_credential.identity.to_vec())
            }
            Credential::X509(x509_credential) => Credential::X509(X509Credential {
                certificates: x509_credential
                    .certificates
                    .iter()
                    .map(|cert| Certificate {
                        cert_data: cert.cert_data.to_vec().into(),
                    })
                    .collect(),
            }),
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Credential::MultiCredential(mc) => Credential::MultiCredential(
                crate::drafts::mls_extensions::multi_credentials::MultiCredential {
                    bindings: mc.bindings.iter().map(|b| b.to_owned()).collect(),
                },
            ),
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Credential::WeakMultiCredential(wmc) => Credential::WeakMultiCredential(
                crate::drafts::mls_extensions::multi_credentials::WeakMultiCredential {
                    bindings: wmc.bindings.iter().map(|b| b.to_owned()).collect(),
                },
            ),
            #[cfg(feature = "draft-mahy-mls-sd-cwt-credential")]
            Credential::SdCwtCredential(sd_cwt) => {
                Credential::SdCwtCredential(crate::drafts::sd_cwt_credential::SdCwtCredential {
                    sd_kbt: sd_cwt.sd_kbt.to_vec().into(),
                })
            }
            #[cfg(feature = "draft-mahy-mls-sd-cwt-credential")]
            Credential::SdJwtCredential(sd_jwt) => {
                use crate::drafts::sd_cwt_credential::{SdJwtCredential, SdJwtDisclosure};
                Credential::SdJwtCredential(match sd_jwt {
                    SdJwtCredential::Uncompacted { sd_jwt_kb } => SdJwtCredential::Uncompacted {
                        sd_jwt_kb: sd_jwt_kb.to_vec().into(),
                    },
                    SdJwtCredential::Compacted {
                        protected,
                        payload,
                        signature,
                        disclosures,
                        sd_jwt_key_binding,
                    } => SdJwtCredential::Compacted {
                        protected: protected.to_vec().into(),
                        payload: payload.to_vec().into(),
                        signature: signature.to_vec().into(),
                        disclosures: disclosures
                            .iter()
                            .map(|d| SdJwtDisclosure {
                                disclosure: d.disclosure.to_vec().into(),
                            })
                            .collect(),
                        sd_jwt_key_binding: sd_jwt_key_binding.to_vec().into(),
                    },
                })
            }
        }
    }

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

#[cfg(all(test, feature = "draft-ietf-mls-extensions"))]
mod tests {
    use super::*;
    use crate::drafts::mls_extensions::multi_credentials::{CredentialBinding, MultiCredential};

    #[test]
    fn multi_credential_to_owned_preserves_nested_credential() {
        let cred = Credential::MultiCredential(MultiCredential {
            bindings: vec![CredentialBinding {
                cipher_suite: Default::default(),
                credential: Credential::basic(b"alice".to_vec()),
                credential_key: b"key".to_vec().into(),
                signature: b"sig".to_vec().into(),
            }],
        });
        assert_eq!(cred.to_owned(), cred);
    }
}
