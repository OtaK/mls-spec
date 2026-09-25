use crate::{
    SensitiveBytes, credential::Credential, crypto::SignaturePublicKey, defs::CiphersuiteId,
};

pub const MULTI_CREDENTIAL: u16 = 0x0003;
pub const WEAK_MULTI_CREDENTIAL: u16 = 0x0004;

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CredentialBinding<'a> {
    pub cipher_suite: CiphersuiteId,
    pub credential: Credential<'a>,
    pub credential_key: SignaturePublicKey<'a>,
    pub signature: SensitiveBytes<'a>,
}

impl<'a> CredentialBinding<'a> {
    pub fn to_tbs(&'a self, signature_key: &'a SignaturePublicKey<'a>) -> CredentialBindingTBS<'a> {
        CredentialBindingTBS {
            cipher_suite: &self.cipher_suite,
            credential: &self.credential,
            credential_key: &self.credential_key,
            signature_key,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MultiCredential<'a> {
    pub bindings: Vec<CredentialBinding<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WeakMultiCredential<'a> {
    pub bindings: Vec<CredentialBinding<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct CredentialBindingTBS<'a> {
    pub cipher_suite: &'a CiphersuiteId,
    pub credential: &'a Credential<'a>,
    pub credential_key: &'a SignaturePublicKey<'a>,
    pub signature_key: &'a SignaturePublicKey<'a>,
}
