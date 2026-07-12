use std::borrow::Cow;

pub const CREDENTIAL_SD_CWT: u16 = 0x0005;
pub const CREDENTIAL_SD_JWT: u16 = 0x0006;

#[derive(Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SdCwtCredential<'a> {
    pub sd_kbt: Cow<'a, [u8]>,
}

impl std::fmt::Debug for SdCwtCredential<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SdCwtCredential")
            .field("sd_kbt", &hex::encode(&self.sd_kbt))
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(
    feature = "serde",
    derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr)
)]
#[repr(u8)]
pub enum SdJwtCredentialCompacted {
    Uncompacted = 0x00,
    Compacted = 0x01,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SdJwtDisclosure<'a> {
    pub disclosure: Cow<'a, [u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum SdJwtCredential<'a> {
    #[tlspl(discriminant = "SdJwtCredentialCompacted::Uncompacted")]
    Uncompacted { sd_jwt_kb: Cow<'a, [u8]> },
    #[tlspl(discriminant = "SdJwtCredentialCompacted::Compacted")]
    Compacted {
        protected: Cow<'a, [u8]>,
        payload: Cow<'a, [u8]>,
        signature: Cow<'a, [u8]>,
        disclosures: Vec<SdJwtDisclosure<'a>>,
        sd_jwt_key_binding: Cow<'a, [u8]>,
    },
}
