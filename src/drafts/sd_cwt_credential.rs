pub const CREDENTIAL_SD_CWT: u16 = 0x0005;
pub const CREDENTIAL_SD_JWT: u16 = 0x0006;

#[derive(
    Clone,
    PartialEq,
    Eq,
    Hash,
    tls_codec::TlsSize,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SdCwtCredential {
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub sd_kbt: Vec<u8>,
}

impl std::fmt::Debug for SdCwtCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SdCwtCredential")
            .field("sd_kbt", &hex::encode(&self.sd_kbt))
            .finish()
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    tls_codec::TlsSize,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
)]
#[cfg_attr(
    feature = "serde",
    derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr)
)]
#[repr(u8)]
pub enum SdJwtCredentialCompacted {
    Uncompacted = 0x00,
    Compacted = 0x01,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    tls_codec::TlsSize,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SdJwtDisclosure {
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub disclosure: Vec<u8>,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    tls_codec::TlsSize,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum SdJwtCredential {
    #[tls_codec(discriminant = "SdJwtCredentialCompacted::Uncompacted")]
    Uncompacted {
        #[tls_codec(with = "crate::tlspl::bytes")]
        sd_jwt_kb: Vec<u8>,
    },
    #[tls_codec(discriminant = "SdJwtCredentialCompacted::Compacted")]
    Compacted {
        #[tls_codec(with = "crate::tlspl::bytes")]
        protected: Vec<u8>,
        #[tls_codec(with = "crate::tlspl::bytes")]
        payload: Vec<u8>,
        #[tls_codec(with = "crate::tlspl::bytes")]
        signature: Vec<u8>,
        disclosures: Vec<SdJwtDisclosure>,
        #[tls_codec(with = "crate::tlspl::bytes")]
        sd_jwt_key_binding: Vec<u8>,
    },
}
