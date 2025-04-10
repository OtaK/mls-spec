use crate::{defs::CiphersuiteId, key_schedule::PreSharedKeyId, SensitiveBytes, ToPrefixedLabel};

pub type Mac = SensitiveBytes;
pub type HpkePublicKey = SensitiveBytes;
pub type HpkePublicKeyRef<'a> = &'a SensitiveBytes;
pub type HpkePrivateKey = SensitiveBytes;
pub type HpkePrivateKeyRef<'a> = &'a SensitiveBytes;
pub type SignaturePublicKey = SensitiveBytes;
pub type SignaturePublicKeyRef<'a> = &'a SensitiveBytes;
pub type SignaturePrivateKey = SensitiveBytes;

#[derive(Debug, PartialEq, Eq, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyPair {
    #[zeroize(skip)]
    pub kem_id: u16,
    #[zeroize(skip)]
    pub ciphersuite: CiphersuiteId,
    pub pk: SensitiveBytes,
    pub sk: SensitiveBytes,
}

macro_rules! impl_keypair_alias {
    ($newtype:ident) => {
        #[derive(Debug, PartialEq, Eq, Clone)]
        #[repr(transparent)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "serde", serde(transparent))]
        pub struct $newtype(KeyPair);

        impl $newtype {
            pub fn extract_public_key(&mut self) -> SensitiveBytes {
                std::mem::take(&mut self.0.pk)
            }

            pub fn extract_secret_key(&mut self) -> SensitiveBytes {
                std::mem::take(&mut self.0.sk)
            }
        }

        impl From<KeyPair> for $newtype {
            fn from(value: KeyPair) -> Self {
                Self(value)
            }
        }

        impl std::ops::Deref for $newtype {
            type Target = KeyPair;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
    };
}

impl_keypair_alias!(SignatureKeyPair);
impl_keypair_alias!(HpkeKeyPair);
impl_keypair_alias!(KeyPackageKeyPair);

impl From<HpkeKeyPair> for KeyPackageKeyPair {
    fn from(mut value: HpkeKeyPair) -> Self {
        Self(KeyPair {
            kem_id: value.0.kem_id,
            ciphersuite: value.0.ciphersuite,
            pk: std::mem::take(&mut value.0.pk),
            sk: std::mem::take(&mut value.0.sk),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PreSharedKeyPair {
    pub psk_id: PreSharedKeyId,
    pub psk_secret: SensitiveBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct HpkeExport {
    pub kem_output: SensitiveBytes,
    pub export: SensitiveBytes,
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExternalInitSecret;
impl std::fmt::Display for ExternalInitSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "external init secret")
    }
}
impl ToPrefixedLabel for ExternalInitSecret {}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HpkeCiphertext {
    pub kem_output: SensitiveBytes,
    pub ciphertext: SensitiveBytes,
}

#[derive(Debug, Clone, Eq, PartialEq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignContent<'a> {
    #[tls_codec(with = "crate::tlspl::string")]
    pub label: &'a str,
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub content: &'a [u8],
}

#[derive(Debug, Clone, Eq, PartialEq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EncryptContext<'a> {
    #[tls_codec(with = "crate::tlspl::string")]
    pub label: &'a str,
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub context: &'a [u8],
}

#[derive(Debug, Clone, Eq, PartialEq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HashReferenceInput<'a> {
    #[tls_codec(with = "crate::tlspl::string")]
    pub label: &'a str,
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub value: &'a [u8],
}

#[derive(Debug, Clone, Eq, PartialEq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct KdfLabel<'a> {
    pub length: u16,
    #[tls_codec(with = "crate::tlspl::string")]
    pub label: &'a str,
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub context: &'a [u8],
}
