use crate::{SensitiveBytes, ToPrefixedLabel, defs::CiphersuiteId, key_schedule::PreSharedKeyId};

pub type Mac<'a> = SensitiveBytes<'a>;
pub type HpkePublicKey<'a> = SensitiveBytes<'a>;
pub type HpkePrivateKey<'a> = SensitiveBytes<'a>;
pub type SignaturePublicKey<'a> = SensitiveBytes<'a>;
pub type SignaturePrivateKey<'a> = SensitiveBytes<'a>;

#[derive(Debug, PartialEq, Eq, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyPair<'a> {
    #[zeroize(skip)]
    pub kem_id: u16,
    #[zeroize(skip)]
    pub ciphersuite: CiphersuiteId,
    pub pk: SensitiveBytes<'a>,
    pub sk: SensitiveBytes<'a>,
}

macro_rules! impl_keypair_alias {
    ($newtype:ident) => {
        #[derive(Debug, PartialEq, Eq, Clone)]
        #[repr(transparent)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "serde", serde(transparent))]
        pub struct $newtype<'a>(KeyPair<'a>);

        impl $newtype<'_> {
            pub fn extract_public_key(&mut self) -> SensitiveBytes<'_> {
                std::mem::take(&mut self.0.pk)
            }

            pub fn extract_secret_key(&mut self) -> SensitiveBytes<'_> {
                std::mem::take(&mut self.0.sk)
            }
        }

        impl<'a> From<KeyPair<'a>> for $newtype<'a> {
            fn from(value: KeyPair<'a>) -> Self {
                Self(value)
            }
        }

        impl<'a> std::ops::Deref for $newtype<'a> {
            type Target = KeyPair<'a>;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
    };
}

impl_keypair_alias!(SignatureKeyPair);
impl_keypair_alias!(HpkeKeyPair);
impl_keypair_alias!(KeyPackageKeyPair);

impl<'a> From<HpkeKeyPair<'a>> for KeyPackageKeyPair<'a> {
    fn from(mut value: HpkeKeyPair<'a>) -> Self {
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
pub struct PreSharedKeyPair<'a> {
    pub psk_id: PreSharedKeyId<'a>,
    pub psk_secret: SensitiveBytes<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct HpkeExport<'a> {
    pub kem_output: SensitiveBytes<'a>,
    pub export: SensitiveBytes<'a>,
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

#[derive(Debug, Clone, Eq, PartialEq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HpkeCiphertext<'a> {
    pub kem_output: SensitiveBytes<'a>,
    pub ciphertext: SensitiveBytes<'a>,
}

#[derive(Debug, Clone, Eq, PartialEq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignContent<'a> {
    pub label: &'a str,
    pub content: &'a [u8],
}

#[derive(Debug, Clone, Eq, PartialEq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EncryptContext<'a> {
    pub label: &'a str,
    pub context: &'a [u8],
}

#[derive(Debug, Clone, Eq, PartialEq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HashReferenceInput<'a> {
    pub label: &'a str,
    pub value: &'a [u8],
}

#[derive(Debug, Clone, Eq, PartialEq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct KdfLabel<'a> {
    pub length: u16,
    pub label: &'a str,
    pub context: &'a [u8],
}
