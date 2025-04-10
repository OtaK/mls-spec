use crate::{
    credential::Credential,
    crypto::{HpkePublicKey, HpkePublicKeyRef, SignaturePublicKey, SignaturePublicKeyRef},
    defs::{Capabilities, LeafIndex},
    group::{extensions::Extension, KeyPackageLifetime},
    SensitiveBytes,
};

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    tls_codec::TlsSize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSerialize,
    strum::Display,
)]
#[repr(u8)]
pub enum LeafNodeSourceType {
    Reserved = 0x00,
    KeyPackage = 0x01,
    Update = 0x02,
    Commit = 0x03,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum LeafNodeSource {
    #[tls_codec(discriminant = "LeafNodeSourceType::KeyPackage")]
    KeyPackage { lifetime: KeyPackageLifetime },
    #[tls_codec(discriminant = "LeafNodeSourceType::Update")]
    Update,
    #[tls_codec(discriminant = "LeafNodeSourceType::Commit")]
    Commit { parent_hash: SensitiveBytes },
}

impl From<&LeafNodeSource> for LeafNodeSourceType {
    fn from(value: &LeafNodeSource) -> Self {
        match value {
            LeafNodeSource::KeyPackage { .. } => Self::KeyPackage,
            LeafNodeSource::Update => Self::Update,
            LeafNodeSource::Commit { .. } => Self::Commit,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct LeafNodeMemberInfo<'a> {
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub group_id: &'a [u8],
    pub leaf_index: LeafIndex,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LeafNode {
    pub encryption_key: HpkePublicKey,
    pub signature_key: SignaturePublicKey,
    pub credential: Credential,
    pub capabilities: Capabilities,
    pub source: LeafNodeSource,
    pub extensions: Vec<Extension>,
    pub signature: SensitiveBytes,
}

impl LeafNode {
    #[inline]
    pub fn requires_member_info(&self) -> bool {
        matches!(
            self.source,
            LeafNodeSource::Update | LeafNodeSource::Commit { .. }
        )
    }

    pub fn parent_hash(&self) -> Option<&[u8]> {
        match &self.source {
            LeafNodeSource::Commit { parent_hash } => Some(parent_hash),
            _ => None,
        }
    }

    pub fn to_tbs<'a>(
        &'a self,
        member_info: Option<LeafNodeMemberInfo<'a>>,
    ) -> Option<LeafNodeTBS<'a>> {
        Some(LeafNodeTBS {
            encryption_key: &self.encryption_key,
            signature_key: &self.signature_key,
            credential: &self.credential,
            capabilities: &self.capabilities,
            source: &self.source,
            extensions: &self.extensions,
            member_info: if self.requires_member_info() {
                // Invalid because in those context we should have a valid member_info
                Some(member_info?)
            } else {
                None
            },
        })
    }

    pub fn application_id(&self) -> Option<&[u8]> {
        self.extensions.iter().find_map(|ext| {
            if let Extension::ApplicationId(app_id) = ext {
                Some(app_id.as_slice())
            } else {
                None
            }
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct LeafNodeTBS<'a> {
    pub encryption_key: HpkePublicKeyRef<'a>,
    pub signature_key: SignaturePublicKeyRef<'a>,
    pub credential: &'a Credential,
    pub capabilities: &'a Capabilities,
    pub source: &'a LeafNodeSource,
    pub extensions: &'a Vec<Extension>,
    pub member_info: Option<LeafNodeMemberInfo<'a>>,
}

impl tls_codec::Size for LeafNodeTBS<'_> {
    fn tls_serialized_len(&self) -> usize {
        self.encryption_key.tls_serialized_len()
            + self.signature_key.tls_serialized_len()
            + self.credential.tls_serialized_len()
            + self.capabilities.tls_serialized_len()
            + self.source.tls_serialized_len()
            + self.extensions.tls_serialized_len()
            + self.member_info.map_or(0, |mi| mi.tls_serialized_len())
    }
}

impl tls_codec::Serialize for LeafNodeTBS<'_> {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = 0;
        written += crate::tlspl::bytes::tls_serialize(self.encryption_key, writer)?;
        written += crate::tlspl::bytes::tls_serialize(self.signature_key, writer)?;
        written += self.credential.tls_serialize(writer)?;
        written += self.capabilities.tls_serialize(writer)?;
        written += self.source.tls_serialize(writer)?;
        written += self.extensions.tls_serialize(writer)?;
        if let Some(member_info) = self.member_info {
            written += member_info.tls_serialize(writer)?;
        }

        Ok(written)
    }
}
