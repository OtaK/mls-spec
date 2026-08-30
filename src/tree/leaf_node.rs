use crate::{
    SensitiveBytes,
    credential::Credential,
    crypto::{HpkePublicKey, SignaturePublicKey},
    defs::{Capabilities, LeafIndex},
    group::{GroupId, KeyPackageLifetime, RequiredCapabilities, extensions::Extension},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thalassa::TlsplAll, strum::Display)]
#[cfg_attr(
    feature = "serde",
    derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr)
)]
#[repr(u8)]
pub enum LeafNodeSourceType {
    Reserved = 0x00,
    KeyPackage = 0x01,
    Update = 0x02,
    Commit = 0x03,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum LeafNodeSource<'a> {
    #[tlspl(discriminant = "LeafNodeSourceType::KeyPackage")]
    KeyPackage { lifetime: KeyPackageLifetime },
    #[tlspl(discriminant = "LeafNodeSourceType::Update")]
    Update,
    #[tlspl(discriminant = "LeafNodeSourceType::Commit")]
    Commit { parent_hash: SensitiveBytes<'a> },
}

impl LeafNodeSource<'_> {
    pub fn to_owned<'out>(&self) -> LeafNodeSource<'out> {
        match self {
            LeafNodeSource::KeyPackage { lifetime } => LeafNodeSource::KeyPackage {
                lifetime: *lifetime,
            },
            LeafNodeSource::Update => LeafNodeSource::Update,
            LeafNodeSource::Commit { parent_hash } => LeafNodeSource::Commit {
                parent_hash: parent_hash.to_vec().into(),
            },
        }
    }
}

impl From<&LeafNodeSource<'_>> for LeafNodeSourceType {
    fn from(value: &LeafNodeSource) -> Self {
        match value {
            LeafNodeSource::KeyPackage { .. } => Self::KeyPackage,
            LeafNodeSource::Update => Self::Update,
            LeafNodeSource::Commit { .. } => Self::Commit,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct LeafNodeMemberInfo<'a> {
    pub group_id: GroupId<'a>,
    pub leaf_index: LeafIndex,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LeafNode<'a> {
    pub encryption_key: HpkePublicKey<'a>,
    pub signature_key: SignaturePublicKey<'a>,
    pub credential: Credential<'a>,
    pub capabilities: Capabilities,
    pub source: LeafNodeSource<'a>,
    pub extensions: Vec<Extension<'a>>,
    pub signature: SensitiveBytes<'a>,
}

impl LeafNode<'_> {
    pub fn to_owned<'out>(&self) -> LeafNode<'out> {
        LeafNode {
            encryption_key: self.encryption_key.to_vec().into(),
            signature_key: self.signature_key.to_vec().into(),
            credential: self.credential.to_owned(),
            capabilities: self.capabilities.clone(),
            source: self.source.to_owned(),
            extensions: self.extensions.iter().map(|ext| ext.to_owned()).collect(),
            signature: self.signature.to_vec().into(),
        }
    }

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
                Some(&**app_id)
            } else {
                None
            }
        })
    }

    pub fn supports_required_capabilities(&self, required_caps: &RequiredCapabilities) -> bool {
        if !required_caps.extension_types.iter().all(|req_ext| {
            req_ext.is_grease_value()
                || req_ext.is_spec_default()
                || self.capabilities.extensions.contains(req_ext)
        }) {
            return false;
        }

        if !required_caps.proposal_types.iter().all(|req_prop| {
            req_prop.is_grease_value()
                || req_prop.is_spec_default()
                || self.capabilities.proposals.contains(req_prop)
        }) {
            return false;
        }

        if !required_caps.credential_types.iter().all(|req_cred| {
            req_cred.is_grease_value() || self.capabilities.credentials.contains(req_cred)
        }) {
            return false;
        }

        true
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct LeafNodeTBS<'a> {
    pub encryption_key: &'a HpkePublicKey<'a>,
    pub signature_key: &'a SignaturePublicKey<'a>,
    pub credential: &'a Credential<'a>,
    pub capabilities: &'a Capabilities,
    pub source: &'a LeafNodeSource<'a>,
    pub extensions: &'a Vec<Extension<'a>>,
    pub member_info: Option<LeafNodeMemberInfo<'a>>,
}

impl thalassa::TlsplSize for LeafNodeTBS<'_> {
    fn tlspl_serialized_len(&self) -> usize {
        self.encryption_key.tlspl_serialized_len()
            + self.signature_key.tlspl_serialized_len()
            + self.credential.tlspl_serialized_len()
            + self.capabilities.tlspl_serialized_len()
            + self.source.tlspl_serialized_len()
            + self.extensions.tlspl_serialized_len()
            + self
                .member_info
                .as_ref()
                .map_or(0, |mi| mi.tlspl_serialized_len())
    }
}

impl thalassa::TlsplSerialize for LeafNodeTBS<'_> {
    fn tlspl_serialize_to<W: thalassa::io::Write>(
        &self,
        writer: &mut W,
    ) -> thalassa::error::TlsplWriteResult<usize> {
        let mut written = 0;
        written += self.encryption_key.tlspl_serialize_to(writer)?;
        written += self.signature_key.tlspl_serialize_to(writer)?;
        written += self.credential.tlspl_serialize_to(writer)?;
        written += self.capabilities.tlspl_serialize_to(writer)?;
        written += self.source.tlspl_serialize_to(writer)?;
        written += self.extensions.tlspl_serialize_to(writer)?;
        if let Some(member_info) = &self.member_info {
            written += member_info.tlspl_serialize_to(writer)?;
        }

        Ok(written)
    }
}
