use crate::{
    SensitiveBytes,
    crypto::Mac,
    defs::{LeafIndex, ProtocolVersion},
    group::extensions::{Extension, ExternalPub, RatchetTreeExtension},
    key_schedule::GroupContext,
    messages::MlsMessage,
    tree::RatchetTree,
};

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct GroupInfoTBS<'a> {
    pub group_context: &'a GroupContext,
    pub extensions: &'a [Extension],
    pub confirmation_tag: &'a Mac,
    pub signer: &'a LeafIndex,
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
pub struct GroupInfo {
    pub group_context: GroupContext,
    pub extensions: Vec<Extension>,
    pub confirmation_tag: Mac,
    pub signer: LeafIndex,
    pub signature: SensitiveBytes,
}

impl GroupInfo {
    pub fn to_tbs(&self) -> GroupInfoTBS<'_> {
        GroupInfoTBS {
            group_context: &self.group_context,
            extensions: &self.extensions,
            confirmation_tag: &self.confirmation_tag,
            signer: &self.signer,
        }
    }

    /// Returns the RatchetTree extension if present
    pub fn ratchet_tree(&self) -> Option<&RatchetTree> {
        self.extensions.iter().find_map(|ext| {
            if let Extension::RatchetTree(RatchetTreeExtension { ratchet_tree }) = ext {
                Some(ratchet_tree)
            } else {
                None
            }
        })
    }

    /// Returns the ExternalPub extension if present
    pub fn external_pub(&self) -> Option<&[u8]> {
        self.extensions.iter().find_map(|ext| {
            if let Extension::ExternalPub(ExternalPub { external_pub }) = ext {
                Some(external_pub.as_slice())
            } else {
                None
            }
        })
    }

    pub fn into_mls_message(self, protocol_version: ProtocolVersion) -> MlsMessage {
        MlsMessage {
            version: protocol_version,
            content: crate::messages::MlsMessageContent::GroupInfo(self),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::generate_roundtrip_test;

    use super::*;

    generate_roundtrip_test!(can_roundtrip_groupinfo, {
        GroupInfo {
            group_context: GroupContext::with_group_id(vec![]),
            extensions: vec![],
            confirmation_tag: vec![].into(),
            signer: 0,
            signature: vec![].into(),
        }
    });
}
