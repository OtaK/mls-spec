use crate::{
    SensitiveBytes,
    crypto::Mac,
    defs::{LeafIndex, ProtocolVersion},
    group::extensions::{Extension, ExternalPub, RatchetTreeExtension},
    key_schedule::GroupContext,
    messages::MlsMessage,
    tree::RatchetTree,
};

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct GroupInfoTBS<'a> {
    pub group_context: &'a GroupContext<'a>,
    pub extensions: &'a [Extension<'a>],
    pub confirmation_tag: &'a Mac<'a>,
    pub signer: &'a LeafIndex,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GroupInfo<'a> {
    pub group_context: GroupContext<'a>,
    pub extensions: Vec<Extension<'a>>,
    pub confirmation_tag: Mac<'a>,
    pub signer: LeafIndex,
    pub signature: SensitiveBytes<'a>,
}

impl<'a> GroupInfo<'a> {
    pub fn to_tbs(&'a self) -> GroupInfoTBS<'a> {
        GroupInfoTBS {
            group_context: &self.group_context,
            extensions: &self.extensions,
            confirmation_tag: &self.confirmation_tag,
            signer: &self.signer,
        }
    }

    /// Returns the RatchetTree extension if present
    pub fn ratchet_tree(&self) -> Option<&RatchetTree<'a>> {
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

    pub fn into_mls_message(self, protocol_version: ProtocolVersion) -> MlsMessage<'a> {
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
            group_context: GroupContext::with_group_id(vec![].into()),
            extensions: vec![],
            confirmation_tag: vec![].into(),
            signer: 0,
            signature: vec![].into(),
        }
    });
}
