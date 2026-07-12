use std::borrow::Cow;

use crate::{
    CRATE_NAME,
    crypto::HpkeCiphertext,
    defs::{ProtocolVersion, WireFormat},
    group::commits::ProposalOrRef,
    messages::{MlsMessage, MlsMessageContent},
    tree::{UpdatePathNode, leaf_node::LeafNode},
};

pub const WIRE_FORMAT_MLS_SPLIT_COMMIT: u16 = 0xFF5C; // TODO: Pending IANA assignment
static_assertions::const_assert!(
    *WireFormat::RESERVED_PRIVATE_USE_RANGE.start() <= WIRE_FORMAT_MLS_SPLIT_COMMIT
        && WIRE_FORMAT_MLS_SPLIT_COMMIT <= *WireFormat::RESERVED_PRIVATE_USE_RANGE.end()
);

pub const CONTENT_TYPE_SPLIT_COMMIT: u8 = 0xF5;

#[derive(Debug, Clone, PartialEq, Eq, Default, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SplitUpdatePath<'a> {
    pub nodes: Vec<UpdatePathNode<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SplitCommit<'a> {
    pub epoch_identifier: Cow<'a, [u8]>,
    pub proposals: Vec<ProposalOrRef<'a>>,
    pub leaf_node: Option<LeafNode<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SplitCommitMessage<'a> {
    pub split_commit_message: Box<MlsMessage<'a>>,
    pub path: Option<SplitUpdatePath<'a>>,
}

impl thalassa::TlsplSize for SplitCommitMessage<'_> {
    fn tlspl_serialized_len(&self) -> usize {
        let message_len = matches!(
            self.split_commit_message.content,
            MlsMessageContent::MlsPrivateMessage(_) | MlsMessageContent::MlsPublicMessage(_)
        )
        .then(|| self.split_commit_message.tlspl_serialized_len())
        .unwrap_or_default();

        message_len + self.path.tlspl_serialized_len()
    }
}

impl thalassa::TlsplSerialize for SplitCommitMessage<'_> {
    fn tlspl_serialize_to<W: thalassa::io::Write>(
        &self,
        writer: &mut W,
    ) -> thalassa::error::TlsplWriteResult<usize> {
        if !matches!(
            self.split_commit_message.content,
            MlsMessageContent::MlsPrivateMessage(_) | MlsMessageContent::MlsPublicMessage(_),
        ) {
            return Err(thalassa::error::TlsplWriteError::custom(
                CRATE_NAME,
                "Cannot serialize a SplitCommitMessage containing other than PrivateMessage or PublicMessage to avoid infinite recursion",
            ));
        }

        let mut written = self.split_commit_message.tlspl_serialize_to(writer)?;
        written += self.path.tlspl_serialize_to(writer)?;
        Ok(written)
    }
}

impl<'a> thalassa::TlsplDeserialize<'a> for SplitCommitMessage<'a> {
    fn tlspl_deserialize_from<R: thalassa::io::Read<'a>>(
        reader: &mut R,
    ) -> thalassa::error::TlsplReadResult<Self>
    where
        Self: Sized + 'a,
    {
        let version = ProtocolVersion::tlspl_deserialize_from(reader)?;
        let wire_format = WireFormat::tlspl_deserialize_from(reader)?;
        let split_commit_message = match *wire_format {
            WireFormat::MLS_PRIVATE_MESSAGE => MlsMessage {
                version,
                content: MlsMessageContent::MlsPrivateMessage(<_>::tlspl_deserialize_from(reader)?),
            },
            WireFormat::MLS_PUBLIC_MESSAGE => MlsMessage {
                version,
                content: MlsMessageContent::MlsPublicMessage(<_>::tlspl_deserialize_from(reader)?),
            },
            _ => {
                return Err(thalassa::error::TlsplReadError::custom(
                    CRATE_NAME,
                    "Cannot deserialize a SplitCommitMessage containing other than PrivateMessage or PublicMessage to avoid infinite recursion",
                ));
            }
        };

        Ok(Self {
            split_commit_message: Box::new(split_commit_message),
            path: <_>::tlspl_deserialize_from(reader)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PerMemberCommit<'a> {
    pub split_commit_message: MlsMessage<'a>,
    pub encrypted_path_secret: Option<HpkeCiphertext<'a>>,
}
