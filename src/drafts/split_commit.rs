use crate::{
    crypto::HpkeCiphertext,
    defs::{ProtocolVersion, WireFormat},
    group::commits::ProposalOrRef,
    messages::{MlsMessage, MlsMessageContent},
    tree::{UpdatePathNode, leaf_node::LeafNode},
};

pub const WIRE_FORMAT_MLS_SPLIT_COMMIT: u16 = 0xFFCC; // TODO: Pending IANA assignment
static_assertions::const_assert!(
    *WireFormat::RESERVED_PRIVATE_USE_RANGE.start() <= WIRE_FORMAT_MLS_SPLIT_COMMIT
        && WIRE_FORMAT_MLS_SPLIT_COMMIT <= *WireFormat::RESERVED_PRIVATE_USE_RANGE.end()
);

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Default,
    tls_codec::TlsSize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSerialize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SplitUpdatePath {
    pub nodes: Vec<UpdatePathNode>,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Default,
    tls_codec::TlsSize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSerialize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SplitCommit {
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub epoch_identifier: Vec<u8>,
    pub proposals: Vec<ProposalOrRef>,
    pub leaf_node: Option<LeafNode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SplitCommitMessage {
    pub split_commit_message: Box<MlsMessage>,
    pub path: Option<SplitUpdatePath>,
}

impl tls_codec::Size for SplitCommitMessage {
    fn tls_serialized_len(&self) -> usize {
        let message_len = matches!(
            self.split_commit_message.content,
            MlsMessageContent::MlsPrivateMessage(_) | MlsMessageContent::MlsPublicMessage(_)
        )
        .then(|| self.split_commit_message.tls_serialized_len())
        .unwrap_or_default();

        message_len + self.path.tls_serialized_len()
    }
}

impl tls_codec::Serialize for SplitCommitMessage {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        if !matches!(
            self.split_commit_message.content,
            MlsMessageContent::MlsPrivateMessage(_) | MlsMessageContent::MlsPublicMessage(_),
        ) {
            return Err(tls_codec::Error::EncodingError("Cannot serialize a SplitCommitMessage containing other than PrivateMessage or PublicMessage to avoid infinite recursion".into()));
        }

        let mut written = self.split_commit_message.tls_serialize(writer)?;
        written += self.path.tls_serialize(writer)?;
        Ok(written)
    }
}

impl tls_codec::Deserialize for SplitCommitMessage {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let version = ProtocolVersion::tls_deserialize(bytes)?;
        let wire_format = WireFormat::tls_deserialize(bytes)?;
        let split_commit_message = match *wire_format {
            WireFormat::MLS_PRIVATE_MESSAGE => MlsMessage { version, content: MlsMessageContent::MlsPrivateMessage(<_>::tls_deserialize(bytes)?) },
            WireFormat::MLS_PUBLIC_MESSAGE => MlsMessage { version, content: MlsMessageContent::MlsPublicMessage(<_>::tls_deserialize(bytes)?) },
            _ => return Err(tls_codec::Error::DecodingError("Cannot deserialize a SplitCommitMessage containing other than PrivateMessage or PublicMessage to avoid infinite recursion".into()))
        };

        Ok(Self {
            split_commit_message: Box::new(split_commit_message),
            path: <_>::tls_deserialize(bytes)?,
        })
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    tls_codec::TlsSize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSerialize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PerMemberCommit {
    pub split_commit_message: MlsMessage,
    pub encrypted_path_secret: Option<HpkeCiphertext>,
}
