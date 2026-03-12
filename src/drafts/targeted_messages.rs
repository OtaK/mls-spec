use crate::{
    SensitiveBytes,
    defs::{Epoch, LeafIndex, ProtocolVersion, WireFormat, labels::KdfLabelKind},
    group::{GroupId, GroupIdRef},
};

pub const WIRE_FORMAT_MLS_TARGETED_MESSAGE: u16 = 0x0006;

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
pub struct TargetedMessageSenderAuthData {
    pub sender_leaf_index: LeafIndex,
    pub signature: SensitiveBytes,
    pub kem_output: SensitiveBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
pub struct TargetedMessageTBM<'a> {
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub group_id: GroupIdRef<'a>,
    pub epoch: &'a Epoch,
    pub recipient_leaf_index: &'a LeafIndex,
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub authenticated_data: &'a [u8],
    pub sender_auth_data: &'a TargetedMessageSenderAuthData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetedMessageTBS<'a> {
    pub group_id: GroupIdRef<'a>,
    pub epoch: &'a Epoch,
    pub recipient_leaf_index: &'a LeafIndex,
    pub authenticated_data: &'a [u8],
    pub sender_leaf_index: &'a LeafIndex,
    pub kem_output: &'a [u8],
    pub ciphertext: &'a [u8],
}

impl<'a> tls_codec::Size for TargetedMessageTBS<'a> {
    fn tls_serialized_len(&self) -> usize {
        ProtocolVersion::Mls10.tls_serialized_len()
            + WireFormat::new_unchecked(WireFormat::MLS_TARGETED_MESSAGE).tls_serialized_len()
            + crate::tlspl::bytes::tls_serialized_len(self.group_id)
            + self.epoch.tls_serialized_len()
            + self.recipient_leaf_index.tls_serialized_len()
            + crate::tlspl::bytes::tls_serialized_len(self.authenticated_data)
            + self.sender_leaf_index.tls_serialized_len()
            + crate::tlspl::bytes::tls_serialized_len(self.kem_output)
            + crate::tlspl::bytes::tls_serialized_len(self.ciphertext)
    }
}

impl<'a> tls_codec::Serialize for TargetedMessageTBS<'a> {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = ProtocolVersion::Mls10.tls_serialize(writer)?;
        written +=
            WireFormat::new_unchecked(WireFormat::MLS_TARGETED_MESSAGE).tls_serialize(writer)?;
        written += crate::tlspl::bytes::tls_serialize(self.group_id, writer)?;
        written += self.epoch.tls_serialize(writer)?;
        written += self.recipient_leaf_index.tls_serialize(writer)?;
        written += crate::tlspl::bytes::tls_serialize(self.authenticated_data, writer)?;
        written += self.sender_leaf_index.tls_serialize(writer)?;
        written += crate::tlspl::bytes::tls_serialize(self.kem_output, writer)?;
        written += crate::tlspl::bytes::tls_serialize(self.ciphertext, writer)?;

        Ok(written)
    }
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
pub struct TargetedMessage {
    pub group_id: GroupId,
    pub epoch: Epoch,
    pub recipient_leaf_index: LeafIndex,
    pub authenticated_data: SensitiveBytes,
    pub encrypted_sender_auth_data: SensitiveBytes,
    pub ciphertext: SensitiveBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
pub struct TargetedMessagePreSharedKeyId<'a> {
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub group_id: GroupIdRef<'a>,
    pub epoch: &'a Epoch,
}

impl TargetedMessagePreSharedKeyId<'_> {
    pub const LABEL: KdfLabelKind = KdfLabelKind::TargetedMessagePsk;
}

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
pub struct TargetedMessageSenderAuthDataAAD<'a> {
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub group_id: GroupIdRef<'a>,
    pub epoch: &'a Epoch,
    pub recipient_leaf_index: &'a LeafIndex,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TargetedMessageContent {
    pub application_data: Vec<u8>,
    pub padding_len: usize,
}

impl tls_codec::Size for TargetedMessageContent {
    fn tls_serialized_len(&self) -> usize {
        crate::tlspl::tls_serialized_len_as_vlvec(self.application_data.len()) + self.padding_len
    }
}

impl tls_codec::Serialize for TargetedMessageContent {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = crate::tlspl::bytes::tls_serialize(&self.application_data, writer)?;
        writer.write_all(&vec![0u8; self.padding_len][..])?;
        written += self.padding_len;
        Ok(written)
    }
}

impl tls_codec::Deserialize for TargetedMessageContent {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let application_data = crate::tlspl::bytes::tls_deserialize(bytes)?;
        let padding_len = crate::messages::PrivateMessageContent::consume_padding(bytes)?;
        Ok(Self {
            application_data,
            padding_len,
        })
    }
}
