use std::borrow::Cow;

use crate::{
    SensitiveBytes,
    defs::{Epoch, LeafIndex, ProtocolVersion, WireFormat, labels::KdfLabelKind},
    group::GroupId,
};

pub const WIRE_FORMAT_MLS_TARGETED_MESSAGE: u16 = 0x0006;

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TargetedMessageSenderAuthData<'a> {
    pub sender_leaf_index: LeafIndex,
    pub signature: SensitiveBytes<'a>,
    pub kem_output: SensitiveBytes<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
pub struct TargetedMessageTBM<'a> {
    pub group_id: &'a GroupId<'a>,
    pub epoch: &'a Epoch,
    pub recipient_leaf_index: &'a LeafIndex,
    pub authenticated_data: &'a [u8],
    pub sender_leaf_index: LeafIndex,
    pub kem_output: SensitiveBytes<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetedMessageTBS<'a> {
    pub group_id: GroupId<'a>,
    pub epoch: &'a Epoch,
    pub recipient_leaf_index: &'a LeafIndex,
    pub authenticated_data: &'a [u8],
    pub sender_leaf_index: &'a LeafIndex,
    pub kem_output: &'a [u8],
    pub ciphertext_hash: &'a [u8],
}

impl thalassa::TlsplSize for TargetedMessageTBS<'_> {
    fn tlspl_serialized_len(&self) -> usize {
        ProtocolVersion::Mls10.tlspl_serialized_len()
            + WireFormat::new_unchecked(WireFormat::MLS_TARGETED_MESSAGE).tlspl_serialized_len()
            + self.group_id.tlspl_serialized_len()
            + self.epoch.tlspl_serialized_len()
            + self.recipient_leaf_index.tlspl_serialized_len()
            + self.authenticated_data.tlspl_serialized_len()
            + self.sender_leaf_index.tlspl_serialized_len()
            + self.kem_output.tlspl_serialized_len()
            + self.ciphertext_hash.tlspl_serialized_len()
    }
}

impl thalassa::TlsplSerialize for TargetedMessageTBS<'_> {
    fn tlspl_serialize_to<W: thalassa::io::Write>(
        &self,
        writer: &mut W,
    ) -> thalassa::error::TlsplWriteResult<usize> {
        let mut written = ProtocolVersion::Mls10.tlspl_serialize_to(writer)?;
        written += WireFormat::new_unchecked(WireFormat::MLS_TARGETED_MESSAGE)
            .tlspl_serialize_to(writer)?;
        written += self.group_id.tlspl_serialize_to(writer)?;
        written += self.epoch.tlspl_serialize_to(writer)?;
        written += self.recipient_leaf_index.tlspl_serialize_to(writer)?;
        written += self.authenticated_data.tlspl_serialize_to(writer)?;
        written += self.sender_leaf_index.tlspl_serialize_to(writer)?;
        written += self.kem_output.tlspl_serialize_to(writer)?;
        written += self.ciphertext_hash.tlspl_serialize_to(writer)?;
        Ok(written)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TargetedMessage<'a> {
    pub group_id: GroupId<'a>,
    pub epoch: Epoch,
    pub recipient_leaf_index: LeafIndex,
    pub authenticated_data: SensitiveBytes<'a>,
    pub encrypted_sender_auth_data: SensitiveBytes<'a>,
    pub ciphertext: SensitiveBytes<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
pub struct TargetedMessagePreSharedKeyId<'a> {
    pub group_id: &'a GroupId<'a>,
    pub epoch: &'a Epoch,
}

impl TargetedMessagePreSharedKeyId<'_> {
    pub const LABEL: KdfLabelKind = KdfLabelKind::TargetedMessagePsk;
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
pub struct TargetedMessageSenderAuthDataAAD<'a> {
    pub group_id: &'a GroupId<'a>,
    pub epoch: &'a Epoch,
    pub recipient_leaf_index: &'a LeafIndex,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TargetedMessageContent<'a> {
    pub application_data: Cow<'a, [u8]>,
    pub padding_len: usize,
}

impl thalassa::TlsplSize for TargetedMessageContent<'_> {
    #[inline]
    fn tlspl_serialized_len(&self) -> usize {
        self.application_data.tlspl_serialized_len() + self.padding_len
    }
}

impl thalassa::TlsplSerialize for TargetedMessageContent<'_> {
    #[inline]
    fn tlspl_serialize_to<W: thalassa::io::Write>(
        &self,
        writer: &mut W,
    ) -> thalassa::error::TlsplWriteResult<usize> {
        let written = self.application_data.tlspl_serialize_to(writer)? + self.padding_len;
        writer.write_all(&vec![0u8; self.padding_len][..])?;
        Ok(written)
    }
}

impl<'a> thalassa::TlsplDeserialize<'a> for TargetedMessageContent<'a> {
    fn tlspl_deserialize_from<R: thalassa::io::Read<'a>>(
        reader: &mut R,
    ) -> thalassa::error::TlsplReadResult<Self>
    where
        Self: Sized + 'a,
    {
        let application_data = <_>::tlspl_deserialize_from(reader)?;
        let padding_len = crate::consume_padding(reader)?;

        Ok(Self {
            application_data,
            padding_len,
        })
    }
}
