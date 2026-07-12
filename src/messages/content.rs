use thalassa::{TlsplDeserialize, error::TlsplReadError, io::Read};

use crate::{
    MlsSpecError, MlsSpecResult, SensitiveBytes,
    crypto::Mac,
    defs::{Epoch, ProposalType, ProtocolVersion, WireFormat},
    group::{GroupId, group_info::GroupInfo, welcome::Welcome},
    key_package::KeyPackage,
    key_schedule::{ConfirmedTranscriptHashInput, GroupContext},
    messages::{ContentType, ContentTypeInner, PrivateMessage, PublicMessage, Sender, SenderType},
};

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FramedContent<'a> {
    pub group_id: GroupId<'a>,
    pub epoch: Epoch,
    pub sender: Sender,
    pub authenticated_data: SensitiveBytes<'a>,
    pub content: ContentTypeInner<'a>,
}

impl FramedContent<'_> {
    pub fn to_tbs<'a>(
        &'a self,
        wire_format: &'a WireFormat,
        ctx: &'a GroupContext,
    ) -> MlsSpecResult<FramedContentTBS<'a>> {
        let sender_type_raw: SenderType = (&self.sender).into();
        let sender_type =
            FramedContentTBSSenderType::from_sender_type_with_ctx(sender_type_raw, Some(ctx))?;

        Ok(FramedContentTBS {
            version: &ctx.version,
            wire_format,
            content: self,
            sender_type,
        })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[repr(u8)]
pub enum FramedContentTBSSenderType<'a> {
    #[tlspl(discriminant = "SenderType::Member")]
    Member(FramedContentTBSSenderTypeContext<'a>),
    #[tlspl(discriminant = "SenderType::External")]
    External,
    #[tlspl(discriminant = "SenderType::NewMemberCommit")]
    NewMemberCommit(FramedContentTBSSenderTypeContext<'a>),
    #[tlspl(discriminant = "SenderType::NewMemberProposal")]
    NewMemberProposal,
}

impl<'a> FramedContentTBSSenderType<'a> {
    pub fn from_sender_type_with_ctx(
        sender_type: SenderType,
        mut ctx: Option<&'a GroupContext>,
    ) -> MlsSpecResult<Self> {
        Ok(match sender_type {
            SenderType::NewMemberCommit => {
                let Some(context) = ctx.take() else {
                    return Err(MlsSpecError::FramedContentTBSMissingGroupContext);
                };
                Self::NewMemberCommit(FramedContentTBSSenderTypeContext { context })
            }
            SenderType::Member => {
                let Some(context) = ctx.take() else {
                    return Err(MlsSpecError::FramedContentTBSMissingGroupContext);
                };
                Self::Member(FramedContentTBSSenderTypeContext { context })
            }
            SenderType::External => Self::External,
            SenderType::NewMemberProposal => Self::NewMemberProposal,
            _ => return Err(MlsSpecError::ReservedValueUsage),
        })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FramedContentTBSSenderTypeContext<'a> {
    pub context: &'a GroupContext<'a>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FramedContentTBS<'a> {
    pub version: &'a ProtocolVersion,
    pub wire_format: &'a WireFormat,
    pub content: &'a FramedContent<'a>,
    pub sender_type: FramedContentTBSSenderType<'a>,
}

// Impl TLS serialization by hand to make this depend on `self.content.sender.sender_type`'s discriminant
impl thalassa::TlsplSize for FramedContentTBS<'_> {
    fn tlspl_serialized_len(&self) -> usize {
        let mut len = self.version.tlspl_serialized_len()
            + self.wire_format.tlspl_serialized_len()
            + self.content.tlspl_serialized_len();
        if matches!(
            self.content.sender,
            Sender::Member(_) | Sender::NewMemberCommit
        ) {
            match &self.sender_type {
                FramedContentTBSSenderType::NewMemberCommit(context)
                | FramedContentTBSSenderType::Member(context) => {
                    len += context.tlspl_serialized_len();
                }
                _ => {}
            }
        }
        len
    }
}

impl thalassa::TlsplSerialize for FramedContentTBS<'_> {
    fn tlspl_serialize_to<W: thalassa::io::Write>(
        &self,
        writer: &mut W,
    ) -> thalassa::error::TlsplWriteResult<usize> {
        let mut ret = self.version.tlspl_serialize_to(writer)?;

        ret += self.wire_format.tlspl_serialize_to(writer)?;
        ret += self.content.tlspl_serialize_to(writer)?;
        if matches!(
            self.content.sender,
            Sender::Member(_) | Sender::NewMemberCommit
        ) {
            match &self.sender_type {
                FramedContentTBSSenderType::NewMemberCommit(context)
                | FramedContentTBSSenderType::Member(context) => {
                    ret += context.tlspl_serialize_to(writer)?;
                }
                _ => {}
            }
        }

        Ok(ret)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FramedContentAuthData<'a> {
    pub signature: SensitiveBytes<'a>,
    pub confirmation_tag: Option<Mac<'a>>,
}

impl FramedContentAuthData<'_> {
    pub fn without_confirmation_tag(&self) -> Self {
        Self {
            signature: self.signature.clone(),
            confirmation_tag: None,
        }
    }
}

impl thalassa::TlsplSize for FramedContentAuthData<'_> {
    fn tlspl_serialized_len(&self) -> usize {
        self.signature.tlspl_serialized_len()
            + self
                .confirmation_tag
                .as_ref()
                .map_or(0, SensitiveBytes::tlspl_serialized_len)
    }
}

impl thalassa::TlsplSerialize for FramedContentAuthData<'_> {
    fn tlspl_serialize_to<W: thalassa::io::Write>(
        &self,
        writer: &mut W,
    ) -> thalassa::error::TlsplWriteResult<usize> {
        let mut written = self.signature.tlspl_serialize_to(writer)?;
        if let Some(confirmation_tag) = &self.confirmation_tag {
            written += confirmation_tag.tlspl_serialize_to(writer)?;
        }
        Ok(written)
    }
}

impl<'a> FramedContentAuthData<'a> {
    pub fn tlspl_deserialize_from_with_content_type<R: Read<'a>>(
        reader: &mut R,
        content_type: ContentType,
    ) -> Result<Self, TlsplReadError> {
        let signature = SensitiveBytes::tlspl_deserialize_from(reader)?;
        let confirmation_tag = (content_type == ContentType::Commit)
            .then(|| Mac::tlspl_deserialize_from(reader))
            .transpose()?;

        Ok(Self {
            signature,
            confirmation_tag,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u16)]
pub enum MlsMessageContent<'a> {
    #[tlspl(discriminant = "WireFormat::MLS_PUBLIC_MESSAGE")]
    MlsPublicMessage(PublicMessage<'a>),
    #[tlspl(discriminant = "WireFormat::MLS_PRIVATE_MESSAGE")]
    MlsPrivateMessage(PrivateMessage<'a>),
    #[tlspl(discriminant = "WireFormat::MLS_WELCOME")]
    Welcome(Welcome<'a>),
    #[tlspl(discriminant = "WireFormat::MLS_GROUP_INFO")]
    GroupInfo(GroupInfo<'a>),
    #[tlspl(discriminant = "WireFormat::MLS_KEY_PACKAGE")]
    KeyPackage(KeyPackage<'a>),
    #[cfg(feature = "draft-ietf-mls-targeted-messages")]
    #[tlspl(discriminant = "WireFormat::MLS_TARGETED_MESSAGE")]
    MlsTargetedMessage(crate::drafts::targeted_messages::TargetedMessage<'a>),
    #[cfg(feature = "draft-mahy-mls-semiprivatemessage")]
    #[tlspl(discriminant = "WireFormat::MLS_SEMIPRIVATE_MESSAGE")]
    MlsSemiPrivateMessage(crate::drafts::semiprivate_message::messages::SemiPrivateMessage<'a>),
    #[cfg(feature = "draft-mularczyk-mls-splitcommit")]
    #[tlspl(discriminant = "WireFormat::MLS_SPLIT_COMMIT")]
    MlsSplitCommitMessage(crate::drafts::split_commit::SplitCommitMessage<'a>),
    #[cfg(feature = "draft-pham-mls-additional-wire-formats")]
    #[tlspl(discriminant = "WireFormat::MLS_MESSAGE_WITHOUT_AAD")]
    MlsMessageWithoutAad(crate::drafts::additional_wire_formats::MessageWithoutAad<'a>),
    #[cfg(feature = "draft-mahy-mls-private-external")]
    #[tlspl(discriminant = "WireFormat::MLS_PRIVATE_EXTERNAL_MESSAGE")]
    MlsPrivateExternalMessage(crate::drafts::private_external::PrivateExternalMessage<'a>),
    #[cfg(feature = "draft-kohbrok-mls-leaf-operation-intents")]
    #[tlspl(discriminant = "WireFormat::MLS_LEAF_OPERATION_INTENT")]
    MlsLeafOperationIntent(crate::drafts::leaf_operation_intents::LeafOperationIntent<'a>),
}

impl MlsMessageContent<'_> {
    pub fn content_type(&self) -> Option<ContentType> {
        match self {
            MlsMessageContent::MlsPublicMessage(pub_msg) => Some((&pub_msg.content.content).into()),
            MlsMessageContent::MlsPrivateMessage(priv_msg) => Some(priv_msg.content_type),
            #[cfg(feature = "draft-mahy-mls-semiprivatemessage")]
            MlsMessageContent::MlsSemiPrivateMessage(semi_priv_msg) => {
                Some(semi_priv_msg.content_type)
            }
            #[cfg(feature = "draft-mularczyk-mls-splitcommit")]
            MlsMessageContent::MlsSplitCommitMessage(message) => {
                message.split_commit_message.content.content_type()
            }
            #[cfg(feature = "draft-mahy-mls-private-external")]
            MlsMessageContent::MlsPrivateExternalMessage(message) => Some(message.content_type),
            _ => None,
        }
    }

    pub fn proposal_type(&self) -> Option<ProposalType> {
        match self {
            MlsMessageContent::MlsPublicMessage(pub_msg) => {
                if let ContentTypeInner::Proposal { proposal } = &pub_msg.content.content {
                    Some(proposal.into())
                } else {
                    None
                }
            }
            #[cfg(feature = "draft-mularczyk-mls-splitcommit")]
            MlsMessageContent::MlsSplitCommitMessage(message) => {
                message.split_commit_message.content.proposal_type()
            }
            _ => None,
        }
    }

    pub fn authenticated_data(&self) -> Option<&[u8]> {
        match self {
            MlsMessageContent::MlsPublicMessage(public_message) => {
                Some(&public_message.content.authenticated_data)
            }
            MlsMessageContent::MlsPrivateMessage(private_message) => {
                Some(&private_message.authenticated_data)
            }
            #[cfg(feature = "draft-mahy-mls-semiprivatemessage")]
            MlsMessageContent::MlsSemiPrivateMessage(semi_priv_msg) => {
                Some(&semi_priv_msg.authenticated_data)
            }
            #[cfg(feature = "draft-mularczyk-mls-splitcommit")]
            MlsMessageContent::MlsSplitCommitMessage(message) => {
                message.split_commit_message.content.authenticated_data()
            }
            #[cfg(feature = "draft-mahy-mls-private-external")]
            MlsMessageContent::MlsPrivateExternalMessage(message) => {
                Some(&message.authenticated_data)
            }
            _ => None,
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<WireFormat> for &MlsMessageContent<'_> {
    fn into(self) -> WireFormat {
        match self {
            MlsMessageContent::MlsPublicMessage(_) => {
                WireFormat::new_unchecked(WireFormat::MLS_PUBLIC_MESSAGE)
            }
            MlsMessageContent::MlsPrivateMessage(_) => {
                WireFormat::new_unchecked(WireFormat::MLS_PRIVATE_MESSAGE)
            }
            MlsMessageContent::Welcome(_) => WireFormat::new_unchecked(WireFormat::MLS_WELCOME),
            MlsMessageContent::GroupInfo(_) => {
                WireFormat::new_unchecked(WireFormat::MLS_GROUP_INFO)
            }
            MlsMessageContent::KeyPackage(_) => {
                WireFormat::new_unchecked(WireFormat::MLS_KEY_PACKAGE)
            }
            #[cfg(feature = "draft-ietf-mls-targeted-messages")]
            MlsMessageContent::MlsTargetedMessage(_) => {
                WireFormat::new_unchecked(WireFormat::MLS_TARGETED_MESSAGE)
            }
            #[cfg(feature = "draft-mahy-mls-semiprivatemessage")]
            MlsMessageContent::MlsSemiPrivateMessage(_) => {
                WireFormat::new_unchecked(WireFormat::MLS_SEMIPRIVATE_MESSAGE)
            }
            #[cfg(feature = "draft-mularczyk-mls-splitcommit")]
            MlsMessageContent::MlsSplitCommitMessage(_) => {
                WireFormat::new_unchecked(WireFormat::MLS_SPLIT_COMMIT)
            }
            #[cfg(feature = "draft-pham-mls-additional-wire-formats")]
            MlsMessageContent::MlsMessageWithoutAad(_) => {
                WireFormat::new_unchecked(WireFormat::MLS_MESSAGE_WITHOUT_AAD)
            }
            #[cfg(feature = "draft-mahy-mls-private-external")]
            MlsMessageContent::MlsPrivateExternalMessage(_) => {
                WireFormat::new_unchecked(WireFormat::MLS_PRIVATE_EXTERNAL_MESSAGE)
            }
            #[cfg(feature = "draft-kohbrok-mls-leaf-operation-intents")]
            MlsMessageContent::MlsLeafOperationIntent(_) => {
                WireFormat::new_unchecked(WireFormat::MLS_LEAF_OPERATION_INTENT)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuthenticatedContent<'a> {
    pub wire_format: WireFormat,
    pub content: FramedContent<'a>,
    pub auth: FramedContentAuthData<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AuthenticatedContentRef<'a> {
    pub wire_format: &'a WireFormat,
    pub content: &'a FramedContent<'a>,
    pub auth: &'a FramedContentAuthData<'a>,
}

impl AuthenticatedContent<'_> {
    pub fn confirmed_transcript_hash_input(&self) -> ConfirmedTranscriptHashInput<'_> {
        ConfirmedTranscriptHashInput {
            wire_format: &self.wire_format,
            content: &self.content,
            signature: &self.auth.signature,
        }
    }

    pub fn as_ref(&self) -> AuthenticatedContentRef<'_> {
        AuthenticatedContentRef {
            wire_format: &self.wire_format,
            content: &self.content,
            auth: &self.auth,
        }
    }
}

impl<'a> thalassa::TlsplDeserialize<'a> for AuthenticatedContent<'a> {
    fn tlspl_deserialize_from<R: Read<'a>>(reader: &mut R) -> thalassa::error::TlsplReadResult<Self>
    where
        Self: Sized + 'a,
    {
        let wire_format = WireFormat::tlspl_deserialize_from(reader)?;
        let content = FramedContent::tlspl_deserialize_from(reader)?;
        let auth = FramedContentAuthData::tlspl_deserialize_from_with_content_type(
            reader,
            (&content.content).into(),
        )?;
        Ok(Self {
            wire_format,
            content,
            auth,
        })
    }
}
