use tls_codec::Deserialize;

use crate::{
    MlsSpecError, MlsSpecResult, SensitiveBytes,
    crypto::Mac,
    defs::{Epoch, ProposalType, ProtocolVersion, WireFormat},
    group::{GroupId, group_info::GroupInfo, welcome::Welcome},
    key_package::KeyPackage,
    key_schedule::{ConfirmedTranscriptHashInput, GroupContext},
    messages::{ContentType, ContentTypeInner, PrivateMessage, PublicMessage, Sender, SenderType},
};

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
pub struct FramedContent {
    pub group_id: GroupId,
    pub epoch: Epoch,
    pub sender: Sender,
    pub authenticated_data: SensitiveBytes,
    pub content: ContentTypeInner,
}

impl FramedContent {
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

#[derive(Debug, Copy, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[repr(u8)]
pub enum FramedContentTBSSenderType<'a> {
    #[tls_codec(discriminant = "SenderType::Member")]
    Member(FramedContentTBSSenderTypeContext<'a>),
    #[tls_codec(discriminant = "SenderType::External")]
    External,
    #[tls_codec(discriminant = "SenderType::NewMemberCommit")]
    NewMemberCommit(FramedContentTBSSenderTypeContext<'a>),
    #[tls_codec(discriminant = "SenderType::NewMemberProposal")]
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

#[derive(Debug, Copy, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FramedContentTBSSenderTypeContext<'a> {
    pub context: &'a GroupContext,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FramedContentTBS<'a> {
    pub version: &'a ProtocolVersion,
    pub wire_format: &'a WireFormat,
    pub content: &'a FramedContent,
    pub sender_type: FramedContentTBSSenderType<'a>,
}

// Impl TLS serialization by hand to make this depend on `self.content.sender.sender_type`'s discriminant
impl tls_codec::Size for FramedContentTBS<'_> {
    fn tls_serialized_len(&self) -> usize {
        let mut len = self.version.tls_serialized_len()
            + self.wire_format.tls_serialized_len()
            + self.content.tls_serialized_len();
        if matches!(
            self.content.sender,
            Sender::Member(_) | Sender::NewMemberCommit
        ) {
            match &self.sender_type {
                FramedContentTBSSenderType::NewMemberCommit(context)
                | FramedContentTBSSenderType::Member(context) => {
                    len += context.tls_serialized_len();
                }
                _ => {}
            }
        }
        len
    }
}

impl tls_codec::Serialize for FramedContentTBS<'_> {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut ret = self.version.tls_serialize(writer)?;

        ret += self.wire_format.tls_serialize(writer)?;
        ret += self.content.tls_serialize(writer)?;
        if matches!(
            self.content.sender,
            Sender::Member(_) | Sender::NewMemberCommit
        ) {
            match &self.sender_type {
                FramedContentTBSSenderType::NewMemberCommit(context)
                | FramedContentTBSSenderType::Member(context) => {
                    ret += context.tls_serialize(writer)?;
                }
                _ => {}
            }
        }

        Ok(ret)
    }
}

impl<'a> tls_codec::Size for &'a FramedContentTBS<'a> {
    fn tls_serialized_len(&self) -> usize {
        (*self).tls_serialized_len()
    }
}

impl<'a> tls_codec::Serialize for &'a FramedContentTBS<'a> {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        (*self).tls_serialize(writer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FramedContentAuthData {
    pub signature: SensitiveBytes,
    pub confirmation_tag: Option<Mac>,
}

impl FramedContentAuthData {
    pub fn without_confirmation_tag(&self) -> Self {
        Self {
            signature: self.signature.clone(),
            confirmation_tag: None,
        }
    }
}

impl tls_codec::Size for FramedContentAuthData {
    fn tls_serialized_len(&self) -> usize {
        self.signature.tls_serialized_len()
            + self
                .confirmation_tag
                .as_ref()
                .map_or(0, SensitiveBytes::tls_serialized_len)
    }
}

impl tls_codec::Size for &FramedContentAuthData {
    fn tls_serialized_len(&self) -> usize {
        (*self).tls_serialized_len()
    }
}

impl tls_codec::Serialize for FramedContentAuthData {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.signature.tls_serialize(writer)?;
        if let Some(confirmation_tag) = &self.confirmation_tag {
            written += confirmation_tag.tls_serialize(writer)?;
        }
        Ok(written)
    }
}

impl tls_codec::Serialize for &FramedContentAuthData {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        (*self).tls_serialize(writer)
    }
}

impl FramedContentAuthData {
    pub fn tls_deserialize_with_content_type<R: std::io::Read>(
        bytes: &mut R,
        content_type: ContentType,
    ) -> Result<Self, tls_codec::Error> {
        let signature = SensitiveBytes::tls_deserialize(bytes)?;
        let confirmation_tag = (content_type == ContentType::Commit)
            .then(|| Mac::tls_deserialize(bytes))
            .transpose()?;

        Ok(Self {
            signature,
            confirmation_tag,
        })
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
#[repr(u16)]
pub enum MlsMessageContent {
    #[tls_codec(discriminant = "WireFormat::MLS_PUBLIC_MESSAGE")]
    MlsPublicMessage(PublicMessage),
    #[tls_codec(discriminant = "WireFormat::MLS_PRIVATE_MESSAGE")]
    MlsPrivateMessage(PrivateMessage),
    #[tls_codec(discriminant = "WireFormat::MLS_WELCOME")]
    Welcome(Welcome),
    #[tls_codec(discriminant = "WireFormat::MLS_GROUP_INFO")]
    GroupInfo(GroupInfo),
    #[tls_codec(discriminant = "WireFormat::MLS_KEY_PACKAGE")]
    KeyPackage(KeyPackage),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[tls_codec(discriminant = "WireFormat::MLS_TARGETED_MESSAGE")]
    MlsTargetedMessage(crate::drafts::mls_extensions::targeted_message::TargetedMessage),
    #[cfg(feature = "draft-mahy-mls-semiprivatemessage")]
    #[tls_codec(discriminant = "WireFormat::MLS_SEMIPRIVATE_MESSAGE")]
    MlsSemiPrivateMessage(crate::drafts::semiprivate_message::messages::SemiPrivateMessage),
    #[cfg(feature = "draft-mularczyk-mls-splitcommit")]
    #[tls_codec(discriminant = "WireFormat::MLS_SPLIT_COMMIT")]
    MlsSplitCommitMessage(crate::drafts::split_commit::SplitCommitMessage),
    #[cfg(feature = "draft-pham-mls-additional-wire-formats")]
    #[tls_codec(discriminant = "WireFormat::MLS_MESSAGE_WITHOUT_AAD")]
    MlsMessageWithoutAad(crate::drafts::additional_wire_formats::MessageWithoutAad),
}

impl MlsMessageContent {
    pub fn content_type(&self) -> Option<ContentType> {
        match self {
            MlsMessageContent::MlsPublicMessage(pub_msg) => Some((&pub_msg.content.content).into()),
            MlsMessageContent::MlsPrivateMessage(priv_msg) => Some(priv_msg.content_type),
            #[cfg(feature = "draft-mularczyk-mls-splitcommit")]
            MlsMessageContent::MlsSplitCommitMessage(message) => {
                message.split_commit_message.content.content_type()
            }
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
}

#[allow(clippy::from_over_into)]
impl Into<WireFormat> for &MlsMessageContent {
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
            #[cfg(feature = "draft-ietf-mls-extensions")]
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
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuthenticatedContent {
    pub wire_format: WireFormat,
    pub content: FramedContent,
    pub auth: FramedContentAuthData,
}

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AuthenticatedContentRef<'a> {
    pub wire_format: &'a WireFormat,
    pub content: &'a FramedContent,
    pub auth: &'a FramedContentAuthData,
}

impl AuthenticatedContent {
    pub fn confirmed_transcript_hash_input(&self) -> ConfirmedTranscriptHashInput {
        ConfirmedTranscriptHashInput {
            wire_format: &self.wire_format,
            content: &self.content,
            signature: &self.auth.signature,
        }
    }

    pub fn as_ref(&self) -> AuthenticatedContentRef {
        AuthenticatedContentRef {
            wire_format: &self.wire_format,
            content: &self.content,
            auth: &self.auth,
        }
    }
}

impl tls_codec::Deserialize for AuthenticatedContent {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let wire_format = WireFormat::tls_deserialize(bytes)?;
        let content = FramedContent::tls_deserialize(bytes)?;
        let auth = FramedContentAuthData::tls_deserialize_with_content_type(
            bytes,
            (&content.content).into(),
        )?;
        Ok(Self {
            wire_format,
            content,
            auth,
        })
    }
}
