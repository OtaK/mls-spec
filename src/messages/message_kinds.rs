use crate::{
    CRATE_NAME, SensitiveBytes,
    crypto::Mac,
    defs::WireFormat,
    group::GroupId,
    messages::{ContentType, FramedContent, FramedContentAuthData, FramedContentTBS, Sender},
};

use super::{AuthenticatedContent, AuthenticatedContentRef};

/// MLS Public Message (authenticated only)
///
/// <https://www.rfc-editor.org/rfc/rfc9420.html#name-encoding-and-decoding-a-pub>
///
/// ## TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     FramedContent content;
///     FramedContentAuthData auth;
///     select (PublicMessage.content.sender.sender_type) {
///         case member:
///             MAC membership_tag;
///         case external:
///         case new_member_commit:
///         case new_member_proposal:
///             struct{};
///     };
/// } PublicMessage;
/// ```
///
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PublicMessage<'a> {
    pub content: FramedContent<'a>,
    pub auth: FramedContentAuthData<'a>,
    pub membership_tag: Option<Mac<'a>>,
}

impl<'a> PublicMessage<'a> {
    const AUTH_CONTENT_REF_WF: WireFormat =
        WireFormat::new_unchecked(WireFormat::MLS_PUBLIC_MESSAGE);

    pub fn into_authenticated_content(self) -> AuthenticatedContent<'a> {
        AuthenticatedContent {
            wire_format: Self::AUTH_CONTENT_REF_WF,
            content: self.content,
            auth: self.auth,
        }
    }

    pub fn as_authenticated_content(&'a self) -> AuthenticatedContentRef<'a> {
        AuthenticatedContentRef {
            wire_format: &Self::AUTH_CONTENT_REF_WF,
            content: &self.content,
            auth: &self.auth,
        }
    }
}

impl thalassa::TlsplSize for PublicMessage<'_> {
    fn tlspl_serialized_len(&self) -> usize {
        let membership_tag_len = if matches!(self.content.sender, Sender::Member(_)) {
            self.membership_tag
                .as_ref()
                .map(thalassa::TlsplSize::tlspl_serialized_len)
                .unwrap_or_default()
        } else {
            debug_assert!(
                self.membership_tag.is_none(),
                "PublicMessage contains a membership_tag while it shouldn't. There's a bug somewhere"
            );

            0
        };

        self.content.tlspl_serialized_len() + self.auth.tlspl_serialized_len() + membership_tag_len
    }
}

impl thalassa::TlsplSerialize for PublicMessage<'_> {
    fn tlspl_serialize_to<W: thalassa::io::Write>(
        &self,
        writer: &mut W,
    ) -> thalassa::error::TlsplWriteResult<usize> {
        let mut written =
            self.content.tlspl_serialize_to(writer)? + self.auth.tlspl_serialize_to(writer)?;

        if matches!(self.content.sender, Sender::Member(_)) {
            let Some(mac) = &self.membership_tag else {
                return Err(thalassa::error::TlsplWriteError::custom(
                    CRATE_NAME,
                    "PublicMessage.content.sender is Member but `membership_tag` is missing",
                ));
            };
            written += mac.tlspl_serialize_to(writer)?;
        }

        Ok(written)
    }
}

impl<'a> thalassa::TlsplDeserialize<'a> for PublicMessage<'a> {
    fn tlspl_deserialize_from<R: thalassa::io::Read<'a>>(
        reader: &mut R,
    ) -> thalassa::error::TlsplReadResult<Self>
    where
        Self: Sized + 'a,
    {
        let content = FramedContent::tlspl_deserialize_from(reader)?;
        let auth = FramedContentAuthData::tlspl_deserialize_from_with_content_type(
            reader,
            (&content.content).into(),
        )?;

        let membership_tag = if matches!(content.sender, Sender::Member(_)) {
            Some(Mac::tlspl_deserialize_from(reader)?)
        } else {
            None
        };

        Ok(Self {
            content,
            auth,
            membership_tag,
        })
    }
}

/// Struct to be HMAC'd to calculate a [PublicMessage]'s `membership_tag`
///
/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-6.2-4>
///
/// ## TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///   FramedContentTBS content_tbs;
///   FramedContentAuthData auth;
/// } AuthenticatedContentTBM;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
pub struct AuthenticatedContentTBM<'a> {
    pub content_tbs: FramedContentTBS<'a>,
    pub auth: &'a FramedContentAuthData<'a>,
}

/// MLS Private Message (authenticated & encrypted)
///
/// <https://www.rfc-editor.org/rfc/rfc9420.html#name-encoding-and-decoding-a-pri>
///
/// ## TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     opaque group_id<V>;
///     uint64 epoch;
///     ContentType content_type;
///     opaque authenticated_data<V>;
///     opaque encrypted_sender_data<V>;
///     opaque ciphertext<V>;
/// } PrivateMessage;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PrivateMessage<'a> {
    pub group_id: GroupId<'a>,
    pub epoch: u64,
    pub content_type: ContentType,
    pub authenticated_data: SensitiveBytes<'a>,
    pub encrypted_sender_data: SensitiveBytes<'a>,
    pub ciphertext: SensitiveBytes<'a>,
}
