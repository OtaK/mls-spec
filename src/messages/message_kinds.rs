use crate::{
    crypto::Mac,
    defs::WireFormat,
    group::GroupId,
    messages::{ContentType, FramedContent, FramedContentAuthData, FramedContentTBS, Sender},
    SensitiveBytes,
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
pub struct PublicMessage {
    pub content: FramedContent,
    pub auth: FramedContentAuthData,
    pub membership_tag: Option<Mac>,
}

impl PublicMessage {
    const AUTH_CONTENT_REF_WF: WireFormat =
        WireFormat::new_unchecked(WireFormat::MLS_PUBLIC_MESSAGE);

    pub fn into_authenticated_content(self) -> AuthenticatedContent {
        AuthenticatedContent {
            wire_format: Self::AUTH_CONTENT_REF_WF,
            content: self.content,
            auth: self.auth,
        }
    }

    pub fn as_authenticated_content(&self) -> AuthenticatedContentRef {
        AuthenticatedContentRef {
            wire_format: &Self::AUTH_CONTENT_REF_WF,
            content: &self.content,
            auth: &self.auth,
        }
    }
}

impl tls_codec::Serialize for PublicMessage {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.content.tls_serialize(writer)?;
        written += self.auth.tls_serialize(writer)?;
        if matches!(self.content.sender, Sender::Member(_)) {
            let Some(mac) = &self.membership_tag else {
                return Err(tls_codec::Error::EncodingError(
                    "PublicMessage.content.sender is Member but `membership_tag` is missing".into(),
                ));
            };
            written += mac.tls_serialize(writer)?;
        }

        Ok(written)
    }
}

impl tls_codec::Deserialize for PublicMessage {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let content = FramedContent::tls_deserialize(bytes)?;
        let auth = FramedContentAuthData::tls_deserialize_with_content_type(
            bytes,
            (&content.content).into(),
        )?;

        let membership_tag = if matches!(content.sender, Sender::Member(_)) {
            Some(Mac::tls_deserialize(bytes)?)
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

impl tls_codec::Size for PublicMessage {
    fn tls_serialized_len(&self) -> usize {
        let membership_tag_len = if matches!(self.content.sender, Sender::Member(_)) {
            self.membership_tag
                .as_ref()
                .map(tls_codec::Size::tls_serialized_len)
                .unwrap_or_default()
        } else {
            debug_assert!(
                self.membership_tag.is_none(),
                "PublicMessage contains a membership_tag while it shouldn't. There's a bug somewhere"
            );

            0
        };

        self.content.tls_serialized_len() + self.auth.tls_serialized_len() + membership_tag_len
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
#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
pub struct AuthenticatedContentTBM<'a> {
    pub content_tbs: FramedContentTBS<'a>,
    pub auth: &'a FramedContentAuthData,
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
pub struct PrivateMessage {
    pub group_id: GroupId,
    pub epoch: u64,
    pub content_type: ContentType,
    pub authenticated_data: SensitiveBytes,
    pub encrypted_sender_data: SensitiveBytes,
    pub ciphertext: SensitiveBytes,
}
