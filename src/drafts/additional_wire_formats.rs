use crate::{
    crypto::Mac,
    defs::{Epoch, WireFormat},
    group::GroupId,
    messages::{ContentType, ContentTypeInner, FramedContentAuthData, Sender},
    SensitiveBytes,
};

pub const WIRE_FORMAT_MLS_MESSAGE_WITHOUT_AAD: u16 = 0xFADF; // TODO: Waiting for IANA registration
static_assertions::const_assert!(
    *WireFormat::RESERVED_PRIVATE_USE_RANGE.start() <= WIRE_FORMAT_MLS_MESSAGE_WITHOUT_AAD
        && WIRE_FORMAT_MLS_MESSAGE_WITHOUT_AAD <= *WireFormat::RESERVED_PRIVATE_USE_RANGE.end()
);

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    tls_codec::TlsSize,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
)]
#[cfg_attr(
    feature = "serde",
    derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr)
)]
#[repr(u8)]
pub enum MessageWithoutAadType {
    PublicMessage = 0,
    PrivateMessage = 1,
}

///
/// <https://www.ietf.org/archive/id/draft-pham-mls-additional-wire-formats-00.html#section-2-2>
///
/// ```notrust,ignore
/// enum {
///     PublicMessageWithoutAAD(0),
///     PrivateMessageWithoutAAD(1),
/// } MessageWithoutAAD;
/// ```
///
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    tls_codec::TlsSize,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
#[allow(clippy::large_enum_variant)]
pub enum MessageWithoutAad {
    #[tls_codec(discriminant = "MessageWithoutAadType::PublicMessage")]
    PublicMessageWithoutAad(PublicMessageWithoutAad),
    #[tls_codec(discriminant = "MessageWithoutAadType::PrivateMessage")]
    PrivateMessageWithoutAad(PrivateMessageWithoutAad),
}

///
/// ```notrust,ignore
/// struct {
///     opaque group_id<V>;
///     uint64 epoch;
///     Sender sender;
///
///     ContentType content_type;
///         select (FramedContent.content_type) {
///             case application:
///                 opaque application_data<V>;
///             case proposal:
///                 Proposal proposal;
///             case commit:
///                 Commit commit;
///         };
/// } FramedContentWithoutAAD;
/// ```
///
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    tls_codec::TlsSize,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FramedContentWithoutAad {
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub group_id: GroupId,
    pub epoch: Epoch,
    pub sender: Sender,
    pub content: ContentTypeInner,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PublicMessageWithoutAad {
    pub content: FramedContentWithoutAad,
    pub auth: FramedContentAuthData,
    pub membership_tag: Option<Mac>,
}

impl tls_codec::Serialize for PublicMessageWithoutAad {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.content.tls_serialize(writer)?;
        written += self.auth.tls_serialize(writer)?;
        if matches!(self.content.sender, Sender::Member(_)) {
            let Some(mac) = &self.membership_tag else {
                return Err(tls_codec::Error::EncodingError(
                    "PublicMessageWithoutAad.content.sender is Member but `membership_tag` is missing".into(),
                ));
            };
            written += mac.tls_serialize(writer)?;
        }

        Ok(written)
    }
}

impl tls_codec::Deserialize for PublicMessageWithoutAad {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let content = FramedContentWithoutAad::tls_deserialize(bytes)?;
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

impl tls_codec::Size for PublicMessageWithoutAad {
    fn tls_serialized_len(&self) -> usize {
        let membership_tag_len = if matches!(self.content.sender, Sender::Member(_)) {
            self.membership_tag
                .as_ref()
                .map(tls_codec::Size::tls_serialized_len)
                .unwrap_or_default()
        } else {
            debug_assert!(
                self.membership_tag.is_none(),
                "PublicMessageWithoutAad contains a membership_tag while it shouldn't. There's a bug somewhere"
            );

            0
        };

        self.content.tls_serialized_len() + self.auth.tls_serialized_len() + membership_tag_len
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    tls_codec::TlsSize,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PrivateMessageWithoutAad {
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub group_id: GroupId,
    pub epoch: Epoch,
    pub content_type: ContentType,
    pub encrypted_sender_data: SensitiveBytes,
    pub ciphertext: SensitiveBytes,
}
