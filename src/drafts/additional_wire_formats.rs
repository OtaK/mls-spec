use crate::{
    CRATE_NAME, SensitiveBytes,
    crypto::Mac,
    defs::{Epoch, WireFormat},
    group::GroupId,
    messages::{ContentType, ContentTypeInner, FramedContentAuthData, Sender},
};

pub const WIRE_FORMAT_MLS_MESSAGE_WITHOUT_AAD: u16 = 0xFADF; // TODO: Waiting for IANA registration
static_assertions::const_assert!(
    *WireFormat::RESERVED_PRIVATE_USE_RANGE.start() <= WIRE_FORMAT_MLS_MESSAGE_WITHOUT_AAD
        && WIRE_FORMAT_MLS_MESSAGE_WITHOUT_AAD <= *WireFormat::RESERVED_PRIVATE_USE_RANGE.end()
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(
    feature = "serde",
    derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr)
)]
#[repr(u8)]
pub enum MessageWithoutAadType {
    PublicMessage = 0x00,
    PrivateMessage = 0x01,
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
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
#[allow(clippy::large_enum_variant)]
pub enum MessageWithoutAad<'a> {
    #[tlspl(discriminant = "MessageWithoutAadType::PublicMessage")]
    PublicMessageWithoutAad(PublicMessageWithoutAad<'a>),
    #[tlspl(discriminant = "MessageWithoutAadType::PrivateMessage")]
    PrivateMessageWithoutAad(PrivateMessageWithoutAad<'a>),
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
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FramedContentWithoutAad<'a> {
    pub group_id: GroupId<'a>,
    pub epoch: Epoch,
    pub sender: Sender,
    pub content: ContentTypeInner<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PublicMessageWithoutAad<'a> {
    pub content: FramedContentWithoutAad<'a>,
    pub auth: FramedContentAuthData<'a>,
    pub membership_tag: Option<Mac<'a>>,
}

impl thalassa::TlsplSize for PublicMessageWithoutAad<'_> {
    #[inline]
    fn tlspl_serialized_len(&self) -> usize {
        let membership_tag_len = if matches!(self.content.sender, Sender::Member(_)) {
            self.membership_tag
                .as_ref()
                .map(thalassa::TlsplSize::tlspl_serialized_len)
                .unwrap_or_default()
        } else {
            debug_assert!(
                self.membership_tag.is_none(),
                "PublicMessageWithoutAad contains a membership_tag while it shouldn't. There's a bug somewhere"
            );

            0
        };

        self.content.tlspl_serialized_len() + self.auth.tlspl_serialized_len() + membership_tag_len
    }
}

impl thalassa::TlsplSerialize for PublicMessageWithoutAad<'_> {
    #[inline]
    fn tlspl_serialize_to<W: thalassa::io::Write>(
        &self,
        writer: &mut W,
    ) -> thalassa::error::TlsplWriteResult<usize> {
        let mut written = self.content.tlspl_serialize_to(writer)?;
        written += self.auth.tlspl_serialize_to(writer)?;
        if matches!(self.content.sender, Sender::Member(_)) {
            let Some(mac) = &self.membership_tag else {
                return Err(thalassa::error::TlsplWriteError::custom(
                    CRATE_NAME,
                    "PublicMessageWithoutAad.content.sender is Member but `membership_tag` is missing",
                ));
            };
            written += mac.tlspl_serialize_to(writer)?;
        }

        Ok(written)
    }
}

impl<'a> thalassa::TlsplDeserialize<'a> for PublicMessageWithoutAad<'a> {
    #[inline]
    fn tlspl_deserialize_from<R: thalassa::io::Read<'a>>(
        reader: &mut R,
    ) -> thalassa::error::TlsplReadResult<Self>
    where
        Self: Sized + 'a,
    {
        let content = FramedContentWithoutAad::tlspl_deserialize_from(reader)?;
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

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PrivateMessageWithoutAad<'a> {
    pub group_id: GroupId<'a>,
    pub epoch: Epoch,
    pub content_type: ContentType,
    pub encrypted_sender_data: SensitiveBytes<'a>,
    pub ciphertext: SensitiveBytes<'a>,
}
