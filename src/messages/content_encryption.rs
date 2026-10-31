use crate::{
    defs::{Epoch, Generation, LeafIndex},
    group::GroupIdRef,
    messages::{ContentType, ContentTypeInner, FramedContentAuthData},
};

pub type ReuseGuard = [u8; 4];

#[derive(Debug, Clone)]
pub struct PrivateMessageContent {
    pub inner: ContentTypeInner,
    pub auth: FramedContentAuthData,
    pub padding_len: usize,
}

impl PartialEq for PrivateMessageContent {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.auth == other.auth
    }
}
impl Eq for PrivateMessageContent {}

impl tls_codec::Size for PrivateMessageContent {
    fn tls_serialized_len(&self) -> usize {
        let inner_len = match &self.inner {
            ContentTypeInner::Application { application_data } => {
                crate::tlspl::bytes::tls_serialized_len(application_data)
            }
            ContentTypeInner::Proposal { proposal } => proposal.tls_serialized_len(),
            ContentTypeInner::Commit { commit } => commit.tls_serialized_len(),
            #[cfg(feature = "draft-mularczyk-mls-splitcommit")]
            ContentTypeInner::SplitCommit { split_commit } => split_commit.tls_serialized_len(),
            #[cfg(feature = "draft-mahy-mls-new-content-types")]
            ContentTypeInner::Status { application_data }
            | ContentTypeInner::Ephemeral { application_data } => {
                crate::tlspl::bytes::tls_serialized_len(application_data)
            }
        };
        inner_len + self.auth.tls_serialized_len() + self.padding_len
    }
}

impl tls_codec::Serialize for PrivateMessageContent {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = match &self.inner {
            ContentTypeInner::Application { application_data } => {
                crate::tlspl::bytes::tls_serialize(application_data, writer)?
            }
            ContentTypeInner::Proposal { proposal } => proposal.tls_serialize(writer)?,
            ContentTypeInner::Commit { commit } => commit.tls_serialize(writer)?,
            #[cfg(feature = "draft-mularczyk-mls-splitcommit")]
            ContentTypeInner::SplitCommit { split_commit } => split_commit.tls_serialize(writer)?,
            #[cfg(feature = "draft-mahy-mls-new-content-types")]
            ContentTypeInner::Status { application_data }
            | ContentTypeInner::Ephemeral { application_data } => {
                crate::tlspl::bytes::tls_serialize(application_data, writer)?
            }
        };
        written += self.auth.tls_serialize(writer)? + self.padding_len;
        writer.write_all(&vec![0u8; self.padding_len][..])?;
        Ok(written)
    }
}

impl PrivateMessageContent {
    pub(crate) fn consume_padding<R: std::io::Read>(
        bytes: &mut R,
    ) -> Result<usize, tls_codec::Error> {
        let mut padding = Vec::new();
        bytes.read_to_end(&mut padding).map_err(|_| {
            tls_codec::Error::DecodingError("Cannot decode padding past MessageContent".into())
        })?;

        let padding_len = padding.len();
        if padding.into_iter().any(|b| b != 0x00) {
            return Err(tls_codec::Error::DecodingError(
                "MessageContent padding isn't all zeroes!".into(),
            ));
        }

        Ok(padding_len)
    }

    pub fn tls_deserialize_with_content_type<R: std::io::Read>(
        bytes: &mut R,
        content_type: ContentType,
    ) -> Result<Self, tls_codec::Error> {
        use tls_codec::Deserialize as _;

        let inner = match content_type {
            ContentType::Reserved => {
                return Err(tls_codec::Error::DecodingError(
                    "Tried to deserialize a ContentType::RESERVED, which is invalid".into(),
                ));
            }
            ContentType::Application => ContentTypeInner::Application {
                application_data: crate::tlspl::bytes::tls_deserialize(bytes)?,
            },
            ContentType::Proposal => ContentTypeInner::Proposal {
                proposal: <_>::tls_deserialize(bytes)?,
            },
            ContentType::Commit => ContentTypeInner::Commit {
                commit: <_>::tls_deserialize(bytes)?,
            },
            #[cfg(feature = "draft-mahy-mls-new-content-types")]
            ContentType::Status => ContentTypeInner::Status {
                application_data: crate::tlspl::bytes::tls_deserialize(bytes)?,
            },
            #[cfg(feature = "draft-mahy-mls-new-content-types")]
            ContentType::Ephemeral => ContentTypeInner::Ephemeral {
                application_data: crate::tlspl::bytes::tls_deserialize(bytes)?,
            },
            #[cfg(feature = "draft-mularczyk-mls-splitcommit")]
            ContentType::SplitCommit => ContentTypeInner::SplitCommit {
                split_commit: <_>::tls_deserialize(bytes)?,
            },
        };
        let auth = FramedContentAuthData::tls_deserialize_with_content_type(bytes, content_type)?;

        let padding_len = Self::consume_padding(bytes)?;

        Ok(Self {
            inner,
            auth,
            padding_len,
        })
    }
}

/// PrivateMessage content AAD struct
///
/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-6.3.1-9>
///
/// # TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     opaque group_id<V>;
///     uint64 epoch;
///     ContentType content_type;
///     opaque authenticated_data<V>;
/// } PrivateContentAAD;
/// ````
#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
pub struct PrivateContentAAD<'a> {
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub group_id: GroupIdRef<'a>,
    pub epoch: &'a Epoch,
    pub content_type: &'a ContentType,
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub authenticated_data: &'a [u8],
}

/// SenderData struct
///
/// <https://www.rfc-editor.org/rfc/rfc9420.html#name-sender-data-encryption>
///
/// # TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     uint32 leaf_index;
///     uint32 generation;
///     opaque reuse_guard[4];
/// } SenderData;
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
pub struct SenderData {
    pub leaf_index: LeafIndex,
    pub generation: Generation,
    pub reuse_guard: ReuseGuard,
}

/// SenderData AAD struct
///
/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-6.3.2-7>
///
/// # TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     opaque group_id<V>;
///     uint64 epoch;
///     ContentType content_type;
/// } SenderDataAAD;
/// ````
#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
pub struct SenderDataAAD<'a> {
    pub group_id: GroupIdRef<'a>,
    pub epoch: &'a Epoch,
    pub content_type: &'a ContentType,
}

#[cfg(test)]
mod tests {
    use crate::Serializable;

    use super::*;

    #[test]
    fn can_roundtrip_private_message_content() -> color_eyre::eyre::Result<()> {
        let _ = color_eyre::install();
        let value = PrivateMessageContent {
            inner: ContentTypeInner::Application {
                application_data: b"Hello world!".into(),
            },
            auth: FramedContentAuthData {
                signature: Default::default(),
                confirmation_tag: None,
            },
            padding_len: 10,
        };

        let bytes = value.to_tls_bytes()?;

        let value2 = PrivateMessageContent::tls_deserialize_with_content_type(
            &mut &bytes[..],
            ContentType::Application,
        )?;
        crate::test_utils::assertions::assert_eq_err!(value, value2);

        Ok(())
    }
}
