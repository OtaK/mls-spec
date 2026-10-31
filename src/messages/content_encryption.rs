use thalassa::{
    error::TlsplReadError,
    io::{DepthAwareReaderGuard, Read},
};

use crate::{
    CRATE_NAME,
    defs::{Epoch, Generation, LeafIndex},
    messages::{ContentType, ContentTypeInner, FramedContentAuthData},
};

pub type ReuseGuard = [u8; 4];

#[derive(Debug, Clone)]
pub struct PrivateMessageContent<'a> {
    pub inner: ContentTypeInner<'a>,
    pub auth: FramedContentAuthData<'a>,
    pub padding_len: usize,
}

impl PartialEq for PrivateMessageContent<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.auth == other.auth
    }
}
impl Eq for PrivateMessageContent<'_> {}

impl thalassa::TlsplSize for PrivateMessageContent<'_> {
    fn tlspl_serialized_len(&self) -> usize {
        let inner_len = match &self.inner {
            ContentTypeInner::Application { application_data } => {
                application_data.tlspl_serialized_len()
            }
            ContentTypeInner::Proposal { proposal } => proposal.tlspl_serialized_len(),
            ContentTypeInner::Commit { commit } => commit.tlspl_serialized_len(),
            #[cfg(feature = "draft-mularczyk-mls-splitcommit")]
            ContentTypeInner::SplitCommit { split_commit } => split_commit.tlspl_serialized_len(),
            #[cfg(feature = "draft-mahy-mls-new-content-types")]
            ContentTypeInner::Status { application_data }
            | ContentTypeInner::Ephemeral { application_data } => {
                application_data.tlspl_serialized_len()
            }
        };
        inner_len + self.auth.tlspl_serialized_len() + self.padding_len
    }
}

impl thalassa::TlsplSerialize for PrivateMessageContent<'_> {
    fn tlspl_serialize_to<W: thalassa::io::Write>(
        &self,
        writer: &mut W,
    ) -> thalassa::error::TlsplWriteResult<usize> {
        let mut written = match &self.inner {
            ContentTypeInner::Application { application_data } => {
                application_data.tlspl_serialize_to(writer)?
            }
            ContentTypeInner::Proposal { proposal } => proposal.tlspl_serialize_to(writer)?,
            ContentTypeInner::Commit { commit } => commit.tlspl_serialize_to(writer)?,
            #[cfg(feature = "draft-mularczyk-mls-splitcommit")]
            ContentTypeInner::SplitCommit { split_commit } => {
                split_commit.tlspl_serialize_to(writer)?
            }
            #[cfg(feature = "draft-mahy-mls-new-content-types")]
            ContentTypeInner::Status { application_data }
            | ContentTypeInner::Ephemeral { application_data } => {
                application_data.tlspl_serialize_to(writer)?
            }
        };
        written += self.auth.tlspl_serialize_to(writer)? + self.padding_len;

        writer.write_all(&vec![0u8; self.padding_len])?;

        Ok(written)
    }
}

impl<'a> PrivateMessageContent<'a> {
    pub fn tlspl_deserialize_with_content_type<R: Read<'a>>(
        reader: &mut DepthAwareReaderGuard<'_, R>,
        content_type: ContentType,
    ) -> Result<Self, TlsplReadError> {
        use thalassa::TlsplDeserialize as _;
        let inner = match content_type {
            ContentType::Reserved => {
                return Err(TlsplReadError::custom(
                    CRATE_NAME,
                    "Tried to deserialize a ContentType::RESERVED, which is invalid",
                ));
            }
            ContentType::Application => ContentTypeInner::Application {
                application_data: <_>::tlspl_deserialize_from(reader)?,
            },
            ContentType::Proposal => ContentTypeInner::Proposal {
                proposal: <_>::tlspl_deserialize_from(reader)?,
            },
            ContentType::Commit => ContentTypeInner::Commit {
                commit: <_>::tlspl_deserialize_from(reader)?,
            },
            #[cfg(feature = "draft-mahy-mls-new-content-types")]
            ContentType::Status => ContentTypeInner::Status {
                application_data: <_>::tlspl_deserialize_from(reader)?,
            },
            #[cfg(feature = "draft-mahy-mls-new-content-types")]
            ContentType::Ephemeral => ContentTypeInner::Ephemeral {
                application_data: <_>::tlspl_deserialize_from(reader)?,
            },
            #[cfg(feature = "draft-mularczyk-mls-splitcommit")]
            ContentType::SplitCommit => ContentTypeInner::SplitCommit {
                split_commit: <_>::tlspl_deserialize_from(reader)?,
            },
        };
        let auth = FramedContentAuthData::tlspl_deserialize_from_with_content_type(
            &mut reader.enter().map_err(TlsplReadError::from)?,
            content_type,
        )?;

        let padding_len = crate::consume_padding(reader)?;

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
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
pub struct PrivateContentAAD<'a> {
    pub group_id: &'a [u8],
    pub epoch: &'a Epoch,
    pub content_type: &'a ContentType,
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
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
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
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
pub struct SenderDataAAD<'a> {
    pub group_id: &'a [u8],
    pub epoch: &'a Epoch,
    pub content_type: &'a ContentType,
}

#[cfg(test)]
mod tests {
    use thalassa::io::DepthAwareReader;

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

        let mut bytes = value.to_tls_bytes()?;

        let value2 = PrivateMessageContent::tlspl_deserialize_with_content_type(
            &mut DepthAwareReader::from_reader(&mut bytes).enter()?,
            ContentType::Application,
        )?;
        crate::test_utils::assertions::assert_eq_err!(value, value2);

        Ok(())
    }
}
