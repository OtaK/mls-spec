use crate::{
    group::{commits::Commit, proposals::Proposal},
    MlsSpecError,
};

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
    strum::Display,
)]
#[strum(prefix = "ContentType")]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
#[non_exhaustive]
pub enum ContentType {
    Reserved = 0x00,
    Application = 0x01,
    Proposal = 0x02,
    Commit = 0x03,
    #[cfg(feature = "draft-mularczyk-mls-splitcommit")]
    SplitCommit = 0x04,
}

impl TryFrom<u8> for ContentType {
    type Error = MlsSpecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let ct = match value {
            0x00 => Self::Reserved,
            0x01 => Self::Application,
            0x02 => Self::Proposal,
            0x03 => Self::Commit,
            #[cfg(feature = "draft-mularczyk-mls-splitcommit")]
            0x04 => Self::SplitCommit,
            _ => return Err(MlsSpecError::InvalidContentType),
        };

        Ok(ct)
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
#[repr(u8)]
pub enum ContentTypeInner {
    #[tls_codec(discriminant = "ContentType::Application")]
    Application {
        #[tls_codec(with = "crate::tlspl::bytes")]
        application_data: Vec<u8>,
    },
    #[tls_codec(discriminant = "ContentType::Proposal")]
    Proposal { proposal: Proposal },
    #[tls_codec(discriminant = "ContentType::Commit")]
    Commit { commit: Commit },
    #[cfg(feature = "draft-mularczyk-mls-splitcommit")]
    #[tls_codec(discriminant = "ContentType::SplitCommit")]
    SplitCommit {
        split_commit: crate::drafts::split_commit::SplitCommit,
    },
}

impl From<&ContentTypeInner> for ContentType {
    fn from(value: &ContentTypeInner) -> Self {
        match value {
            ContentTypeInner::Application { .. } => ContentType::Application,
            ContentTypeInner::Proposal { .. } => ContentType::Proposal,
            ContentTypeInner::Commit { .. } => ContentType::Commit,
            #[cfg(feature = "draft-mularczyk-mls-splitcommit")]
            ContentTypeInner::SplitCommit { .. } => ContentType::SplitCommit,
        }
    }
}
