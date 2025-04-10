use crate::{
    credential::Credential,
    crypto::{HpkeCiphertext, HpkePublicKey},
    defs::{Epoch, LeafIndex, WireFormat},
    group::HashReference,
    messages::ReuseGuard,
    SensitiveBytes,
};

use super::mls_extensions::safe_application::{Component, ComponentId};

pub const EXTERNAL_RECEIVERS_COMPONENT_ID: ComponentId = 0xFEEE_0000; // TODO: Waiting for IANA registration
static_assertions::const_assert!(
    *super::mls_extensions::COMPONENT_RESERVED_PRIVATE_RANGE.start()
        <= EXTERNAL_RECEIVERS_COMPONENT_ID
        && EXTERNAL_RECEIVERS_COMPONENT_ID
            <= *super::mls_extensions::COMPONENT_RESERVED_PRIVATE_RANGE.end()
);

pub const WIRE_FORMAT_MLS_SEMIPRIVATE_MESSAGE: u16 = 0xFAFE; // TODO: Waiting for IANA registration
static_assertions::const_assert!(
    *WireFormat::RESERVED_PRIVATE_USE_RANGE.start() <= WIRE_FORMAT_MLS_SEMIPRIVATE_MESSAGE
        && WIRE_FORMAT_MLS_SEMIPRIVATE_MESSAGE <= *WireFormat::RESERVED_PRIVATE_USE_RANGE.end()
);

pub type ExternalReceiverRef = HashReference;

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
pub struct ExternalReceiver {
    pub external_receiver_public_key: HpkePublicKey,
    pub credential: Credential,
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
pub struct ExternalReceivers {
    pub external_receivers: Vec<ExternalReceiver>,
}

impl Component for ExternalReceivers {
    fn component_id() -> ComponentId {
        EXTERNAL_RECEIVERS_COMPONENT_ID
    }
}

/// <https://rohanmahy.github.io/mls-semiprivatemessage/draft-mahy-mls-semiprivatemessage.html#section-3.1-2>
///
/// ```notrust,ignore
/// struct {
///   opaque key<V>;
///   opaque nonce<V>;
///   opaque reuse_guard[4];
///   uint32 sender_leaf_index;
/// } PerMessageKeyAndNonces;
/// ```
///
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
pub struct PerMessageKeyAndNonces {
    pub key: SensitiveBytes,
    pub nonce: SensitiveBytes,
    pub reuse_guard: ReuseGuard,
    pub sender_leaf_index: LeafIndex,
}

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SemiPrivateMessageContext<'a> {
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub group_id: &'a [u8],
    pub epoch: &'a Epoch,
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub partial_context_hash: &'a [u8],
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
pub struct KeyForExternalReceiver {
    pub external_receiver_ref: ExternalReceiverRef,
    pub encrypted_keys_and_nonces: HpkeCiphertext,
}

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct KeyForExternalReceiverRef<'a> {
    pub external_receiver_ref: &'a ExternalReceiverRef,
    pub encrypted_keys_and_nonces: &'a HpkeCiphertext,
}

pub mod messages {
    use crate::{
        defs::Epoch,
        group::{commits::Commit, proposals::Proposal, GroupId, GroupIdRef},
        messages::{ContentType, ContentTypeInner, FramedContentAuthData, PrivateMessageContent},
        SensitiveBytes,
    };

    use super::{KeyForExternalReceiver, KeyForExternalReceiverRef};

    #[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize))]
    pub struct SemiPrivateContentAad<'a> {
        #[tls_codec(with = "crate::tlspl::bytes")]
        pub group_id: GroupIdRef<'a>,
        pub epoch: &'a Epoch,
        pub content_type: &'a ContentType,
        #[tls_codec(with = "crate::tlspl::bytes")]
        pub authenticated_data: &'a [u8],
        #[tls_codec(with = "crate::tlspl::bytes")]
        pub partial_context_hash: &'a [u8],
        pub keys_for_external_receivers: &'a [KeyForExternalReceiverRef<'a>],
        #[tls_codec(with = "crate::tlspl::bytes")]
        pub framed_content_tbs_hash: &'a [u8],
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct SemiPrivateMessageContent {
        pub inner: ContentTypeInner,
        pub auth: FramedContentAuthData,
        pub padding_len: usize,
    }

    impl tls_codec::Size for SemiPrivateMessageContent {
        fn tls_serialized_len(&self) -> usize {
            self.inner.tls_serialized_len() + self.auth.tls_serialized_len() + self.padding_len
        }
    }

    impl tls_codec::Serialize for SemiPrivateMessageContent {
        fn tls_serialize<W: std::io::Write>(
            &self,
            writer: &mut W,
        ) -> Result<usize, tls_codec::Error> {
            let mut written = 0;
            written += self.inner.tls_serialize(writer)?;
            written += self.auth.tls_serialize(writer)?;
            writer.write_all(&vec![0u8; self.padding_len][..])?;
            written += self.padding_len;
            Ok(written)
        }
    }

    impl SemiPrivateMessageContent {
        pub fn tls_deserialize_with_content_type<R: std::io::Read>(
            bytes: &mut R,
            content_type: ContentType,
        ) -> Result<Self, tls_codec::Error> {
            use tls_codec::Deserialize as _;

            let inner = match content_type {
                ContentType::Proposal => ContentTypeInner::Proposal {
                    proposal: Proposal::tls_deserialize(bytes)?,
                },
                ContentType::Commit => ContentTypeInner::Commit {
                    commit: Commit::tls_deserialize(bytes)?,
                },
                _ => {
                    return Err(tls_codec::Error::DecodingError(
                        format!("Tried to deserialize a {content_type}, which is invalid for a SemiPrivateMessage"),
                    ))
                }
            };
            let auth =
                FramedContentAuthData::tls_deserialize_with_content_type(bytes, content_type)?;

            let padding_len = PrivateMessageContent::consume_padding(bytes)?;

            Ok(Self {
                inner,
                auth,
                padding_len,
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
    pub struct SemiPrivateMessage {
        pub group_id: GroupId,
        pub epoch: Epoch,
        pub content_type: ContentType,
        pub authenticated_data: SensitiveBytes,
        pub partial_context_hash: SensitiveBytes,
        pub keys_for_external_receivers: Vec<KeyForExternalReceiver>,
        pub framed_content_tbs_hash: SensitiveBytes,
        pub encrypted_sender_data: SensitiveBytes,
        pub ciphertext: SensitiveBytes,
    }
}
