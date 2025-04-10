use color_eyre::eyre::{Result, WrapErr as _};
use mls_spec::{
    group::{
        commits::Commit,
        proposals::{
            AddProposal, ExternalInitProposal, GroupContextExtensionsProposal,
            PreSharedKeyProposal, ReInitProposal, RemoveProposal, UpdateProposal,
        },
        welcome::GroupSecrets,
    },
    messages::{ContentTypeInner, FramedContent, MlsMessage, MlsMessageContent, PublicMessage},
    test_utils::assertions::assert_eq_err,
    tree::RatchetTree,
};

#[derive(Debug, serde::Deserialize)]
pub struct MessagesVector {
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub mls_welcome: Vec<u8>,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub mls_group_info: Vec<u8>,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub mls_key_package: Vec<u8>,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub ratchet_tree: Vec<u8>,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub group_secrets: Vec<u8>,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub add_proposal: Vec<u8>,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub update_proposal: Vec<u8>,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub remove_proposal: Vec<u8>,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub pre_shared_key_proposal: Vec<u8>,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub re_init_proposal: Vec<u8>,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub external_init_proposal: Vec<u8>,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub group_context_extensions_proposal: Vec<u8>,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub commit: Vec<u8>,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub public_message_application: Vec<u8>,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub public_message_proposal: Vec<u8>,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub public_message_commit: Vec<u8>,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub private_message: Vec<u8>,
}

fn roundtrip<S: mls_spec::Serializable + mls_spec::Parsable>(buf: &[u8]) -> Result<S> {
    let type_name = std::any::type_name::<S>();
    let value = S::from_tls_bytes(buf).context(format!("{type_name} {buf:?}"))?;
    assert_eq_err!(buf, &value.to_tls_bytes()?, type_name);
    Ok(value)
}

#[async_trait::async_trait(?Send)]
impl super::TestVector for MessagesVector {
    const TEST_FILE: &'static str = "messages.json";

    async fn execute(self) -> Result<()> {
        roundtrip::<RatchetTree>(&self.ratchet_tree)?;

        roundtrip::<GroupSecrets>(&self.group_secrets)?;

        roundtrip::<AddProposal>(&self.add_proposal)?;
        roundtrip::<UpdateProposal>(&self.update_proposal)?;
        roundtrip::<RemoveProposal>(&self.remove_proposal)?;
        roundtrip::<PreSharedKeyProposal>(&self.pre_shared_key_proposal)?;
        roundtrip::<ReInitProposal>(&self.re_init_proposal)?;
        roundtrip::<ExternalInitProposal>(&self.external_init_proposal)?;
        roundtrip::<GroupContextExtensionsProposal>(&self.group_context_extensions_proposal)?;
        roundtrip::<Commit>(&self.commit)?;

        let mls_welcome = roundtrip::<MlsMessage>(&self.mls_welcome)?;
        assert_eq_err!(
            matches!(mls_welcome.content, MlsMessageContent::Welcome(_)),
            true
        );

        let mls_group_info = roundtrip::<MlsMessage>(&self.mls_group_info)?;
        assert_eq_err!(
            matches!(mls_group_info.content, MlsMessageContent::GroupInfo(_)),
            true
        );

        let mls_key_package = roundtrip::<MlsMessage>(&self.mls_key_package)?;
        assert_eq_err!(
            matches!(mls_key_package.content, MlsMessageContent::KeyPackage(_)),
            true
        );

        let public_message_application = roundtrip::<MlsMessage>(&self.public_message_application)?;
        assert_eq_err!(
            matches!(
                public_message_application.content,
                MlsMessageContent::MlsPublicMessage(PublicMessage {
                    content: FramedContent {
                        content: ContentTypeInner::Application { .. },
                        ..
                    },
                    ..
                })
            ),
            true
        );

        let public_message_proposal = roundtrip::<MlsMessage>(&self.public_message_proposal)?;
        assert_eq_err!(
            matches!(
                public_message_proposal.content,
                MlsMessageContent::MlsPublicMessage(PublicMessage {
                    content: FramedContent {
                        content: ContentTypeInner::Proposal { .. },
                        ..
                    },
                    ..
                })
            ),
            true
        );

        let public_message_commit = roundtrip::<MlsMessage>(&self.public_message_commit)?;
        assert_eq_err!(
            matches!(
                public_message_commit.content,
                MlsMessageContent::MlsPublicMessage(PublicMessage {
                    content: FramedContent {
                        content: ContentTypeInner::Commit { .. },
                        ..
                    },
                    ..
                })
            ),
            true
        );

        let private_message = roundtrip::<MlsMessage>(&self.private_message)?;
        assert_eq_err!(
            matches!(
                private_message.content,
                MlsMessageContent::MlsPrivateMessage(_)
            ),
            true
        );

        Ok(())
    }
}
