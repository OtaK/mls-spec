use crate::{
    SensitiveBytes,
    defs::{CiphersuiteId, LeafIndex, ProposalType, ProtocolVersion},
    group::{GroupId, extensions::Extension},
    key_package::KeyPackage,
    key_schedule::{GroupContext, PreSharedKeyId},
    tree::leaf_node::LeafNode,
};

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u16)]
pub enum Proposal<'a> {
    #[tlspl(discriminant = "ProposalType::ADD")]
    Add(AddProposal<'a>),
    #[tlspl(discriminant = "ProposalType::UPDATE")]
    Update(UpdateProposal<'a>),
    #[tlspl(discriminant = "ProposalType::REMOVE")]
    Remove(RemoveProposal),
    #[tlspl(discriminant = "ProposalType::PSK")]
    PreSharedKey(PreSharedKeyProposal<'a>),
    #[tlspl(discriminant = "ProposalType::REINIT")]
    ReInit(ReInitProposal<'a>),
    #[tlspl(discriminant = "ProposalType::EXTERNAL_INIT")]
    ExternalInit(ExternalInitProposal<'a>),
    #[tlspl(discriminant = "ProposalType::GROUP_CONTEXT_EXTENSIONS")]
    GroupContextExtensions(GroupContextExtensionsProposal<'a>),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[tlspl(discriminant = "ProposalType::APP_DATA_UPDATE")]
    AppDataUpdate(crate::drafts::mls_extensions::safe_application::AppDataUpdate<'a>),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[tlspl(discriminant = "ProposalType::APP_EPHEMERAL")]
    AppEphemeral(crate::drafts::mls_extensions::safe_application::AppEphemeral<'a>),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[tlspl(discriminant = "ProposalType::SELF_REMOVE")]
    SelfRemove(crate::drafts::mls_extensions::self_remove::SelfRemoveProposal),
}

impl Proposal<'_> {
    #[inline(always)]
    pub fn proposal_type(&self) -> ProposalType {
        self.into()
    }
}

impl From<&Proposal<'_>> for ProposalType {
    fn from(val: &Proposal) -> Self {
        match val {
            Proposal::Add(_) => ProposalType::ADD,
            Proposal::Update(_) => ProposalType::UPDATE,
            Proposal::Remove(_) => ProposalType::REMOVE,
            Proposal::PreSharedKey(_) => ProposalType::PSK,
            Proposal::ReInit(_) => ProposalType::REINIT,
            Proposal::ExternalInit(_) => ProposalType::EXTERNAL_INIT,
            Proposal::GroupContextExtensions(_) => ProposalType::GROUP_CONTEXT_EXTENSIONS,
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Proposal::AppDataUpdate(_) => ProposalType::APP_DATA_UPDATE,
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Proposal::AppEphemeral(_) => ProposalType::APP_EPHEMERAL,
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Proposal::SelfRemove(_) => ProposalType::SELF_REMOVE,
        }
    }
}

impl Proposal<'_> {
    #[inline]
    pub fn needs_update_path(&self) -> bool {
        self.proposal_type().needs_update_path()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AddProposal<'a> {
    pub key_package: KeyPackage<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UpdateProposal<'a> {
    pub leaf_node: LeafNode<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoveProposal {
    pub removed: LeafIndex,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PreSharedKeyProposal<'a> {
    pub psk: PreSharedKeyId<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReInitProposal<'a> {
    pub group_id: GroupId<'a>,
    pub version: ProtocolVersion,
    pub cipher_suite: CiphersuiteId,
    pub extensions: Vec<Extension<'a>>,
}

impl ReInitProposal<'_> {
    pub fn matches_group_context(&self, ctx: &GroupContext) -> bool {
        self.group_id == ctx.group_id()
            && self.version == ctx.version
            && self.cipher_suite == ctx.cipher_suite
            && self.extensions == ctx.extensions
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExternalInitProposal<'a> {
    pub kem_output: SensitiveBytes<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GroupContextExtensionsProposal<'a> {
    pub extensions: Vec<Extension<'a>>,
}
