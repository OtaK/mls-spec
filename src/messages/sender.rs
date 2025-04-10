use crate::defs::{LeafIndex, SenderIndex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum SenderType {
    Reserved = 0x00,
    Member = 0x01,
    External = 0x02,
    NewMemberProposal = 0x03,
    NewMemberCommit = 0x04,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum Sender {
    #[tls_codec(discriminant = "SenderType::Member")]
    Member(LeafIndex),
    #[tls_codec(discriminant = "SenderType::External")]
    External(SenderIndex),
    #[tls_codec(discriminant = "SenderType::NewMemberCommit")]
    NewMemberCommit,
    #[tls_codec(discriminant = "SenderType::NewMemberProposal")]
    NewMemberProposal,
}

impl From<&Sender> for SenderType {
    fn from(value: &Sender) -> Self {
        match value {
            Sender::Member(_) => SenderType::Member,
            Sender::External(_) => SenderType::External,
            Sender::NewMemberCommit => SenderType::NewMemberCommit,
            Sender::NewMemberProposal => SenderType::NewMemberProposal,
        }
    }
}
