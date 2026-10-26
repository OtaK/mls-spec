use crate::defs::{LeafIndex, SenderIndex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr)
)]
#[repr(u8)]
pub enum SenderType {
    Reserved = 0x00,
    Member = 0x01,
    External = 0x02,
    NewMemberProposal = 0x03,
    NewMemberCommit = 0x04,
}

/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-6>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     SenderType sender_type;
///     select (Sender.sender_type) {
///         case member:
///             uint32 leaf_index;
///         case external:
///             uint32 sender_index;
///         case new_member_commit:
///         case new_member_proposal:
///             struct{};
///     };
/// } Sender;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum Sender {
    #[tlspl(discriminant = "SenderType::Member")]
    Member(LeafIndex),
    #[tlspl(discriminant = "SenderType::External")]
    External(SenderIndex),
    #[tlspl(discriminant = "SenderType::NewMemberCommit")]
    NewMemberCommit,
    #[tlspl(discriminant = "SenderType::NewMemberProposal")]
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
