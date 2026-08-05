mod content;
pub use self::content::*;
mod content_type;
pub use self::content_type::*;
mod sender;
pub use self::sender::*;
mod message_kinds;
pub use self::message_kinds::*;
mod content_encryption;
pub use self::content_encryption::*;

use crate::defs::Epoch;
use crate::defs::ProtocolVersion;

/// MLS Message
///
/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-6-4>
///
/// ## TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     ProtocolVersion version = mls10;
///     WireFormat wire_format;
///     select (MLSMessage.wire_format) {
///         case mls_public_message:
///             PublicMessage public_message;
///         case mls_private_message:
///             PrivateMessage private_message;
///         case mls_welcome:
///             Welcome welcome;
///         case mls_group_info:
///             GroupInfo group_info;
///         case mls_key_package:
///             KeyPackage key_package;
///     };
/// } MLSMessage;
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MlsMessage {
    pub version: ProtocolVersion,
    pub content: MlsMessageContent,
}

impl MlsMessage {
    pub fn group_id_and_epoch(&self) -> Option<(&[u8], &Epoch)> {
        Some(match &self.content {
            MlsMessageContent::MlsPublicMessage(public_message) => (
                &public_message.content.group_id,
                &public_message.content.epoch,
            ),
            MlsMessageContent::MlsPrivateMessage(private_message) => {
                (&private_message.group_id, &private_message.epoch)
            }
            MlsMessageContent::GroupInfo(group_info) => (
                group_info.group_context.group_id(),
                &group_info.group_context.epoch,
            ),
            #[cfg(feature = "draft-ietf-mls-targeted-messages")]
            MlsMessageContent::MlsTargetedMessage(targeted_message) => {
                (&targeted_message.group_id, &targeted_message.epoch)
            }
            #[cfg(feature = "draft-mahy-mls-semiprivatemessage")]
            MlsMessageContent::MlsSemiPrivateMessage(semi_private_message) => {
                (&semi_private_message.group_id, &semi_private_message.epoch)
            }
            #[cfg(feature = "draft-mularczyk-mls-splitcommit")]
            MlsMessageContent::MlsSplitCommitMessage(split_commit_message) => {
                return split_commit_message
                    .split_commit_message
                    .group_id_and_epoch();
            }
            #[cfg(feature = "draft-pham-mls-additional-wire-formats")]
            MlsMessageContent::MlsMessageWithoutAad(message_without_aad) => {
                match message_without_aad {
                    crate::drafts::additional_wire_formats::MessageWithoutAad::PublicMessageWithoutAad(public_message_without_aad) => (&public_message_without_aad.content.group_id, &public_message_without_aad.content.epoch),
                    crate::drafts::additional_wire_formats::MessageWithoutAad::PrivateMessageWithoutAad(private_message_without_aad) => (&private_message_without_aad.group_id, &private_message_without_aad.epoch),
                }
            },
            #[cfg(feature = "draft-mahy-mls-private-external")]
            MlsMessageContent::MlsPrivateExternalMessage(private_external_message) => (&private_external_message.group_id, &private_external_message.epoch),
            _ => return None,
        })
    }
}
