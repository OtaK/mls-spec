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
