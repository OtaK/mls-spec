use crate::messages::ContentType;

pub const EXTENSION_SUPPORTED_CONTENT_TYPES: u16 = 0x0009;
pub const EXTENSION_REQUIRED_CONTENT_TYPES: u16 = 0x000A;
pub const CONTENT_TYPE_STATUS: u8 = 0x04;
pub const CONTENT_TYPE_EPHEMERAL: u8 = 0x05;

/// <https://www.ietf.org/archive/id/draft-mahy-mls-new-content-types-01.html#section-3>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///    ContentType content_types<V>;
/// } ContentTypes;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ContentTypes {
    pub content_types: Vec<ContentType>,
}
