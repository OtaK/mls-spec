use crate::messages::ContentType;

pub const EXTENSION_SUPPORTED_CONTENT_TYPES: u16 = 0x0009;
pub const EXTENSION_REQUIRED_CONTENT_TYPES: u16 = 0x000A;
pub const CONTENT_TYPE_STATUS: u8 = 0x04;
pub const CONTENT_TYPE_EPHEMERAL: u8 = 0x05;

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    tls_codec::TlsSize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSerialize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ContentTypes {
    pub content_types: Vec<ContentType>,
}
