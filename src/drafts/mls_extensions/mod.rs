use safe_application::ComponentId;

pub mod app_ack;
pub mod content_advertisement;
pub mod last_resort_keypackage;
pub mod multi_credentials;
pub mod safe_application;
pub mod self_remove;

pub const EXTENSION_APP_DATA_DICT: u16 = 0x0006;
pub const EXTENSION_SUPPORTED_WIRE_FORMATS: u16 = 0x0007;
pub const EXTENSION_REQUIRED_WIRE_FORMATS: u16 = 0x0008;

pub const PROPOSAL_APP_DATA_UPDATE: u16 = 0x0008;
pub const PROPOSAL_APP_EPHEMERAL: u16 = 0x0009;
pub const PROPOSAL_SELF_REMOVE: u16 = 0x000A;

pub const APP_COMPONENTS_ID: ComponentId = 0x0001;
pub const SAFE_AAD_ID: ComponentId = 0x0002;
pub const CONTENT_MEDIA_TYPES_ID: ComponentId = 0x0003;
pub const LAST_RESORT_KEY_PACKAGE_ID: ComponentId = 0x0004;
pub const APP_ACK_ID: ComponentId = 0x0005;
pub const COMPONENT_RESERVED_PRIVATE_RANGE: std::ops::RangeInclusive<ComponentId> = 0x8000..=0xFFFF;
