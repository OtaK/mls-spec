use crate::defs::{Generation, SenderIndex};

use super::safe_application::Component;

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AppAck {
    pub received_ranges: Vec<MessageRange>,
}

impl<'a> Component<'a> for AppAck {
    fn component_id() -> super::safe_application::ComponentId {
        super::APP_ACK_ID
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MessageRange {
    pub sender: SenderIndex,
    pub first_generation: Generation,
    pub last_generation: Generation,
}
