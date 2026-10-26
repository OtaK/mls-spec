use crate::defs::{Generation, SenderIndex};

use super::safe_application::Component;

/// <https://www.ietf.org/archive/id/draft-ietf-mls-extensions-10.html#section-6.1>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     MessageRange received_ranges<V>;
/// } AppAck;
/// ```
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

/// <https://www.ietf.org/archive/id/draft-ietf-mls-extensions-10.html#section-6.1>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     uint32 sender;
///     uint32 first_generation;
///     uint32 last_generation;
/// } MessageRange;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MessageRange {
    pub sender: SenderIndex,
    pub first_generation: Generation,
    pub last_generation: Generation,
}
