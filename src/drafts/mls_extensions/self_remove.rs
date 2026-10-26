/// <https://www.ietf.org/archive/id/draft-ietf-mls-extensions-10.html#section-6.3.1>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {} SelfRemove;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SelfRemoveProposal;
