use color_eyre::eyre::Result;
use mls_spec::{Parsable as _, test_utils::assertions::assert_eq_err};

#[derive(Debug, serde::Deserialize)]
pub struct DeserializationVector {
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub vlbytes_header: Vec<u8>,
    pub length: usize,
}

#[async_trait::async_trait(?Send)]
impl super::TestVector for DeserializationVector {
    const TEST_FILE: &'static str = "deserialization.json";

    async fn execute(mut self) -> Result<()> {
        self.vlbytes_header
            .resize(self.vlbytes_header.len() + self.length, 0);
        let deserialized = mls_spec::SensitiveBytes::from_tls_bytes(&self.vlbytes_header)?;
        assert_eq_err!(deserialized.len(), self.length);
        Ok(())
    }
}
