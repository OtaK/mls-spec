use color_eyre::eyre::Result;

use libtest_mimic::{Arguments, Trial};

#[async_trait::async_trait(?Send)]
pub trait TestVector: serde::de::DeserializeOwned {
    const TEST_FILE: &'static str;

    async fn execute(self) -> Result<()>;

    fn collect_tests() -> Result<Vec<Trial>>
    where
        Self: Sized + Send + 'static,
    {
        let mut path = std::path::PathBuf::from("tests/spec-test-vectors/vectors/");
        path.push(Self::TEST_FILE);

        let file = std::fs::File::open(path.clone())?;
        let reader = std::io::BufReader::new(file);
        let test_instances: Vec<Self> = serde_json::from_reader(reader)?;
        let mut tests: Vec<Trial> = test_instances
            .into_iter()
            .enumerate()
            .map(|(idx, test)| {
                use convert_case::{Case, Casing as _};
                let test_name = format!(
                    "{}_{:04}",
                    path.file_stem().unwrap().to_str().unwrap(),
                    idx + 1
                )
                .to_case(Case::Snake);

                Trial::test(test_name, move || {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?
                        .block_on(test.execute())
                        .unwrap();
                    Ok(())
                })
                .with_kind("kat-test-vector")
            })
            .collect();

        tests.sort_unstable_by(|a, b| a.name().cmp(b.name()));

        Ok(tests)
    }
}

fn main() -> Result<()> {
    use tracing_subscriber::prelude::*;
    let fmt_layer = tracing_subscriber::fmt::layer().with_target(false);
    let filter_layer = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_new("info"))?;
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .with(tracing_error::ErrorLayer::default())
        .init();

    color_eyre::install()?;

    let mut args = Arguments::from_args();
    args.test_threads = Some(1);

    let mut tests = vec![];
    tests.append(&mut deserialization::DeserializationVector::collect_tests()?);
    tests.append(&mut messages::MessagesVector::collect_tests()?);

    libtest_mimic::run(&args, tests).exit_if_failed();
    Ok(())
}

#[path = "spec-test-vectors/messages.rs"]
mod messages;

#[path = "spec-test-vectors/deserialization.rs"]
mod deserialization;
