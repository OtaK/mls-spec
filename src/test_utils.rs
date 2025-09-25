#![allow(dead_code, unused_macros)]

pub mod assertions {
    #[macro_export]
    macro_rules! assert_eq_err {
        ($actual:expr, $expected:expr, $msg:expr) => {{
            color_eyre::eyre::ensure!(
                $actual == $expected,
                "{}\n{}",
                $msg,
                pretty_assertions::Comparison::new(&$actual, &$expected)
            )
        }};
        ($actual:expr, $expected:expr) => {{
            color_eyre::eyre::ensure!(
                $actual == $expected,
                "{}",
                pretty_assertions::Comparison::new(&$actual, &$expected)
            )
        }};
    }

    #[macro_export]
    macro_rules! assert_ne_err {
        ($actual:expr, $expected:expr, $msg:expr) => {
            color_eyre::eyre::ensure!(
                $actual != $expected,
                "{} {} == {}",
                $msg,
                stringify!($actual),
                strinfify!($expected),
            )
        };
        ($actual:expr, $expected:expr) => {
            color_eyre::eyre::ensure!(
                $actual != $expected,
                "{} == {}",
                stringify!($actual),
                stringify!($expected)
            )
        };
    }

    #[macro_export]
    macro_rules! assert_err {
        ($assertion:expr, $msg:expr) => {
            color_eyre::eyre::ensure!($assertion, "{} {:?} != true", $msg, $assertion)
        };
        ($assertion:expr) => {
            color_eyre::eyre::ensure!($assertion, "{:?} != true", $assertion)
        };
    }

    pub use assert_eq_err;
    pub use assert_err;
    pub use assert_ne_err;
}

// TODO: Use this macro to roundtrip all the structs in the drafts
pub(crate) mod testing {
    #[cfg(not(feature = "serde"))]
    pub trait Target: crate::Parsable + crate::Serializable + std::fmt::Debug + PartialEq {}
    #[cfg(not(feature = "serde"))]
    impl<T> Target for T where T: crate::Parsable + crate::Serializable + std::fmt::Debug + PartialEq {}

    #[cfg(feature = "serde")]
    pub trait Target:
        crate::Parsable
        + crate::Serializable
        + serde::Serialize
        + for<'a> serde::Deserialize<'a>
        + std::fmt::Debug
        + PartialEq
    {
    }
    #[cfg(feature = "serde")]
    impl<T> Target for T where
        T: crate::Parsable
            + crate::Serializable
            + serde::Serialize
            + for<'a> serde::Deserialize<'a>
            + std::fmt::Debug
            + PartialEq
    {
    }

    pub(crate) fn roundtrip<T: Target>(value: &T, ctx: &str) -> color_eyre::eyre::Result<()> {
        let _ = color_eyre::install();
        let value_bytes = value.to_tls_bytes()?;
        let value2 = T::from_tls_bytes(&value_bytes)?;
        super::assertions::assert_eq_err!(value, &value2);
        println!("==== --> [{ctx}] TLSPL OK");

        #[cfg(feature = "serde")]
        {
            let value3_bytes = postcard::to_stdvec(&value)?;
            let value3 = postcard::from_bytes(&value3_bytes)?;
            super::assertions::assert_eq_err!(value, &value3);
            println!("==== --> [{ctx}] serde+postcard OK");
        }
        Ok(())
    }

    #[macro_export]
    macro_rules! generate_roundtrip_test {
        ($testname:ident, $iv:expr) => {
            #[test]
            fn $testname() -> color_eyre::eyre::Result<()> {
                $crate::test_utils::testing::roundtrip(&$iv, stringify!($testname))?;
                Ok(())
            }
        };
    }
}
