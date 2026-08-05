macro_rules! impl_spec_enum {
    (
        $typename:ident($storage:ty);
        reserved_priv $reserved_priv_range:expr => $range_error:expr;
        default_range $spec_default_range:expr;
        $(
            $(#[cfg($attr:meta)])*
            $identifier:ident = $value:expr
        ),+
    ) => {
        #[derive(
            Clone,
            Copy,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            thalassa::TlsplAll,
        )]
        #[cfg_attr(
            feature = "serde",
            derive(serde::Serialize, serde::Deserialize),
            serde(transparent)
        )]
        #[repr(transparent)]
        pub struct $typename($storage);

        impl $typename {
            $(
                $(#[cfg($attr)])*
                pub const $identifier: Self = Self($value as $storage);
            )+
            pub(crate) const RESERVED_PRIVATE_USE_RANGE: std::ops::RangeInclusive<$storage> = $reserved_priv_range;
            pub(crate) const SPEC_DEFAULT_RANGE: Option<std::ops::RangeInclusive<$storage>> = $spec_default_range;
        }

        impl $typename {
            pub const fn as_repr(&self) -> $storage {
                self.0
            }

            #[must_use]
            pub fn all_without_spec_default() -> Vec<Self> {
                let all = [
                    $(
                        $(#[cfg($attr)])*
                        Self($value),
                    )+
                ];

                all.into_iter()
                    .filter(|elem| !elem.is_spec_default())
                    .collect()
            }

            #[must_use]
            pub const fn new_unchecked(value: $storage) -> Self {
                Self(value)
            }

            pub fn new_private_use(value: $storage) -> crate::MlsSpecResult<Self> {
                if !Self::RESERVED_PRIVATE_USE_RANGE.contains(&value) {
                    return Err($range_error);
                }

                Ok(Self(value))
            }

            pub const fn is_spec_default(&self) -> bool {
                let Some(default_range) = &Self::SPEC_DEFAULT_RANGE else {
                    return false;
                };
                *default_range.start() <= self.0 && self.0 <= *default_range.end()
            }

            pub fn is_grease_value(&self) -> bool {
                if Self::RESERVED_PRIVATE_USE_RANGE.contains(&self.0) {
                    return false;
                }

                #[allow(irrefutable_let_patterns)]
                let Ok(self_as_u16): Result<u16, _> = self.0.try_into() else {
                    return false;
                };

                GREASE_VALUES.contains(&self_as_u16)
            }
        }

        impl std::fmt::Display for $typename {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl std::fmt::Debug for $typename {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let mut const_name = match self {
                    $(
                        $(#[cfg($attr)])*
                        &Self::$identifier => Some(stringify!($identifier)),
                    )+
                    _ => None
                };

                let typename = stringify!($typename);

                if let Some(const_name) = const_name.take() {
                    write!(f, "{typename}::{const_name}")?;
                } else {
                    write!(f, "{typename}::UNKNOWN[{:4X}]", self.0)?;
                }

                Ok(())
            }
        }

        impl std::ops::Deref for $typename {
            type Target = $storage;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl TryFrom<$storage> for $typename {
            type Error = crate::MlsSpecError;
            fn try_from(value: $storage) -> Result<Self, Self::Error> {
                let value = Self(value);
                match value {
                    $(
                        $(#[cfg($attr)])*
                        Self::$identifier => Ok(value),
                    )+
                    v if Self::RESERVED_PRIVATE_USE_RANGE.contains(&v.0) => Ok(value),
                    v if GREASE_VALUES.contains(&v.0) => Ok(value),
                    _ => Err(crate::MlsSpecError::InvalidSpecValue)
                }
            }
        }
    };
}

pub(crate) use impl_spec_enum;
