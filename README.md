# MLS Spec

[![Crates.io](https://img.shields.io/crates/v/mls-spec.svg)](https://crates.io/crates/mls-spec)
[![docs.rs](https://docs.rs/mls-spec/badge.svg)](https://docs.rs/mls-spec)

## Description

This crate is a repository of MLS / RFC9420-related data structures.

It is designed to be used as a base for implementations, and contains all the wire-format related structures to be able to build a RFC9420-compliant implementation.

## Documentation

Here: [https://docs.rs/mls-spec](https://docs.rs/mls-spec)

## Details

All sensitive pieces of data are wrapped in a `SensitiveBytes` newtype, which takes care of being zeroization-on-drop
and has constant-time equality checks using `subtle` to make a best-effort attempt at protecting against side-channel attacks.

There's also some definitions for the follwing drafted extensions, enabled by the matching `feature`:

- [`draft-ietf-mls-extensions`](https://www.ietf.org/archive/id/draft-ietf-mls-extensions-08.html) @ draft-08
  - `mls-extensions` has content-advertisement parsing, this pulls an additional dependency (`mediatype`) with this feature flag: `draft-ietf-mls-extensions-content-advertisement-parse`. If you do the MIME parsing yourself, you can ignore this flag.
- [`draft-mahy-mls-ratchet-tree-options`](https://www.ietf.org/archive/id/draft-mahy-mls-ratchet-tree-options-03.html) @ draft-03
- [`draft-mahy-mls-sd-cwt-credential`](https://www.ietf.org/archive/id/draft-mahy-mls-sd-cwt-credential-01.html) @ draft-01
- [`draft-mahy-mls-semiprivatemessage`](https://www.ietf.org/archive/id/draft-mahy-mls-semiprivatemessage-06.html) @ draft-06
- [`draft-mularczyk-mls-splitcommit`](https://www.ietf.org/archive/id/draft-mularczyk-mls-splitcommit-00.html) @ draft-00
- [`draft-kiefer-mls-light`](https://www.ietf.org/archive/id/draft-kiefer-mls-light-02.html) @ draft-02

The following drafts were modified by extrapolating the current status of `mls-extensions` and the current status of the respective drafts:

- The following are assumed that they will move from Safe Extensions to a Safe Applications Component and associated cryptographic operations (`DeriveExtensionSecret` => `DeriveApplicationSecret` etc)
  - [`draft-kohbrok-mls-associated-parties`](https://www.ietf.org/archive/id/draft-kohbrok-mls-associated-parties-00.html) @ draft-00++
  - [`draft-ietf-mls-combiner`](https://www.ietf.org/archive/id/draft-ietf-mls-combiner-01.html) @ draft-01++
- The following assumes that with the disappearance of Safe WireFormats & the introduction of WireFormat negociation through `[supported|required]_wire_formats`, those drafts will fall back to de facto WireFormats and have been modified in accordance
  - [`draft-pham-mls-additional-wire-formats`](https://www.ietf.org/archive/id/draft-pham-mls-additional-wire-formats-00.html) @ draft-00++

Please note that all the `drafts` are semver-excluded.

Additionally, this crate makes use of RustCrypto's `tls_codec` crate, and has a `mls-rs` compatibility layer (gated under the `mls-rs-compat` feature)
that allows to transcode `mls-spec` to `mls-rs` types and vice-versa.

## License

Licensed under either of these:

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
  [https://www.apache.org/licenses/LICENSE-2.0](https://www.apache.org/licenses/LICENSE-2.0))
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  [https://opensource.org/licenses/MIT](https://opensource.org/licenses/MIT))
