# Commitment encoding derivation macros

![Build](https://github.com/LNP-BP/client_side_validation/workflows/Build/badge.svg)
![Tests](https://github.com/LNP-BP/client_side_validation/workflows/Tests/badge.svg)
![Lints](https://github.com/LNP-BP/client_side_validation/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/LNP-BP/client_side_validation/branch/master/graph/badge.svg)](https://codecov.io/gh/LNP-BP/client_side_validation)

[![crates.io](https://meritbadge.herokuapp.com/strict_encoding_derive)](https://crates.io/crates/strict_encoding_derive)
[![Docs](https://docs.rs/strict_encoding_derive/badge.svg)](https://docs.rs/strict_encoding_derive)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Apache-2 licensed](https://img.shields.io/crates/l/strict_encoding_derive)](../LICENSE)

Derivation macros for strict encoding. To learn more about the strict encoding
please check [`strict_encoding`] crate.

The development of the library is supported by
[LNP/BP Standards Association](https://lnp-bp.org).


## Documentation

Detailed developer & API documentation for the library can be accessed
at <https://docs.rs/strict_encoding_derive/>


## Usage

To use the library, you need to reference a latest version of the 
[`commit_encode_derive`] crate in`[dependencies]` section of your project 
`Cargo.toml`. This crate includes derivation macros from the present library by 
default.

```toml
commit_encode_derive = "0.10"
```

If you are using other client-side-validation libraries, consider importing
just a single [`client_side_validation`] library which re-exports all of them,
including the current one.

Library exports derivation macros `#[derive(CommitEncode)]`.


## Contributing

Contribution guidelines can be found in [CONTRIBUTING](../../CONTRIBUTING.md)


## Licensing

The libraries are distributed on the terms of Apache 2.0 opensource license.
See [LICENCE](LICENSE) file for the license details.

[`client_side_validation`]: https://crates.io/crates/client_side_validation
[`strict_encoding`]: https://crates.io/crates/strict_encoding
