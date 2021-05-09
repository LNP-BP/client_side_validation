# Client-side-validation commit-verify library

![Build](https://github.com/LNP-BP/client_side_validation/workflows/Build/badge.svg)
![Tests](https://github.com/LNP-BP/client_side_validation/workflows/Tests/badge.svg)
![Lints](https://github.com/LNP-BP/client_side_validation/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/LNP-BP/client_side_validation/branch/master/graph/badge.svg)](https://codecov.io/gh/LNP-BP/client_side_validation)

[![crates.io](https://meritbadge.herokuapp.com/single_use_seals)](https://crates.io/crates/single_use_seals)
[![Docs](https://docs.rs/single_use_seals/badge.svg)](https://docs.rs/single_use_seals)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Apache-2 licensed](https://img.shields.io/crates/l/single_use_seals)](./LICENSE)

This is an implementation of [LNPBP-4] multi-commitment standard and [LNPBP-9] 
standard, defining to cryptographic commitment schemes used in 
client-side-validation. It is a part of more generic [`client_side_validation`] 
library covering other client-side-validation standards.

Client-side-validation is a paradigm for distributed computing, based on top of
proof-of-publication/commitment medium layer, which may be a bitcoin blockchain
or other type of distributed consensus system.

The development of the library is supported by [LNP/BP Standards Association](https://lnp-bp.org).
The original idea of client-side-validation was proposed by Peter Todd with its
possible applications designed by Giacomo Zucco. It was shaped into a protocol-
level design by Dr Maxim Orlovsky with a big input from the community and
implemented by him as this set of libraries.


## Documentation

Detailed developer & API documentation for the library can be accessed
at <https://docs.rs/single_use_seals/>

To learn about the technologies enabled by the library please check
[slides from our tech presentations](https://github.com/LNP-BP/FAQ/blob/master/Presentation%20slides/)
and [LNP/BP tech talks videos](https://www.youtube.com/channel/UCK_Q3xcQ-H3ERwArGaMKsxg)


## Usage

To use the library, you just need to reference a latest version, in 
`[dependencies]` section of your project `Cargo.toml`.

```toml
single_use_seals = "1"
```

If you are using other client-side-validation libraries, consider importing
just a single [`client_side_validation`] library which re-exports all of them,
including the current one.

The library does not expose any feature flags and have only a single dependency
on `amplify_derive` crate, also created and supported by the LNP/BP Association.


## Contributing

Contribution guidelines can be found in [CONTRIBUTING](../CONTRIBUTING.md)


## Licensing

The libraries are distributed on the terms of Apache 2.0 opensource license.
See [LICENCE](LICENSE) file for the license details.

[`client_side_validation`]: https://crates.io/crates/client_side_validation
