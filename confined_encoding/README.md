# Confined encoding library

![Build](https://github.com/LNP-BP/client_side_validation/workflows/Build/badge.svg)
![Tests](https://github.com/LNP-BP/client_side_validation/workflows/Tests/badge.svg)
![Lints](https://github.com/LNP-BP/client_side_validation/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/LNP-BP/client_side_validation/branch/master/graph/badge.svg)](https://codecov.io/gh/LNP-BP/client_side_validation)

[![crates.io](https://meritbadge.herokuapp.com/confined_encoding)](https://crates.io/crates/confined_encoding)
[![Docs](https://docs.rs/confined_encoding/badge.svg)](https://docs.rs/confined_encoding)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Apache-2 licensed](https://img.shields.io/crates/l/confined_encoding)](./LICENSE)

Deterministic binary serialization for consenus-critical applications in 
client-side-validation.

This library is based on **strict encoding** standard, defined by
[LNPBP-7](https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0007.md).
Strict encoding is a binary conservative encoding extensively used in
client-side-validation for deterministic portable (platform-independent)
serialization of data with a known internal data structure. Strict encoding
is a schema-less encoding.

Client-side-validation is a paradigm for distributed computing, based on top of
proof-of-publication/commitment medium layer, which may be a bitcoin blockchain
or other type of distributed consensus system.

The development of the library is supported by 
[LNP/BP Standards Association](https://lnp-bp.org).

The library is designed after Peter Todd ideas for client-side-validated data 
serialization by Dr Maxim Orlovsky, who shaped the ideas into the standards and 
implemented them as a part of this library.


## Documentation

Detailed developer & API documentation for the library can be accessed
at <https://docs.rs/confined_encoding/>

To learn about the technologies enabled by the library please check
[slides from our tech presentations](https://github.com/LNP-BP/FAQ/blob/master/Presentation%20slides/)
and [LNP/BP tech talks videos](https://www.youtube.com/channel/UCK_Q3xcQ-H3ERwArGaMKsxg)


## Usage

To use the library, you just need to reference a latest version, in
`[dependencies]` section of your project `Cargo.toml`.

```toml
confined_encoding = "2.0"
```

If you are using other client-side-validation libraries, consider importing
just a single [`client_side_validation`] library which re-exports all of them,
including the current one.

Library defines two main traits, [`ConfinedEncode`] and [`ConfinedDecode`],
which should be implemented on each type that requires to be represented
for client-side-validation. 

Library exports derivation macros `#[derive(ConfinedEncode, ConfinedDecode)]`, 
which are a part of [`confined_encoding_derive`] sub-crate and controlled by a 
default feature `derive`.


## Contributing

Contribution guidelines can be found in [CONTRIBUTING](../CONTRIBUTING.md)


## Licensing

The libraries are distributed on the terms of Apache 2.0 opensource license.
See [LICENCE](LICENSE) file for the license details.

[`client_side_validation`]: https://crates.io/crates/client_side_validation
[`confined_encoding_derive`]: https://crates.io/crates/confined_encoding_derive
