# Strict encoding library

![Build](https://github.com/LNP-BP/client_side_validation/workflows/Build/badge.svg)
![Tests](https://github.com/LNP-BP/client_side_validation/workflows/Tests/badge.svg)
![Lints](https://github.com/LNP-BP/client_side_validation/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/LNP-BP/client_side_validation/branch/master/graph/badge.svg)](https://codecov.io/gh/LNP-BP/client_side_validation)

[![crates.io](https://meritbadge.herokuapp.com/strict_encoding)](https://crates.io/crates/strict_encoding)
[![Docs](https://docs.rs/strict_encoding/badge.svg)](https://docs.rs/strict_encoding)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Apache-2 licensed](https://img.shields.io/crates/l/strict_encoding)](./LICENSE)

Deterministic binary serialization for client-side-validation.

This library implements **strict encoding** standard, defined by
[LNPBP-7](https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0007.md).
Strict encoding is a binary conservative encoding extensively used in
client-side-validation for deterministic portable (platform-independent)
serialization of data with a known internal data structure. Strict encoding
is a schema-less encoding.

As a part of strict encoding, crate also includes implementation of
network address **uniform encoding** standard
([LNPBP-42](https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0042.md)),
which allows representation of any kind of network address as a fixed-size
byte string occupying 37 bytes. This standard is used for the strict
encoding of networking addresses.

Client-side-validation is a paradigm for distributed computing, based on top of
proof-of-publication/commitment medium layer, which may be a bitcoin blockchain
or other type of distributed consensus system.

The development of the library is supported by 
[LNP/BP Standards Association](https://lnp-bp.org).

The library is designed after Peter Todd concepts of proofmarshall and 
serialization principles for client-side-validated data and Dr Maxim Orlovsky 
idea of universal network encodings. Both were shaped into the standards and 
implemented as a part of this library by Dr Maxim Orlovsky.


## Documentation

Detailed developer & API documentation for the library can be accessed
at <https://docs.rs/strict_encoding/>

To learn about the technologies enabled by the library please check
[slides from our tech presentations](https://github.com/LNP-BP/FAQ/blob/master/Presentation%20slides/)
and [LNP/BP tech talks videos](https://www.youtube.com/channel/UCK_Q3xcQ-H3ERwArGaMKsxg)


## Usage

To use the library, you just need to reference a latest version, in
`[dependencies]` section of your project `Cargo.toml`.

```toml
strict_encoding = "1.3"
```

If you are using other client-side-validation libraries, consider importing
just a single [`client_side_validation`] library which re-exports all of them,
including the current one.

Library defines two main traits, [`StrictEncode`] and [`StrictDecode`],
which should be implemented on each type that requires to be represented
for client-side-validation. 

Library exports derivation macros `#[derive(StrictEncode, StrictDecode)]`, 
which are a part of [`strict_encoding_derive`] sub-crate and controlled by a 
default feature `derive`. Finally, it implements strict encoding traits for main
data types defined by rust standard library and frequently used crates; the
latter increases the number of dependencies and thus can be controlled with
feature flags:
- `chrono` (used by default): date & time types from `chrono` crate
- `miniscript`: types defined in bitcoin Miniscript
- `crypto`: non-bitcoin cryptographic primitives, which include Ed25519
  curve, X25519 signatures from `ed25519-dalek` library and pedersen
  commitments + bulletproofs from `lnpbp_secp256k1zkp` library. Encodings for
  other cryptography-related types, such as Secp256k1 and hashes, are always
  included as a part of the library - see NB below.

This crate requires `bitcoin` as an upstream dependency since many of
strict-encoded formats are standardized as using *bitcoin consensus
encoding*.


## Contributing

Contribution guidelines can be found in [CONTRIBUTING](../CONTRIBUTING.md)


## Licensing

The libraries are distributed on the terms of Apache 2.0 opensource license.
See [LICENCE](LICENSE) file for the license details.

[`client_side_validation`]: https://crates.io/crates/client_side_validation
[`strict_encoding_derive`]: https://crates.io/crates/strict_encoding_derive
