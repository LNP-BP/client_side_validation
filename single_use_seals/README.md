# Client-side-validation commit-verify library

![Build](https://github.com/LNP-BP/client_side_validation/workflows/Build/badge.svg)
![Tests](https://github.com/LNP-BP/client_side_validation/workflows/Tests/badge.svg)
![Lints](https://github.com/LNP-BP/client_side_validation/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/LNP-BP/client_side_validation/branch/master/graph/badge.svg)](https://codecov.io/gh/LNP-BP/client_side_validation)

[![crates.io](https://meritbadge.herokuapp.com/single_use_seals)](https://crates.io/crates/single_use_seals)
[![Docs](https://docs.rs/single_use_seals/badge.svg)](https://docs.rs/single_use_seals)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Apache-2 licensed](https://img.shields.io/crates/l/single_use_seals)](./LICENSE)

This is an implementation of [LNPBP-8] single-use-seal abstraction. 
Specifically, it provides a set of traits that allow to implement Peter's Todd 
**single-use seal** paradigm. Information in this file partially contains 
extracts from Peter's works listed in "Further reading" section.

The library is a part of more generic [`client_side_validation`] library 
covering other client-side-validation standards. Client-side-validation is a 
paradigm for distributed computing, based on top of proof-of-publication/
commitment medium layer, which may be a bitcoin blockchain or other type of 
distributed consensus system.

The development of the library is supported by [LNP/BP Standards Association][lnpbp-web]
and is performed on its [GitHub page][lnpbp-github].

Minimum supported rust version for the library (MSRV) is 1.66 and 2021 rust
edition.


## Documentation

Detailed developer & API documentation for the library can be accessed
at <https://docs.rs/single_use_seals/>

To learn about the technologies enabled by the library please check
[slides from our tech presentations][presentations]
and [LNP/BP tech talks videos][lnpbp-youtube]


## Usage

To use the library, you just need to reference the latest version, in 
`[dependencies]` section of your project `Cargo.toml`.

```toml
single_use_seals = "1"
```

If you are using other client-side-validation libraries, consider importing
just a single [`client_side_validation`] library which re-exports all of them,
including the current one.

The library does not expose any feature flags and have only a single dependency
on `amplify_derive` crate, also created and supported by the LNP/BP Association.

## More information

### Single-use-seals definition

Analogous to the real-world, physical, single-use-seals used to secure
shipping containers, a single-use-seal primitive is a unique object that can
be closed over a message exactly once. In short, a single-use-seal is an
abstract mechanism to prevent double-spends.

A single-use-seal implementation supports two fundamental operations:
* `Close(l,m) → w` — Close seal l over message m, producing a witness `w`.
* `Verify(l,w,m) → bool` — Verify that the seal l was closed over message `m`.

A single-use-seal implementation is secure if it is impossible for an
attacker to cause the Verify function to return true for two distinct
messages m1, m2, when applied to the same seal (it is acceptable, although
non-ideal, for there to exist multiple witnesses for the same seal/message
pair).

Practical single-use-seal implementations will also obviously require some
way of generating new single-use-seals:
* `Gen(p)→l` — Generate a new seal basing on some seal definition data `p`.

### Terminology

**Single-use-seal**: a commitment to commit to some (potentially unknown)
  message. The first commitment (i.e. single-use-seal) must be a
  well-defined (i.e. fully specified and unequally identifiable
  in some space, like in time/place or within a given formal informational
  system).
**Closing of a single-use-seal over message**: a fulfilment of the first
  commitment: creation of the actual commitment to some message in a form
  unequally defined by the seal.
**Witness**: data produced with closing of a single use seal which are
  required and sufficient for an independent party to verify that the seal
  was indeed closed over a given message (i.e. the commitment to the message
  had being created according to the seal definition).

NB: It's important to note, that while its possible to deterministically
  define was a given seal closed it yet may be not possible to find out
  if the seal is open; i.e. seal status may be either "closed over message"
  or "unknown". Some specific implementations of single-use-seals may define
  procedure to deterministically prove that a given seal is not closed (i.e.
  opened), however this is not a part of the specification and we should
  not rely on the existence of such possibility in all cases.

### Trait structure

The module defines trait `SealProtocol` that can be used for
implementation of single-use-seals with methods for seal close and
verification. A type implementing this trait operates only with messages
(which is represented by any type that implements `AsRef<[u8]>`,i.e. can be
represented as a sequence of bytes) and witnesses (which is represented by
an associated type `SealProtocol::Witness`). At the same time,
`SealProtocol` can't define seals by itself.

Seal protocol operates with a *seal medium *: a proof of publication medium
on which the seals are defined.

The module provides two options of implementing such medium: synchronous
`SealProtocol` and asynchronous `SealProtocolAsync`.

### Sample implementation

Examples of implementations can be found in `bp::seals` module of `bp-core`
crate.

### Further reading

* Peter Todd. Preventing Consensus Fraud with Commitments and
  Single-Use-Seals.
  <https://petertodd.org/2016/commitments-and-single-use-seals>.
* Peter Todd. Scalable Semi-Trustless Asset Transfer via Single-Use-Seals
  and Proof-of-Publication. 1. Single-Use-Seal Definition.
  <https://petertodd.org/2017/scalable-single-use-seal-asset-transfer>

## Contributing

Contribution guidelines can be found in [CONTRIBUTING](../CONTRIBUTING.md)


## Licensing

The libraries are distributed on the terms of Apache 2.0 opensource license.
See [LICENCE](LICENSE) file for the license details.

[`client_side_validation`]: https://crates.io/crates/client_side_validation
[lnpbp-web]: https://lnp-bp.org
[lnpbp-github]: https://github.com/LNP-BP
[lnpbp-youtube]: https://www.youtube.com/@LNPBP
[presentations]: https://github.com/LNP-BP/FAQ/blob/master/Presentation%20slides/

[LNPBP-8]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0008.md
