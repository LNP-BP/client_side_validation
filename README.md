# Client-side-validation Foundation Libraries

![Build](https://github.com/LNP-BP/client_side_validation/workflows/Build/badge.svg)
![Tests](https://github.com/LNP-BP/client_side_validation/workflows/Tests/badge.svg)
![Lints](https://github.com/LNP-BP/client_side_validation/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/LNP-BP/client_side_validation/branch/master/graph/badge.svg)](https://codecov.io/gh/LNP-BP/client_side_validation)

[![crates.io](https://img.shields.io/crates/v/client_side_validation)](https://crates.io/crates/client_side_validation)
[![Docs](https://docs.rs/client_side_validation/badge.svg)](https://docs.rs/client_side_validation)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Apache-2 licensed](https://img.shields.io/crates/l/client_side_validation)](./LICENSE)

This is an implementation defining standard of client-side-validation 
representing a set of its Foundation libraries. The standards covered by the
libraries include [LNPBP-4], [LNPBP-7], [LNPBP-8], [LNPBP-9], [LNPBP-42], and 
[LNPBP-81] (see [Components](#components) section below for more details).

Client-side-validation is a paradigm for distributed computing, based on top of
proof-of-publication/commitment medium layer, which may be a bitcoin blockchain
or other type of distributed consensus system.

The development of the library is supported by [LNP/BP Standards Association](https://lnp-bp.org).
The original idea of client-side-validation was proposed by Peter Todd with its 
possible applications designed by Giacomo Zucco. It was shaped into a protocol-
level design by Dr Maxim Orlovsky with a big input from the community and
implemented by him as this set of libraries.

Minimum supported rust version for the library (MSRV) is 1.51 (if used without
`crypto` feature because of `dalek` dependency requiring rust edition 2021),
or 1.56 otherwise.


## Documentation

Detailed developer & API documentation for all libraries can be accessed
at <https://docs.rs/client_side_validation/>

To learn about the technologies enabled by the library please check
[slides from our tech presentations](https://github.com/LNP-BP/FAQ/blob/master/Presentation%20slides/)
and [LNP/BP tech talks videos](https://www.youtube.com/channel/UCK_Q3xcQ-H3ERwArGaMKsxg)


## Components

This library consists of the following main three components, which define
independent parts constituting together client-side-validation API and its core
functionality. These are:
- [Strict encoding](strict_encoding/README.md) ([LNPBP-7] and [LNPBP-42] 
  standards): binary standard of encoding client-side-validated data and network 
  addresses.
- [Commit-verify](commit_verify/README.md) client-side-validation-specific APIs:
  * consensus commitments (part of [LNPBP-8] standard)
  * multi-commitments ([LNPBP-4] standard)
  * merklization for client-side-validation ([LNPBP-81] standard)
- [Single-use-seals](single_use_seals/README.md) API ([LNPBP-8] standard)
- Client-side-validation API from the library root, linking those components 
  together according to [LNPBP-9] standard.


## Usage

The repository contains rust libraries for client-side validation.

### Use library in other projects

To use libraries, you just need latest version of libraries, published to 
[crates.io](https://crates.io) into `[dependencies]` section of your project 
`Cargo.toml`. Here is the full list of available libraries from this repository:

```toml
client_side_validation = "1" # "Umbrella" library including all of the tree libraries below
strict_encoding = "1" # Strict encoding API and derivation macros
commit_verify = "1" # Consensus and multi-message commitments
single_use_seals = "1" # Generic (non-bitcoin-specific) API
```

"Umbrella" `client_side_validation` library is configured with default set of
features enabling all of its functionality (and including all of other libraries 
from this repository, listed above). If you need to restrict this set, either
use specific libraries - or configure main library with a set of features in
the following way:
```toml
[dependencies.client_side_validation]
version = "1"
default-features = false
features = [] # Your set of features goes here
```

The library has four feature flags, all of which are not used by default:
- `rand`, providing support for generating random 32-byte sequences of `Slice32`
  type, used in many LNP/BP applications (for instance as hash-lock preimages or
  during LNPBP-4 multi-commitments);
- `serde`, providing support for data structure serialization with serde across
  all library;
- `bitcoin`, providing implementation of strint encoding for bitcoin data types;
- `crypto`, adding strict encoding support for Ed25519/X25519, Grin Secp256k1zkp
  Pedersen commitments and bulletproofs data types.

For specific features which may be enabled for the libraries, please check
library-specific guidelines, located in `README.md` files in each of library
subdirectories.

### Libraries based on client-side-validation

Most of the developers will be probably interested in a more high-level 
libraries based on client-side-validation, applying it to a specific commitment
mediums (bitcoin transaction graph from blockchain or state channels, or more
exotic systems like confidential bitcoin transactions used by elements & liquid,
or mimblewimble-based systems). Here is (potentially incomplete) list of such
libraries:
- Bitcoin: [BP Core Lib](https://github.com/LNP-BP/bp-core), which contains 
  bitcoin UTXO single-use-seal implementations for pay-to-contract and 
  sign-to-contract types of seals, as well as a library for deterministic 
  bitcoin commitments. This library is maintained by LNP/BP Association.
- Mimblewimble: [MW Core Lib](https://github.com/pandoracore/mw-core) from 
  [Pandora Core](https://pandoracore.com) – a very early prototypes and proofs 
  of concept applying client-side-validation to mimblewimble-types of 
  blockchains.
- [Pandora sealchain](https://github.com/pandora-network/sealchain-rs), an 
  experimental blockchain of [Pandora Network](https://pandora.network), 
  playing with client-side-validation using modified bitcoin consensus rules, 
  extended with eltoo- and covenants-related functionality and with removed 
  native blockchain-level coin.


## Contributing

Contribution guidelines can be found in [CONTRIBUTING](CONTRIBUTING.md)


## Licensing

The libraries are distributed on the terms of Apache 2.0 opensource license.
See [LICENCE](LICENSE) file for the license details.


[LNPBP-4]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0004.md
[LNPBP-7]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0007.md
[LNPBP-8]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0008.md
[LNPBP-9]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0009.md
[LNPBP-42]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0042.md
[LNPBP-81]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0081.md
