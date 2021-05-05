# Client-side-validation library

![Build](https://github.com/LNP-BP/client_side_validation/workflows/Build/badge.svg)
![Tests](https://github.com/LNP-BP/client_side_validation/workflows/Tests/badge.svg)
![Lints](https://github.com/LNP-BP/client_side_validation/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/LNP-BP/client_side_validation/branch/master/graph/badge.svg)](https://codecov.io/gh/LNP-BP/client_side_validation)

[![crates.io](https://meritbadge.herokuapp.com/client_side_validation)](https://crates.io/crates/client_side_validation)
[![Docs](https://docs.rs/lnpbp/badge.svg)](https://docs.rs/client_side_validation)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Apache-2 licensed](https://img.shields.io/crates/l/client_side_validation)](./LICENSE)

This is an implementation defining standard of client-side-validation, i.e. its
Core library.

Client-side-validation is a paradigm for distributed computing, based on top of
proof-of-publication/commitment medium layer, which may be a bitcoin blockchain
or other type of distributed consensus system.

The development of the library is supported by [LNP/BP Standards Association](https://lnp-bp.org).
The original idea of client-side-validation was proposed by Peter Todd with its 
possible applications designed by Giacomo Zucco. It was shaped into a protocol-
level design by Dr Maxim Orlovsky with a big input from the community and
implemented by him as this set of libraries.


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
- Strict encoding (LNPBP-7 standard): binary standard of encoding 
  client-side-validated data
- Commit-verify scheme and its client-side-validation specific implementations
  * consensus commitments
  * multi-commitments (LNPBP-4 standard)
- Single-use-seals (LNPBP-8 standard)

Basing on these APIs, this library includes specific applications for commitment/
proof-of-publication mediums. Currently, this is *Bitcoin transaction graph*
(both blockchain and state channel-based), consisting of two main components:
- deterministic bitcoin commitments API (LNPBP-1, 2 & 3 standards)
- bitcoin-based single-use-seal API (LNPBP-10 and LNPBP-39 standards)


## Usage

The repository contains rust libraries for client-side validation and 
command-line tools for debugging/low-level hacking mode.

### Use library in other projects

To use libraries, you just need lates version of libraries, published to 
[crates.io](https://crates.io) into `[dependencies]` section of your project 
`Cargo.toml`. Here is the full list of available libraries from this repository:

```toml
client_side_validation = "1" # "Umbrella" library including all other libraries
strict_encoding = "1" # Strict encoding API and derivation macros
commit_verify = "1" # Consensus and multi-message commitments
single_use_seals = "1" # Generic (non-bitcoin-specific) API
bp-dbc = "1" # Deterministic bitcoin commitments library
bp-seals = "1" # Bitcoin single-use-seals library
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
# Avaliable features
# * `derivation` - includes strict encoding derivation macros
# * `strict_encoding` - strict encoding library (by default does not include
#                       derivation macros, to use it you need`derivation` 
#                       feature to be explicetly enabled
# * `multi-commitments` - LNPBP-4 multi-commitments
# * `dbc` - deterministic bitcoin commitments
# * `seals-all` - All single-use-seals component, including bitcoin seals 
#                 library
# * `seals-api` - single-use-seals core API (without bitcoin-specific extensions)
# * `seals-utxo - Bitcoin-based UTXO single-use-seals
```

For specific features which may be enabled for the libraries, please check
library-specific guidelines, located in `README.md` files in each of library
subdirectories.


### Use command-line tool

First, you have to install rust toolchain using instructions from 
[the official website](https://www.rust-lang.org/tools/install).

Next, if you need the latest published version, you can simply run
```shell script
cargo install client_side_validation
```
which will give you the latest version of the command-line tool. For now, you 
can use it by typing in terminal
```shell script
clisv help
```

If you need a latest `master` version (which may be unstable), you need to clone
git repository and compile the project locally:
```shell script
git clone https://github.com/LNP-BP/client_side_validation
cd client_side_validation
cargo install --path .
```


## Known applications

The current list of the projects based on the library include:
* [RGB](https://github.com/LNP-BP/rgb-node): Confidential & scalable smart
  contracts for Bitcoin & Lightning
* [LNP](https://www.youtube.com/watch?v=YmmNsWS5wiM): generalized lightning 
  network and it's reference implementations named
  [LNP Core](https://github.com/LNP-BP/lnp-core) and
  [LNP Node](https://github.com/LNP-BP/lnp-node)
* [Bitcoin-based decentralized identity](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2021-February/018381.html) 
  proposal uses single-use-seals
* [Internet2 project](https://github.com/internet2-org) uses strict-encoding
  for building its Internet2 APIs and microservice architecture

To learn more about the technologies enabled by the library please check
[slides from our tech presentations](https://github.com/LNP-BP/FAQ/blob/master/Presentation%20slides/)
and [LNP/BP tech talks videos](https://www.youtube.com/channel/UCK_Q3xcQ-H3ERwArGaMKsxg)


## Contributing

Contribution guidelines can be found in [CONTRIBUTING](CONTRIBUTING.md)


## More information

### Policy on altcoins

Altcoins and "blockchains" other than Bitcoin blockchain/Bitcoin protocols are 
not supported and not planned to be supported; pull requests targeting them will 
be declined.

### Licensing

See [LICENCE](LICENSE) file.
