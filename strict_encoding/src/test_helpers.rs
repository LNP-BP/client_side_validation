// LNP/BP client-side-validation foundation libraries implementing LNPBP
// specifications & standards (LNPBP-4, 7, 8, 9, 42, 81)
//
// Written in 2019-2021 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the Apache 2.0 License along with this
// software. If not, see <https://opensource.org/licenses/Apache-2.0>.

// TODO: #35 Extract into separate `strict_encoding_test` crate

//! Helping macros and functions for creating test coverage for strict-encoded
//! data.
//!
//! # Testing enum encoding
//!
//! Enums having assigned primitive 8-bit values (i.e. `u8` values) should be
//! tested with [`test_encoding_enum_u8_exhaustive`], which is a macro
//! performing the most exhaustive testing.
//!
//! If the enum primitive values are of non-`u8`-type, then
//! [`test_encoding_enum_by_values`] should be used. It does not performs
//! exhaustive tests, but covers tests comparing strict encoding with the actual
//! primitive value.
//!
//! If the enum has no primitive values, has associated values (tuple- or
//! structure-based) or any enum variant defines custom
//! `#[strict_encoding(value = ...)]` attribute, testing should be performed
//! with [`test_encoding_enum`] macro.
//!
//! # Testing structures and unions
//!
//! If you have an object which encoding you'd like to test, use
//! [`test_object_encoding_roundtrip`] method.
//!
//! If you have a byte string test vector representing some serialized object,
//! use [`test_vec_decoding_roundtrip`] method.
//!
//! If you have both an object and an independent test vector, representing its
//! serialization (which should not be obtained by just encoding the object),
//! use [`test_encoding_roundtrip`] method.
//!
//! # General guidelines
//!
//! Proper testing should not exercise `asset`s and instead propagate errors
//! returned by test macros and methods to the return of the test case function
//! with `?` operator:
//!
//! ```
//! # #[macro_use] extern crate strict_encoding;
//! use strict_encoding::test_helpers::*;
//!
//! #[derive(Clone, PartialEq, Eq, Debug, StrictEncode, StrictDecode)]
//! struct Data(pub Vec<u8>);
//!
//! #[test]
//! fn test_data_encoding() -> Result<(), DataEncodingTestFailure<Data>> {
//!     let data1 = Data(vec![0x01, 0x02]);
//!     test_encoding_roundtrip(&data1, &[0x02, 0x00, 0x01, 0x02])?;
//!
//!     let data2 = Data(vec![0xff]);
//!     test_encoding_roundtrip(&data2, &[0x02, 0x00, 0xff])?;
//!
//!     Ok(())
//! }
//! ```

use std::fmt::Debug;

use crate::{Error, StrictDecode, StrictEncode};

/// Failures happening during strict encoding tests of enum encodings.
///
/// NB: These errors are specific for testing configuration and should not be
/// used in non-test environment.
#[derive(Clone, PartialEq, Debug, Display, Error)]
pub enum EnumEncodingTestFailure<T>
where
    T: Clone + PartialEq + Debug,
{
    /// Failure during encoding enum variant
    #[display("Failure during encoding enum variant `{0:?}`: {1:?}")]
    EncoderFailure(T, Error),

    /// Failure during decoding binary representation of enum variant
    #[display(
        "Failure during decoding binary representation of enum variant \
         `{0:?}`: `{1:?}`
        \tByte representation: {2:?}"
    )]
    DecoderFailure(T, Error, Vec<u8>),

    /// Test case failure representing mismatch between enum variant produced
    /// by decoding from the originally encoded enum variant
    #[display(
        "Roundtrip encoding of enum variant `{original:?}` results in \
         different variant `{decoded:?}`"
    )]
    DecodedDiffersFromOriginal {
        /// Original value, which was encoded
        original: T,
        /// The value resulting from decoding encoded `original` value
        decoded: T,
    },

    /// Test case failure representing mismatch between expected enum variant
    /// primitive value and the actual primitive value assigned to the enum
    /// variant by the rust compiler
    #[display(
        "Expected value `{expected}` for enum variant \
         `{enum_name}::{variant_name}` does not match the actual value \
         `{actual}`"
    )]
    ValueMismatch {
        /// Name of the enum being tested
        enum_name: &'static str,
        /// Name of the enum variant being tested
        variant_name: &'static str,
        /// Expected primitive value for the tested enum variant
        expected: usize,
        /// Actual primitive value of the tested enum variant
        actual: usize,
    },

    /// Test case failure representing failed byte string representation of the
    /// encoded enum variant
    #[display(
        "Enum variant `{enum_name}:{variant_name}` has incorrect encoding:
        \tExpected: {expected:?}
        \tActual: {actual:?}
        "
    )]
    EncodedValueMismatch {
        /// Name of the enum being tested
        enum_name: &'static str,
        /// Name of the enum variant being tested
        variant_name: &'static str,
        /// Expected encoded byte string for the tested enum variant
        expected: Vec<u8>,
        /// Actual encoded byte string of the tested enum variant
        actual: Vec<u8>,
    },

    /// Test case failure representing incorrect decoder error during
    /// processing out-of-enum range value
    #[display(
        "Decoding of out-of-enum-range value `{0}` results in incorrect \
         decoder error `{1:?}`"
    )]
    DecoderWrongErrorOnUnknownValue(
        /// Value which was decoded into an enum variant
        u8,
        /// Error which was produced during decoding that value
        Error,
    ),

    /// Test case failure representing a out-of-enum range primitive value
    /// still being interpreted as one of enum variants
    #[display(
        "Out-of-enum-range value `{0}` is interpreted as `{1:?}` enum variant \
         by rust compiler"
    )]
    UnknownDecodesToVariant(
        /// Value which was decoded into an enum variant
        u8,
        /// Enum variant resulting from decoding wrong value
        T,
    ),

    /// Test case failure due to wrong `PartialEq` or `Eq` implementation:
    /// enum variant is not equal to itself
    #[display("Enum variant `{0:?}` is not equal to itself")]
    FailedEq(#[doc = "Enum variant which is not equal to itself"] T),

    /// Test case failure due to wrong `PartialEq` or `Eq` implementation:
    /// two distinct enum variants are still equal
    #[display("Two distinct enum variants `{0:?}` and `{1:?}` are equal")]
    FailedNe(
        /// First of two enum variants which are treated as equal
        T,
        /// Second of two enum variants which are treated as equal
        T,
    ),

    /// Test case failure due to wrong `PartialOrd` or `Ord` implementation
    /// happening when enum variants ordering is broken
    #[display(
        "Comparing enum variants `{0:?}` and `{1:?}` results in wrong ordering"
    )]
    FailedOrd(
        /// First of two enum variants which are disordered. This variant
        /// should smaller than the second one, but `Ord` operation
        /// treats it as a larger one
        T,
        /// Second of two enum variants which are disordered. This variant
        /// should larger than the second one, but `Ord` operation
        /// treats it as a smaller one
        T,
    ),
}

/// Macro testing encodings of all enum variants.
///
/// NB: If the enum has primitive assigned values,
/// [`test_encoding_enum_by_values`] should be used instead if this macro. If
/// primitive values are `u8`-based, please use
/// [`test_encoding_enum_u8_exhaustive`].
///
/// Macro expands into an expression of `Result<(),`
/// [`EnumEncodingTestFailure`]`>` type.
///
/// # Covered test case
///
/// - Strict encoding must match little-endian encoding of the value
/// - Roundtrip encoding-decoding of the enum variant must result in the
///   original value
///
/// # Example
///
/// ```
/// # #[macro_use] extern crate strict_encoding;
/// # use strict_encoding::test_encoding_enum;
///
/// #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
/// #[repr(u8)]
/// #[derive(StrictEncode, StrictDecode)]
/// #[strict_encoding(repr = u8)]
/// enum Bits {
///     #[strict_encoding(value = 8)]
///     Bit8,
///
///     #[strict_encoding(value = 16)]
///     Bit16,
/// }
///
/// test_encoding_enum!(
///     Bits as u8;
///     Bits::Bit8 => 8_u8, Bits::Bit16 => 16_u8
/// ).unwrap();
/// ```
#[macro_export]
macro_rules! test_encoding_enum {
    ($enum:path as $ty:ty; $( $item:path => $val:expr ),+) => {
        test_encoding_enum!(strict_encoding => $enum as $ty; $( $item => $val ),+)
    };
    ($se:ident => $enum:path as $ty:ty; $( $item:path => $val:expr ),+) => {
        Ok(())
        $(
            .and_then(|_| {
                use $se::test_helpers::EnumEncodingTestFailure;
                match $se::strict_serialize(&$item) {
                    Ok(bytes) if bytes == &$val.to_le_bytes() => {
                        let deser = $se::strict_deserialize(bytes.clone())
                            .map_err(|e| EnumEncodingTestFailure::DecoderFailure(
                                $item, e, bytes
                            ))?;
                        if deser != $item {
                            Err(EnumEncodingTestFailure::DecodedDiffersFromOriginal {
                                original: $item,
                                decoded: deser,
                            })
                        } else {
                            Ok(())
                        }
                    },
                    Ok(wrong) => Err(EnumEncodingTestFailure::EncodedValueMismatch {
                        enum_name: stringify!($enum),
                        variant_name: stringify!($item),
                        expected: $val.to_le_bytes().to_vec(),
                        actual: wrong,
                    }),
                    Err(err) => Err(
                        EnumEncodingTestFailure::EncoderFailure($item, err)
                    ),
                }
            })
        )+
    }
}

/// Macro testing encodings of all enum variants for enums with assigned
/// primitive integer values.
///
/// Macro expands into an expression of `Result<(),`
/// [`EnumEncodingTestFailure`]`>` type.
///
/// Macro extends functionality of [`test_encoding_enum`] and should be used
/// whenever enum has assigned primitive integer values. If the primitive values
/// are of `u8` type, [`test_encoding_enum_u8_exhaustive`] should be used
/// instead of this macro.
///
/// # Covered test cases
///
/// - Each enum variant must have a primitive value
/// - Primitive value representing enum variant must be equal to strict encoding
///   of the same variant. If a primitive enum value occupies of several bytes
///   (`u16`, `u32` and other large integer types), strict encoding must match
///   little-endian encoding of the value
/// - Roundtrip encoding-decoding of the enum variant must result in the
///   original value
/// - Each enum variant must be equal to itself
/// - Each enum variant must not be equal to any other enum variant
/// - Enum variants must be ordered according to their primitive values
///
/// # Example
///
/// ```
/// # #[macro_use] extern crate strict_encoding;
/// # use strict_encoding::test_encoding_enum_by_values;
///
/// #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
/// #[repr(u8)]
/// #[derive(StrictEncode, StrictDecode)]
/// #[strict_encoding(repr = u8, by_value)]
/// enum Bits {
///     Bit8 = 8,
///     Bit16 = 16,
/// }
///
/// test_encoding_enum_by_values!(
///     Bits as u8;
///     Bits::Bit8 => 8_u8, Bits::Bit16 => 16_u8
/// ).unwrap();
/// ```
#[macro_export]
macro_rules! test_encoding_enum_by_values {
    ($enum:path as $ty:ty; $( $item:path => $val:expr ),+) => {
        test_encoding_enum_by_values!(strict_encoding => $enum as $ty; $( $item => $val ),+)
    };
    ($se:ident => $enum:path as $ty:ty; $( $item:path => $val:expr ),+) => {
        test_encoding_enum!($se => $enum as $ty; $( $item => $val ),+)
        $(
            .and_then(|_| {
                use $se::test_helpers::EnumEncodingTestFailure;
                if $item as $ty != ($val) {
                    return Err(EnumEncodingTestFailure::ValueMismatch {
                        enum_name: stringify!($enum),
                        variant_name: stringify!($item),
                        expected: ($val) as usize,
                        actual: $item as usize,
                    })
                }
                Ok(())
            })
        )+
            .and_then(|_| {
                use $se::test_helpers::EnumEncodingTestFailure;
                let mut all = ::std::collections::BTreeSet::new();
                $( all.insert($item); )+
                for (idx, a) in all.iter().enumerate() {
                    if a != a {
                        return Err(EnumEncodingTestFailure::FailedEq(*a));
                    }
                    for b in all.iter().skip(idx + 1) {
                        if a == b || (*a as usize) == (*b as usize) {
                            return Err(EnumEncodingTestFailure::FailedNe(*a, *b))
                        }
                        if (a >= b && (*a as usize) < (*b as usize)) ||
                           (a <= b && (*a as usize) > (*b as usize)) {
                            return Err(EnumEncodingTestFailure::FailedOrd(*a, *b))
                        }
                    }
                }
                Ok(())
        })
    }
}

/// Macro testing encoding of all possible enum values, covering full range of
/// `u8` values, including enum out-of-range values.
///
/// Macro expands into an expression of `Result<(),`
/// [`EnumEncodingTestFailure`]`>` type.
///
/// Macro extends functionality of [`test_encoding_enum_by_values`] and should
/// be used whenever enum with assigned primitive values is represented by `u8`
/// integers.
///
/// # Covered test cases
///
/// - Each enum variant must have a primitive value
/// - Primitive value representing enum variant must be equal to strict encoding
///   of the same variant. If a primitive enum value occupies of several bytes
///   (`u16`, `u32` and other large integer types), strict encoding must match
///   little-endian encoding of the value
/// - Roundtrip encoding-decoding of the enum variant must result in the
///   original value
/// - Each enum variant must be equal to itself
/// - Each enum variant must not be equal to any other enum variant
/// - Enum variants must be ordered according to their primitive values
/// - All 8-bit integers which do not match any of enum variants must not be
///   decoded with strict decoder into a valid enum and their decoding must
///   result in [`Error::EnumValueNotKnown`] error.
///
/// # Example
///
/// ```
/// # #[macro_use] extern crate strict_encoding;
/// # use strict_encoding::test_encoding_enum_u8_exhaustive;
///
/// #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
/// #[repr(u8)]
/// #[derive(StrictEncode, StrictDecode)]
/// #[strict_encoding(repr = u8, by_value)]
/// enum Bits {
///     Bit8 = 8,
///     Bit16 = 16,
/// }
///
/// test_encoding_enum_u8_exhaustive!(
///     Bits as u8;
///     Bits::Bit8 => 8_u8, Bits::Bit16 => 16_u8
/// ).unwrap();
/// ```
#[macro_export]
macro_rules! test_encoding_enum_u8_exhaustive {
    ($enum:path; $( $item:path => $val:expr ),+) => {
        test_encoding_enum_u8_exhaustive!(strict_encoding => $enum as u8; $( $item => $val ),+)
    };
    ($enum:path as $ty:ty; $( $item:path => $val:expr ),+) => {
        test_encoding_enum_u8_exhaustive!(strict_encoding => $enum as $ty; $( $item => $val ),+)
    };
    ($se:ident => $enum:path; $( $item:path => $val:expr ),+) => {
        test_encoding_enum_u8_exhaustive!($se => $enum as u8; $( $item => $val ),+)
    };
    ($se:ident => $enum:path as $ty:ty; $( $item:path => $val:expr ),+) => {
        test_encoding_enum_by_values!($se => $enum as $ty; $( $item => $val ),+).and_then(|_| {
            use $se::test_helpers::EnumEncodingTestFailure;
            let mut set = ::std::collections::HashSet::new();
            $( set.insert($val); )+
            for x in 0..=u8::MAX {
                if !set.contains(&x) {
                    match $se::strict_deserialize(&[x]) {
                        Err($se::Error::EnumValueNotKnown(stringify!($enum), a)) if a == x as usize => {},
                        Err(err) => return Err(
                            EnumEncodingTestFailure::DecoderWrongErrorOnUnknownValue(x, err)
                        ),
                        Ok(variant) => return Err(
                            EnumEncodingTestFailure::UnknownDecodesToVariant(x, variant)
                        ),
                    }
                }
            }
            Ok(())
        })
    }
}

/// Failures happening during strict encoding tests of struct and union
/// encodings.
///
/// NB: These errors are specific for testing configuration and should not be
/// used in non-test environment.
#[derive(Clone, PartialEq, Debug, Display, Error)]
pub enum DataEncodingTestFailure<T>
where
    T: StrictEncode + StrictDecode + PartialEq + Debug + Clone,
{
    /// Failure during encoding enum variant
    #[display("Failure during encoding: {0:?}")]
    EncoderFailure(#[doc = "Encoder error"] Error),

    /// Failure during decoding binary representation of enum variant
    #[display(
        "Failure during decoding: `{0:?}`
        \tByte representation: {1:?}"
    )]
    DecoderFailure(
        #[doc = "Decoder error"] Error,
        #[doc = "Byte string which failed to decode"] Vec<u8>,
    ),

    /// Failure of the strict encode implementation: encoder reports incorrect
    /// length of the serialized data
    #[display(
        "Encoder reported incorrect length of the serialized data: \
         `{returned}` instead of `{actual}`"
    )]
    EncoderReturnedWrongLength {
        /// Actual length of the serialized data
        actual: usize,
        /// Incorrect length returned by the encoder
        returned: usize,
    },

    /// Test case failure representing mismatch between object produced
    /// by decoding from the originally encoded object
    #[display(
        "Roundtrip encoding of `{original:?}` produced different object \
         `{transcoded:?}`"
    )]
    TranscodedObjectDiffersFromOriginal {
        /// Original value, which was encoded
        original: T,
        /// The value resulting from decoding encoded `original` value
        transcoded: T,
    },

    /// Test case failure representing mismatch between original test vector
    /// and serialization of the object decoded from that test vector
    #[display(
        "Serialization of the object `{object:?}` decoded from a test vector \
         results in a different byte string:
        \tOriginal: {original:?}
        \tSerialization: {transcoded:?}
        "
    )]
    TranscodedVecDiffersFromOriginal {
        /// Original test vector, which was decoded
        original: Vec<u8>,
        /// Byte string produced by encoding object, decoded from the test
        /// vector
        transcoded: Vec<u8>,
        /// Object decoded from the test vector
        object: T,
    },
}

/// Test helper performing encode-decode roundtrip for a provided object. Object
/// type must be `PartialEq + Clone + Debug`.
///
/// # Returns
///
/// If suceeds, encoded byte string representing the object. Otheriwse,
/// [`DataEncodingTestFailure`] (see description below)
///
/// # Error
///
/// Errors on:
/// - encoding or decoding failures;
/// - if the original object is not equivalent to its decoded version;
/// - if encoder returns number of bytes that does not match the length of the
///   encoded data.
///
/// # Panics
///
/// Function does not panics and instead returns [`DataEncodingTestFailure`] for
/// each type of test failures.
///
/// # Example
///
/// ```
/// # #[macro_use] extern crate strict_encoding;
/// # use strict_encoding::test_helpers::test_object_encoding_roundtrip;
///
/// #[derive(Clone, PartialEq, Eq, Debug, StrictEncode, StrictDecode)]
/// struct Data(pub Vec<u8>);
///
/// let data = Data(vec![0x01, 0x02]);
/// assert_eq!(test_object_encoding_roundtrip(&data).unwrap().len(), 4);
/// ```
#[inline]
pub fn test_object_encoding_roundtrip<T>(
    object: &T,
) -> Result<Vec<u8>, DataEncodingTestFailure<T>>
where
    T: StrictEncode + StrictDecode + PartialEq + Clone + Debug,
{
    let mut encoded_object: Vec<u8> = vec![];
    let written = object
        .strict_encode(&mut encoded_object)
        .map_err(DataEncodingTestFailure::EncoderFailure)?;
    let len = encoded_object.len();
    if written != len {
        return Err(DataEncodingTestFailure::EncoderReturnedWrongLength {
            actual: len,
            returned: written,
        });
    }
    let decoded_object =
        T::strict_decode(&encoded_object[..]).map_err(|e| {
            DataEncodingTestFailure::DecoderFailure(e, encoded_object.clone())
        })?;
    if &decoded_object != object {
        return Err(
            DataEncodingTestFailure::TranscodedObjectDiffersFromOriginal {
                original: object.clone(),
                transcoded: decoded_object,
            },
        );
    }
    Ok(encoded_object)
}

/// Test helper performing decode-eecode roundtrip for a provided test vector
/// byte string.
///
/// # Returns
///
/// If suceeds, decoded object, which must have `PartialEq + Clone + Debug`
/// type. Otheriwse, [`DataEncodingTestFailure`] (see description below)
///
/// # Error
///
/// Errors on:
/// - encoding or decoding failures;
/// - if the original test vector is not equivalent to its transcoded version;
/// - if encoder returns number of bytes that does not match the length of the
///   test vector.
///
/// # Panics
///
/// Function does not panics and instead returns [`DataEncodingTestFailure`] for
/// each type of test failures.
///
/// # Example
///
/// ```
/// # #[macro_use] extern crate strict_encoding;
/// # use strict_encoding::test_helpers::test_vec_decoding_roundtrip;
///
/// #[derive(Clone, PartialEq, Eq, Debug, StrictEncode, StrictDecode)]
/// struct Data(pub Vec<u8>);
///
/// let data = Data(vec![0x01, 0x02]);
/// assert_eq!(
///     test_vec_decoding_roundtrip(&[0x02, 0x00, 0x01, 0x02]),
///     Ok(data)
/// );
/// ```
pub fn test_vec_decoding_roundtrip<T>(
    test_vec: impl AsRef<[u8]>,
) -> Result<T, DataEncodingTestFailure<T>>
where
    T: StrictEncode + StrictDecode + PartialEq + Clone + Debug,
{
    let test_vec = test_vec.as_ref();
    let decoded_object = T::strict_decode(test_vec).map_err(|e| {
        DataEncodingTestFailure::DecoderFailure(e, test_vec.to_vec())
    })?;
    let encoded_object = test_object_encoding_roundtrip(&decoded_object)?;
    if test_vec != encoded_object {
        return Err(
            DataEncodingTestFailure::TranscodedVecDiffersFromOriginal {
                original: test_vec.to_vec(),
                transcoded: encoded_object,
                object: decoded_object,
            },
        );
    }
    Ok(decoded_object)
}

/// Test helper performing double encode-decode roundtrip for an object
/// and a matching binary encoding test vector. Object type must be
/// `PartialEq + Clone + Debug`.
///
/// # Error
///
/// Errors on:
/// - encoding or decoding failures;
/// - if the original object is not equivalent to its decoded version;
/// - if the original test vector is not equivalent to its transcoded version;
/// - if encoder returns number of bytes that does not match the length of the
///   test vector.
///
/// # Panics
///
/// Function does not panics and instead returns [`DataEncodingTestFailure`] for
/// each type of test failures.
///
/// # Example
///
/// ```
/// # #[macro_use] extern crate strict_encoding;
/// # use strict_encoding::test_helpers::test_encoding_roundtrip;
///
/// #[derive(Clone, PartialEq, Eq, Debug, StrictEncode, StrictDecode)]
/// struct Data(pub Vec<u8>);
///
/// let data = Data(vec![0x01, 0x02]);
/// test_encoding_roundtrip(&data, &[0x02, 0x00, 0x01, 0x02]).unwrap();
/// ```
pub fn test_encoding_roundtrip<T>(
    object: &T,
    test_vec: impl AsRef<[u8]>,
) -> Result<(), DataEncodingTestFailure<T>>
where
    T: StrictEncode + StrictDecode + PartialEq + Clone + Debug,
{
    let decoded_object = test_vec_decoding_roundtrip(test_vec)?;
    if object != &decoded_object {
        return Err(
            DataEncodingTestFailure::TranscodedObjectDiffersFromOriginal {
                original: object.clone(),
                transcoded: decoded_object,
            },
        );
    }
    Ok(())
}
