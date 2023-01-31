// LNP/BP client-side-validation foundation libraries implementing LNPBP
// specifications & standards (LNPBP-4, 7, 8, 9, 81)
//
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the Apache 2.0 License along with this
// software. If not, see <https://opensource.org/licenses/Apache-2.0>.

use std::io;

use amplify::confinement::{Collection, Confined};
use strict_encoding::{
    StrictEncode, StrictEnum, StrictStruct, StrictTuple, StrictUnion,
    TypedWrite,
};

pub trait StrictCommit: StrictEncode {
    const COMMITMENT_TAG: &'static [u8];

    fn strict_commit(&self) -> [u8; 32];
}

pub struct CommitEncoder {}

impl TypedWrite for CommitEncoder {
    type TupleWriter = ();
    type StructWriter = ();
    type UnionDefiner = ();

    fn write_union<T: StrictUnion>(
        self,
        inner: impl FnOnce(Self::UnionDefiner) -> io::Result<Self>,
    ) -> io::Result<Self> {
        todo!()
    }

    fn write_enum<T: StrictEnum>(self, value: T) -> io::Result<Self>
    where
        u8: From<T>,
    {
        todo!()
    }

    fn write_tuple<T: StrictTuple>(
        self,
        inner: impl FnOnce(Self::TupleWriter) -> io::Result<Self>,
    ) -> io::Result<Self> {
        todo!()
    }

    fn write_struct<T: StrictStruct>(
        self,
        inner: impl FnOnce(Self::StructWriter) -> io::Result<Self>,
    ) -> io::Result<Self> {
        todo!()
    }

    // Fixed-length arrays and write_raw_bytes
    unsafe fn _write_raw<const MAX_LEN: usize>(
        self,
        bytes: impl AsRef<[u8]>,
    ) -> io::Result<Self> {
        // Do not merklize
        todo!()
    }

    /// Used by unicode strings, ASCII strings (excluding byte strings).
    unsafe fn write_string<const MAX_LEN: usize>(
        self,
        bytes: impl AsRef<[u8]>,
    ) -> io::Result<Self> {
        todo!()
    }

    /// Vec and sets - excluding strings, written by [`Self::write_string`], but
    /// including byte strings.
    unsafe fn write_collection<
        C: Collection,
        const MIN_LEN: usize,
        const MAX_LEN: usize,
    >(
        self,
        col: &Confined<C, MIN_LEN, MAX_LEN>,
    ) -> io::Result<Self>
    where
        for<'a> &'a C: IntoIterator,
        for<'a> <&'a C as IntoIterator>::Item: StrictEncode,
    {
        todo!()
    }

    // TODO: Move logic of encoding BTreeMap to TypedWrite trait in
    //       strict-encode
}
