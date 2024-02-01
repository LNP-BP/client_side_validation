// Client-side-validation foundation libraries.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use sha2::Sha256;
use strict_encoding::{StrictEncode, StrictType};
use strict_types::typesys::TypeFqn;

use crate::DigestExt;

pub struct CommitEngine {
    finished: bool,
    hasher: Sha256,
    layout: Vec<TypeFqn>,
}

impl CommitEngine {
    pub fn new(tag: &'static str) -> Self {
        Self {
            finished: false,
            hasher: Sha256::from_tag(tag),
            layout: vec![],
        }
    }

    pub fn commit_to<T: StrictEncode>(&mut self, value: &T) {
        debug_assert!(!self.finished);
        let ok = value.strict_write(usize::MAX, &mut self.hasher).is_ok();
        let fqn = TypeFqn::with(
            libname!(T::STRICT_LIB_NAME),
            T::strict_name().expect("commit encoder can commit only to named types"),
        );
        self.layout.push(fqn);
        debug_assert!(ok);
    }

    pub fn as_layout(&mut self) -> &[TypeFqn] {
        self.finished = true;
        self.layout.as_ref()
    }

    pub fn into_layout(self) -> Vec<TypeFqn> { self.layout }

    pub fn set_finished(&mut self) { self.finished = true; }

    pub fn finish(self) -> Sha256 { self.hasher }

    pub fn finish_layout(self) -> (Sha256, Vec<TypeFqn>) { (self.hasher, self.layout) }
}

/// Prepares the data to the *consensus commit* procedure by first running
/// necessary conceal and merklization procedures, and them performing strict
/// encoding for the resulted data.
pub trait CommitEncode {
    const COMMITMENT_TAG: &'static str;

    /// Type of the resulting commitment.
    type CommitmentId: From<Sha256> + StrictType;

    /// Encodes the data for the commitment by writing them directly into a
    /// [`io::Write`] writer instance
    fn commit_encode(&self, e: &mut CommitEngine);
}

#[derive(Getters, Clone, Eq, PartialEq, Hash, Debug)]
pub struct CommitmentLayout {
    ty: TypeFqn,
    tag: &'static str,
    fields: Vec<TypeFqn>,
}

/// High-level API used in client-side validation for producing a single
/// commitment to the data, which includes running all necessary procedures like
/// concealment with [`crate::Conceal`], merklization, strict encoding,
/// wrapped into [`CommitEncode`], followed by the actual commitment to its
/// output.
pub trait CommitmentId: CommitEncode {
    /// Type of the resulting commitment.
    type Id: From<Sha256>;

    fn commit(&self) -> CommitEngine;

    fn commitment_layout(&self) -> CommitmentLayout;

    /// Performs commitment to client-side-validated data
    fn commitment_id(&self) -> Self::Id;
}

impl<T: CommitEncode> CommitmentId for T {
    type Id = T::CommitmentId;

    fn commit(&self) -> CommitEngine {
        let mut engine = CommitEngine::new(T::COMMITMENT_TAG);
        self.commit_encode(&mut engine);
        engine.set_finished();
        engine
    }

    fn commitment_layout(&self) -> CommitmentLayout {
        let fields = self.commit().into_layout();
        CommitmentLayout {
            ty: TypeFqn::with(
                libname!(Self::CommitmentId::STRICT_LIB_NAME),
                Self::CommitmentId::strict_name()
                    .expect("commitment types must have explicit type name"),
            ),
            tag: T::COMMITMENT_TAG,
            fields,
        }
    }

    fn commitment_id(&self) -> Self::Id { self.commit().finish().into() }
}
