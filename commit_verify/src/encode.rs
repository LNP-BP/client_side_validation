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
