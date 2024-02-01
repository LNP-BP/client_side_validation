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
use strict_encoding::StrictType;
use strict_types::typesys::TypeFqn;

use crate::encode::CommitEngine;
use crate::CommitEncode;

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
