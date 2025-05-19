// Client-side-validation foundation libraries.
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 LNP/BP Laboratories,
//                         Institute for Distributed and Cognitive Systems
// (InDCS), Switzerland. Copyright (C) 2019-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

/// Trait that should perform conversion of a given client-side-validated data
/// type into a concealed (private) form, for instance hiding some of the data
/// behind hashed - or homomorphically-encrypted version.
///
/// Since the resulting concealed version must be unequally derived from the
/// original data with negligible risk of collisions, it is a form of
/// *commitment*.
pub trait Conceal {
    /// The resulting confidential type concealing original data.
    type Concealed;

    /// Performs conceal procedure returning confidential data concealing
    /// original data.
    fn conceal(&self) -> Self::Concealed;
}
