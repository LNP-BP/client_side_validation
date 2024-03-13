// Client-side-validation foundation libraries.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
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

use std::fmt::{self, Debug, Display, Formatter};
use std::hash::Hash;
use std::ops::AddAssign;

/// Result of client-side validation operation
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(u8)]
pub enum Validity {
    /// The data are valid both in terms of the internal consistency and in
    /// terms of commitments in the single-use-seals medium
    Valid = 1,

    /// The data are internally consistent and valid, but there were (multiple)
    /// issues with resolving single-use-seals reported by the provided seal
    /// resolver. These issues are not failed single-use-seals, but rather
    /// errors accessing single-use-seals commitment medium about its status
    /// (networking issues, transaction present in mempool and
    /// not yet mined etc).
    SealIssues = 0xFF,

    /// The data are internally inconsistent/invalid
    Invalid = 0,
}

impl Display for Validity {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Validity::Valid => f.write_str("valid"),
            Validity::SealIssues => f.write_str("unresolved seal issues"),
            Validity::Invalid => f.write_str("invalid"),
        }
    }
}

#[cfg(not(feature = "serde"))]
/// Marker trait for all types of validation log entries (failures, trust
/// issues, warnings, info messages) contained within a [`ValidationReport`]
/// produced during client-side-validation.
pub trait ValidationLog: Clone + Eq + Hash + Debug + Display {}

#[cfg(feature = "serde")]
/// Marker trait for all types of validation log entries (failures, trust
/// issues, warnings, info messages) contained within a [`ValidationReport`]
/// produced during client-side-validation.
pub trait ValidationLog:
    Clone + Eq + Hash + Debug + Display + serde::Serialize + for<'de> serde::Deserialize<'de>
{
}

/// Trait for concrete implementations of seal resolution issues reported by
/// [`SealResolver`]s during client-side-validation process
pub trait SealIssue: ValidationLog + std::error::Error {
    /// Type defining single-use-seals used by the client-side-validated data
    /// and the seal resolver
    type Seal;

    /// Method returning single-use-seal specific to the reported issue
    fn seal(&self) -> &Self::Seal;
}

/// Validation failures marker trait indicating that the data had not passed
/// client-side-validation and must not be accepted by the client. This does not
/// cover issues related to single-use-seal status, which are covered by
/// [`SealIssue`] type
pub trait ValidationFailure: ValidationLog + std::error::Error {}

/// Trait combining different forms of client-side-validation reporting as into
/// a single type pack
pub trait ValidationReport {
    /// Reports on seal resolution issues, for instance produced by failing
    /// accessing the single-use-seals or its medium or inability to
    /// determine whether a given seal was closed.
    type SealIssue: SealIssue;

    /// Internal client-side-validated data inconsistency/invalidity codes and
    /// reports
    type Failure: ValidationFailure;

    #[cfg(not(feature = "serde"))]
    /// Issues which does not render client-side-validated data invalid, but
    /// which should be reported to the user anyway
    type Warning: Clone + Eq + Hash + Debug + Display;

    #[cfg(feature = "serde")]
    /// Issues which does not render client-side-validated data invalid, but
    /// which should be reported to the user anyway
    type Warning: Clone
        + Eq
        + Hash
        + Debug
        + Display
        + serde::Serialize
        + for<'de> serde::Deserialize<'de>;

    #[cfg(not(feature = "serde"))]
    /// Information reports about client-side-validation, which do not affect
    /// data safety or validity and may not be presented to the user
    type Info: Clone + Eq + Hash + Debug + Display;

    #[cfg(feature = "serde")]
    /// Information reports about client-side-validation, which do not affect
    /// data safety or validity and may not be presented to the user
    type Info: Clone
        + Eq
        + Hash
        + Debug
        + Display
        + serde::Serialize
        + for<'de> serde::Deserialize<'de>;
}

/// Client-side-validation status containing all reports from the validation
/// process
#[derive(Clone, PartialEq, Eq, Hash, Debug, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Status<R>
where R: ValidationReport
{
    /// List of seal resolver reported issues (see [`SealIssue`] trait for
    /// details).
    pub seal_issues: Vec<R::SealIssue>,

    /// Failures generated during client-side-validation.
    ///
    /// When the failure happens, the process of client-side-validation is not
    /// stopped and proceeds to the rest of data items, such that there might
    /// be a multiple validation failures stored in this array.
    ///
    /// Does not include issues from single-use-seal resolution, which are
    /// stored in [`Status::seal_issues`] and must be handled separately.
    pub failures: Vec<R::Failure>,

    /// Warnings generated during client-side-validation.
    ///
    /// Warnings are issues which does not render client-side-validated data
    /// invalid, but which should be reported to the user anyway
    ///
    /// See also [`ValidationReport::Warning`].
    pub warnings: Vec<R::Warning>,

    /// Information reports about client-side-validation, which do not affect
    /// data safety or validity and may not be presented to the user
    ///
    /// See also [`ValidationReport::Info`].
    pub info: Vec<R::Info>,
}

impl<R> AddAssign for Status<R>
where R: ValidationReport
{
    fn add_assign(&mut self, rhs: Self) {
        self.seal_issues.extend(rhs.seal_issues);
        self.failures.extend(rhs.failures);
        self.warnings.extend(rhs.warnings);
        self.info.extend(rhs.info);
    }
}

impl<R> FromIterator<R::Failure> for Status<R>
where R: ValidationReport
{
    fn from_iter<T: IntoIterator<Item = R::Failure>>(iter: T) -> Self {
        Status {
            seal_issues: vec![],
            failures: iter.into_iter().collect(),
            warnings: vec![],
            info: vec![],
        }
    }
}

impl<R> Status<R>
where R: ValidationReport
{
    /// Constructs empty status report
    pub fn new() -> Self {
        Status {
            seal_issues: vec![],
            failures: vec![],
            warnings: vec![],
            info: vec![],
        }
    }

    /// Constructs status report from a single failure with the rest of log
    /// lists set to the empty state.
    pub fn from_failure(failure: R::Failure) -> Self {
        Status {
            seal_issues: vec![],
            failures: vec![failure],
            warnings: vec![],
            info: vec![],
        }
    }

    /// Adds a single [`SealIssue`] to the validation report logs
    pub fn add_seal_issue(&mut self, seal_issue: R::SealIssue) -> &Self {
        self.seal_issues.push(seal_issue);
        self
    }

    /// Adds a single [`ValidationFailure`] to the validation report logs
    pub fn add_failure(&mut self, failure: R::Failure) -> &Self {
        self.failures.push(failure);
        self
    }

    /// Adds a single warning entry to the validation report logs. See
    /// [`ValidationReport::Warning`] for more details about warnings.
    pub fn add_warning(&mut self, warning: R::Warning) -> &Self {
        self.warnings.push(warning);
        self
    }

    /// Adds a single information record to the validation report logs. See
    /// [`ValidationReport::Info`] for more details about information log
    /// entries.
    pub fn add_info(&mut self, info: R::Info) -> &Self {
        self.info.push(info);
        self
    }

    /// Returns validity of the client-side data deduced from the current status
    /// containing all reported issues.
    ///
    /// Client-side data are valid ([`Validity::Valid`] status) only and only if
    /// the status report contains no validation failures and seal resolution
    /// issues.
    ///
    /// See also [`Validity`] for the details of possible validation statuses.
    pub fn validity(&self) -> Validity {
        if !self.failures.is_empty() {
            Validity::Invalid
        } else if !self.seal_issues.is_empty() {
            Validity::SealIssues
        } else {
            Validity::Valid
        }
    }
}

/// This simple trait MUST be used by all top-level data structures implementing
/// client-side validation paradigm. The core concept of this paradigm is that a
/// client must have a complete and uniform set of data, which can be
/// represented or accessed through a single structure; and MUST be able to
/// deterministically validate this set giving an external validation function,
/// that is able to provide validator with
pub trait ClientSideValidate<'client_data>: ClientData<'client_data>
where Self::ValidationItem: 'client_data
{
    /// Data type for data sub-entries contained withing the current
    /// client-side-validated data item.
    ///
    /// If the client-side-validated data contain different types of internal
    /// entries, this may be a special enum type with a per-data-type variant.
    ///
    /// If the data do not contain internal data, set this type to `()`.
    type ValidationItem: ClientData<'client_data, ValidationReport = Self::ValidationReport>;

    /// Iterator over the list of specific validation items.
    ///
    /// If the client-side-validated data contain different types of internal
    /// entries, this may be a special enum type with a per-data-type variant.
    type ValidationIter: Iterator<Item = &'client_data Self::ValidationItem>;

    /// The mein method performing client-side-validation for the whole block of
    /// client-side-validated data.
    ///
    /// The default implementation of the trait iterates over
    /// client-side-validated data hierarchy using iterator returned by
    /// [`ClientSideValidate::validation_iter`] and for each of the items
    /// - validates internal data consistency with
    ///   [`ClientData::validate_internal_consistency`] method,
    /// - validates single-use-seal for the item using the provided `resolver`
    ///   object,
    /// adding reported issues to the [`Status`] log returned by the function.
    ///
    /// The function should not fail on any validation failures and run the
    /// whole validation process up to the end, accumulating all failures and
    /// reported issues withing [`Status`] object, returned by the function at
    /// the end.
    fn client_side_validate<Resolver>(
        &'client_data self,
        resolver: &'client_data mut Resolver,
    ) -> Status<Self::ValidationReport>
    where
        Resolver: SealResolver<
            <<<Self as ClientData<'client_data>>::ValidationReport as ValidationReport>::SealIssue as SealIssue>::Seal,
            Error = <<Self as ClientData<'client_data>>::ValidationReport as ValidationReport>::SealIssue,
        >,
    {
        let mut status = Status::new();

        status += self.validate_internal_consistency();
        for item in self.validation_iter() {
            for seal in item.single_use_seals() {
                let _ = resolver
                    .resolve_trust(seal)
                    .map_err(|issue| status.add_seal_issue(issue));
            }
            status += item.validate_internal_consistency();
        }

        status
    }

    /// Returns iterator over hierarchy of individual data items inside
    /// client-side-validation data.
    fn validation_iter(&'client_data self) -> Self::ValidationIter;
}

/// Marker trait for client-side-validation data at any level of data hierarchy.
pub trait ClientData<'client_data>
where Self: 'client_data
{
    /// Data type that stores validation report configuration for the validation
    /// [`Status`] object.
    ///
    /// This type defines also a type of single-use-seals via
    /// [`ValidationReport::SealIssue`]`<Seal>`.
    type ValidationReport: ValidationReport;

    /// Iterator over single-use-seals belonging to a specific validation item.
    type SealIterator: Iterator<Item = &'client_data <<Self::ValidationReport as ValidationReport>::SealIssue as SealIssue>::Seal>;

    /// Method returning iterator over single-use-seal references corresponding
    /// to the current piece of client-side-validated data.
    fn single_use_seals(&'client_data self) -> Self::SealIterator;

    /// Validates internal consistency of the current client-side-validated data
    /// item. Must not validate any single-use-seals or commitments against
    /// external commitment mediums.
    ///
    /// The method should not iterate over internal data items and go deeper
    /// inside the data hierarchy and must validate only data related to the
    /// single current item. The iteration is performed at higher levels,
    /// normally as a part of [`ClientSideValidate::client_side_validate`]
    /// method logic.
    fn validate_internal_consistency(&'client_data self) -> Status<Self::ValidationReport>;
}

/// Seal resolver validates seal to have `closed` status, or reports
/// [`SealResolver::Error`] otherwise, if the seal does not have a determined
/// status or there was a error accessing seal commitment medium. The reported
/// error does not necessary implies that the seal is not closed and the final
/// decision about seal status must be solved at upper protocol levels or by a
/// informed user action.
///
/// Seal resolution MUST always produce a singular success type (defined by
/// `()`) or fail with a well-defined type of [`SealResolver::Error`].
///
/// Seal resolver may have an internal state (represented by `self` reference)
/// and it does not require to produce a deterministic result for the same
/// given data piece and context: the seal resolver may depend on previous
/// operation history and depend on type and other external parameters.
pub trait SealResolver<Seal> {
    /// Error type returned by [`SealResolver::resolve_trust`], which should
    /// cover both errors in accessing single-use-seal medium (like network
    /// connectivity) or evidences of the facts the seal was not (yet) closed.
    type Error: SealIssue<Seal = Seal>;

    /// Resolves trust to the provided single-use-seal.
    ///
    /// The method mutates resolver such that it can be able to store cached
    /// data from a single-use-seal medium.
    ///
    /// Method must fail on both errors in accessing single-use-seal medium
    /// (like network connectivity) or if the seal is not (yet) closed.
    fn resolve_trust(&mut self, seal: &Seal) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod test {
    //! Tests use emulation of a simple client-side-validated state, consisting
    //! of an array of data items, each of which has a name bound to a certain
    //! bitcoin single-use-seal.

    use single_use_seals::{SealProtocol, SealStatus, SealWitness};

    use super::*;

    #[test]
    fn test() {
        #![allow(dead_code)]

        #[derive(Clone, PartialEq, Eq, Hash, Debug, Default)]
        #[derive(Serialize, Deserialize)]
        #[serde(crate = "serde_crate")]
        struct Seal {}

        struct Protocol {}

        impl SealProtocol<Seal> for Protocol {
            type Witness = ();
            type Message = Vec<u8>;
            type PublicationId = ();
            type Error = Issue;

            fn get_seal_status(&self, _seal: &Seal) -> Result<SealStatus, Self::Error> {
                Ok(SealStatus::Undefined)
            }
        }

        impl SealWitness<Seal> for () {
            type Message = Vec<u8>;
            type Error = Issue;

            fn verify_seal(&self, _seal: &Seal, _msg: &Self::Message) -> Result<(), Self::Error> {
                Ok(())
            }
        }

        #[derive(Clone, PartialEq, Eq, Hash, Debug)]
        struct Report {}

        #[derive(Clone, PartialEq, Eq, Hash, Debug)]
        #[derive(Serialize, Deserialize)]
        #[serde(crate = "serde_crate")]
        struct Issue {
            seal: Seal,
        }
        impl Display for Issue {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { f.write_str("") }
        }
        impl std::error::Error for Issue {}

        impl ValidationLog for Issue {}

        impl ValidationFailure for Issue {}

        impl SealIssue for Issue {
            type Seal = Seal;

            fn seal(&self) -> &Self::Seal { &self.seal }
        }

        impl ValidationReport for Report {
            type SealIssue = Issue;
            type Failure = Issue;
            type Warning = Issue;
            type Info = Issue;
        }

        #[derive(Default)]
        struct Data {
            seals: Vec<Seal>,
        }

        impl<'a> ClientData<'a> for Data
        where Data: 'a
        {
            type ValidationReport = Report;
            type SealIterator = std::slice::Iter<'a, Seal>;

            fn single_use_seals(&'a self) -> Self::SealIterator { self.seals.iter() }

            fn validate_internal_consistency(&self) -> Status<Self::ValidationReport> {
                Status::new()
            }
        }

        struct State {
            pub data: Vec<Data>,
        }

        impl<'a> ClientData<'a> for State {
            type ValidationReport = Report;
            type SealIterator = std::slice::Iter<'a, Seal>;

            fn single_use_seals(&self) -> Self::SealIterator { [].iter() }

            fn validate_internal_consistency(&self) -> Status<Self::ValidationReport> {
                Status::new()
            }
        }

        impl<'a> ClientSideValidate<'a> for State {
            type ValidationItem = Data;
            type ValidationIter = std::slice::Iter<'a, Data>;

            fn validation_iter(&'a self) -> Self::ValidationIter { self.data.iter() }
        }

        #[derive(Default)]
        struct Resolver {}

        impl SealResolver<Seal> for Resolver {
            type Error = Issue;

            fn resolve_trust(&mut self, _seal: &Seal) -> Result<(), Self::Error> { Ok(()) }
        }

        let state = State {
            data: vec![Data::default()],
        };
        let mut resolver = Resolver::default();
        let status = state.client_side_validate(&mut resolver);
        assert_eq!(status, Status::new());
    }
}
