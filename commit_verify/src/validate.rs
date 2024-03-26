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

use std::error::Error;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::ops::AddAssign;

pub trait Verifiable {
    fn is_valid(&self) -> bool;
    fn set_valid(&mut self);
    fn set_invalid(&mut self);
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct Valid<C: Verifiable, W: Display = String, I: Display = String> {
    pub content: C,
    pub warnings: Vec<W>,
    pub info: Vec<I>,
}

impl<C: Verifiable, W: Display, I: Display> Valid<C, W, I> {
    pub fn into_content(self) -> C { self.content }
    pub fn into_report<F: Error>(self) -> ValidationReport<F, W, I> { self.split().1 }
    pub fn to_report<F: Error>(&self) -> ValidationReport<F, W, I>
    where
        W: Clone,
        I: Clone,
    {
        ValidationReport {
            failures: vec![],
            warnings: self.warnings.clone(),
            info: self.info.clone(),
        }
    }
    pub fn split<F: Error>(self) -> (C, ValidationReport<F, W, I>) {
        (self.content, ValidationReport {
            failures: vec![],
            warnings: self.warnings,
            info: self.info,
        })
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct Invalid<C, F: Error, W: Display = String, I: Display = String> {
    pub content: C,
    pub failures: Vec<F>,
    pub warnings: Vec<W>,
    pub info: Vec<I>,
}

impl<C: Verifiable, F: Error, W: Display, I: Display> Invalid<C, F, W, I> {
    pub fn into_report(self) -> ValidationReport<F, W, I> {
        ValidationReport {
            failures: self.failures,
            warnings: self.warnings,
            info: self.info,
        }
    }
}

pub trait Validate {
    type Content: Verifiable;
    type Failure: Error;
    type Warning: Display;
    type Info: Display;
    type Context<'a>;

    fn validate(
        self,
        context: Self::Context<'_>,
    ) -> Result<
        Valid<Self::Content, Self::Warning, Self::Info>,
        Invalid<Self::Content, Self::Failure, Self::Warning, Self::Info>,
    >;
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct ValidationReport<F: Error, W: Display = String, I: Display = String> {
    pub failures: Vec<F>,
    pub warnings: Vec<W>,
    pub info: Vec<I>,
}

impl<F: Error, W: Display, I: Display> Default for ValidationReport<F, W, I> {
    fn default() -> Self {
        Self {
            failures: vec![],
            warnings: vec![],
            info: vec![],
        }
    }
}

impl<F: Error, W: Display, I: Display> Display for ValidationReport<F, W, I> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if !self.failures.is_empty() {
            f.write_str("Validation failures:\n")?;
            for fail in &self.failures {
                writeln!(f, "- {fail}")?;
            }
        }

        if !self.warnings.is_empty() {
            f.write_str("Validation warnings:\n")?;
            for warn in &self.warnings {
                writeln!(f, "- {warn}")?;
            }
        }

        if !self.info.is_empty() {
            f.write_str("Validation info:\n")?;
            for info in &self.info {
                writeln!(f, "- {info}")?;
            }
        }

        Ok(())
    }
}

impl<F: Error, W: Display, I: Display> AddAssign for ValidationReport<F, W, I> {
    fn add_assign(&mut self, rhs: Self) {
        self.failures.extend(rhs.failures);
        self.warnings.extend(rhs.warnings);
        self.info.extend(rhs.info);
    }
}

impl<F: Error, W: Display, I: Display> FromIterator<F> for ValidationReport<F, W, I> {
    fn from_iter<T: IntoIterator<Item = F>>(iter: T) -> Self {
        Self {
            failures: iter.into_iter().collect(),
            ..Self::default()
        }
    }
}

impl<F: Error, W: Display, I: Display> ValidationReport<F, W, I> {
    pub fn new() -> Self { Self::default() }

    pub fn with_failure(failure: impl Into<F>) -> Self {
        Self {
            failures: vec![failure.into()],
            ..Self::default()
        }
    }

    pub fn into_result<C: Verifiable>(
        self,
        content: C,
    ) -> Result<Valid<C, W, I>, Invalid<C, F, W, I>> {
        if self.is_valid() {
            Ok(Valid {
                content,
                warnings: self.warnings,
                info: self.info,
            })
        } else {
            Err(Invalid {
                content,
                failures: self.failures,
                warnings: self.warnings,
                info: self.info,
            })
        }
    }

    pub fn is_valid(&self) -> bool { self.failures.is_empty() }

    pub fn has_warnings(&self) -> bool { !self.warnings.is_empty() }

    pub fn add_failure(&mut self, failure: impl Into<F>) -> &Self {
        self.failures.push(failure.into());
        self
    }

    pub fn add_warning(&mut self, warning: impl Into<W>) -> &Self {
        self.warnings.push(warning.into());
        self
    }

    pub fn add_info(&mut self, info: impl Into<I>) -> &Self {
        self.info.push(info.into());
        self
    }
}
