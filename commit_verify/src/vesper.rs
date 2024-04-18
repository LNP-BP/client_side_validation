// Client-side-validation foundation libraries.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2024 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2024 LNP/BP Standards Association. All rights reserved.
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

use amplify::confinement::{Confined, SmallVec, TinyVec};
use strict_encoding::Ident;
use strict_types::layout::vesper::LenRange;
use strict_types::typesys::TypeFqn;
use vesper::{AttrVal, Attribute, Expression, Predicate, TExpr};

use crate::{CommitColType, CommitLayout, CommitStep};

pub type VesperCommit = TExpr<Pred>;

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display)]
#[display(lowercase)]
pub enum Pred {
    Commitment,
    Serialized,
    Hashed,
    Merklized,
    Concealed,
    List,
    Set,
    Element,
    Map,
    #[display("mapKey")]
    MapKey,
    #[display("mapValue")]
    MapValue,
}

impl Predicate for Pred {
    type Attr = Attr;
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum Attr {
    Tagged(&'static str),
    Concealed(TypeFqn),
    LenRange(LenRange),
    Hasher,
}
#[derive(Clone, Eq, PartialEq, Hash, Debug, Display)]
#[display(inner)]
pub enum AttrExpr {
    Tag(&'static str),
    LenRange(LenRange),
}

impl Expression for AttrExpr {}

impl Attribute for Attr {
    type Expression = AttrExpr;

    fn name(&self) -> Option<Ident> {
        match self {
            Attr::Tagged(_) => Some(ident!("tagged")),
            Attr::Concealed(_) => Some(ident!("concealed")),
            Attr::LenRange(_) => Some(ident!("len")),
            Attr::Hasher => Some(ident!("hasher")),
        }
    }

    fn value(&self) -> AttrVal<Self::Expression> {
        match self {
            Attr::Tagged(tag) => AttrVal::Expr(AttrExpr::Tag(tag)),
            Attr::Concealed(fqn) => AttrVal::Ident(fqn.name.to_ident()),
            Attr::LenRange(range) => AttrVal::Expr(AttrExpr::LenRange(range.clone())),
            Attr::Hasher => AttrVal::Ident(ident!("SHA256")),
        }
    }
}

impl CommitStep {
    fn subject(&self) -> Ident {
        match self {
            CommitStep::Serialized(fqn) => fqn,
            CommitStep::Collection(_, _, fqn) => fqn,
            CommitStep::Hashed(fqn) => fqn,
            CommitStep::Merklized(fqn) => fqn,
            CommitStep::Concealed(fqn) => fqn,
        }
        .name
        .to_ident()
    }

    fn predicate(&self) -> Pred {
        match self {
            CommitStep::Serialized(_) => Pred::Serialized,
            CommitStep::Collection(CommitColType::List, _, _) => Pred::List,
            CommitStep::Collection(CommitColType::Set, _, _) => Pred::Set,
            CommitStep::Collection(CommitColType::Map { .. }, _, _) => Pred::Map,
            CommitStep::Hashed(_) => Pred::Hashed,
            CommitStep::Merklized(_) => Pred::Merklized,
            CommitStep::Concealed(_) => Pred::Concealed,
        }
    }

    fn attributes(&self) -> SmallVec<Attr> {
        match self {
            CommitStep::Collection(_, sizing, _) => small_vec![Attr::LenRange((*sizing).into())],
            CommitStep::Concealed(from) => small_vec![Attr::Concealed(from.clone())],
            CommitStep::Serialized(_) | CommitStep::Hashed(_) | CommitStep::Merklized(_) => none!(),
        }
    }

    fn content(&self) -> TinyVec<Box<VesperCommit>> {
        match self {
            CommitStep::Collection(CommitColType::List, _, val) |
            CommitStep::Collection(CommitColType::Set, _, val) => {
                tiny_vec![Box::new(VesperCommit {
                    subject: val.name.to_ident(),
                    predicate: Pred::Element,
                    attributes: none!(),
                    content: none!(),
                    comment: None
                })]
            }
            CommitStep::Collection(CommitColType::Map { key }, _, val) => {
                tiny_vec![
                    Box::new(VesperCommit {
                        subject: key.name.to_ident(),
                        predicate: Pred::MapKey,
                        attributes: none!(),
                        content: none!(),
                        comment: None
                    }),
                    Box::new(VesperCommit {
                        subject: val.name.to_ident(),
                        predicate: Pred::MapValue,
                        attributes: none!(),
                        content: none!(),
                        comment: None
                    })
                ]
            }
            CommitStep::Serialized(_) |
            CommitStep::Hashed(_) |
            CommitStep::Merklized(_) |
            CommitStep::Concealed(_) => empty!(),
        }
    }
}

impl CommitLayout {
    pub fn to_vesper(&self) -> VesperCommit {
        let subject = self.idty().name.to_ident();

        // SecretSeal commitment tagged=""
        //     BlindSeal rec serialized

        let content = self.fields().iter().map(|field| {
            Box::new(VesperCommit {
                subject: field.subject(),
                predicate: field.predicate(),
                attributes: field.attributes(),
                content: field.content(),
                comment: None,
            })
        });

        VesperCommit {
            subject,
            predicate: Pred::Commitment,
            attributes: confined_vec![Attr::Hasher, Attr::Tagged(self.tag())],
            content: Confined::from_iter_unsafe(content),
            comment: None,
        }
    }
}
