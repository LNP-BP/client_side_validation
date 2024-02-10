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

use amplify::num::u24;
pub use ripemd::Ripemd160;
pub use sha2::{Digest, Sha256};

pub trait DigestExt<const BYTE_LEN: usize = 32>: Digest {
    fn from_tag(tag: impl AsRef<[u8]>) -> Self;
    fn input_raw(&mut self, data: &[u8]);
    fn input_with_len<const MAX: usize>(&mut self, data: &[u8]) {
        let len = data.len();
        match MAX {
            0..=0xFF => self.input_raw(&(len as u8).to_le_bytes()),
            0x100..=0xFFFF => self.input_raw(&(len as u16).to_le_bytes()),
            0x10000..=0xFFFFFF => self.input_raw(&u24::with(len as u32).to_le_bytes()),
            0x1000000..=0xFFFFFFFF => self.input_raw(&(len as u32).to_le_bytes()),
            _ => panic!("data too large"),
        }
        self.input_raw(data);
    }
    fn finish(self) -> [u8; BYTE_LEN];
}

impl DigestExt for Sha256 {
    fn from_tag(tag: impl AsRef<[u8]>) -> Self {
        let mut tagger = Sha256::default();
        tagger.update(tag);
        let tag = tagger.finalize();

        let mut engine = Sha256::default();
        engine.update(tag);
        engine.update(tag);
        engine
    }

    fn input_raw(&mut self, data: &[u8]) { self.update(data); }

    fn finish(self) -> [u8; 32] { self.finalize().into() }
}

impl DigestExt<20> for Ripemd160 {
    fn from_tag(tag: impl AsRef<[u8]>) -> Self {
        let mut tagger = Ripemd160::default();
        tagger.update(tag);
        let tag = tagger.finalize();

        let mut engine = Ripemd160::default();
        engine.update(tag);
        engine.update(tag);
        engine
    }

    fn input_raw(&mut self, data: &[u8]) { self.update(data); }

    fn finish(self) -> [u8; 20] { self.finalize().into() }
}
