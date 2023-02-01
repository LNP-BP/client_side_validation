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

use bitcoin_hashes::{sha256, Hash};

use crate::CommitEncode;

/// High-level API used in client-side validation for producing a single
/// commitment to the data, which includes running all necessary procedures like
/// concealment with [`CommitConceal`], merklization, strict encoding,
/// wrapped into [`CommitEncode`], followed by the actual commitment to its
/// output.
pub trait CommitmentId: CommitEncode {
    const TAG: sha256::Midstate;

    /// Type of the resulting commitment.
    type Id: From<sha256::Hash>;

    /// Performs commitment to client-side-validated data
    #[inline]
    fn commitment_id(&self) -> Self::Id {
        let mut engine = sha256::HashEngine::from_midstate(Self::TAG, 64);
        self.commit_encode(&mut engine);
        sha256::Hash::from_engine(engine).into()
    }
}
