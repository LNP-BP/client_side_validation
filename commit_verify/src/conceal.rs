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
