// LNP/BP client-side-validation foundation libraries implementing LNPBP
// specifications & standards (LNPBP-4, 7, 8, 9, 42, 81)
//
// Written in 2019-2021 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the Apache 2.0 License along with this
// software. If not, see <https://opensource.org/licenses/Apache-2.0>.

/// Macro simplifying encoding for a given list of items
#[macro_export]
macro_rules! strict_encode_list {
    ( $encoder:ident; $($item:expr),+ ) => {
        {
            let mut len = 0usize;
            $(
                len += $item.strict_encode(&mut $encoder)?;
            )+
            len
        }
    };

    ( $encoder:ident; $len:ident; $($item:expr),+ ) => {
        {
            $(
                $len += $item.strict_encode(&mut $encoder)?;
            )+
            $len
        }
    }
}

/// Macro simplifying decoding of a structure with a given list of fields
#[macro_export]
macro_rules! strict_decode_self {
    ( $decoder:ident; $($item:ident),+ ) => {
        {
            Self {
            $(
                $item: ::strict_encoding::StrictDecode::strict_decode(&mut $decoder)?,
            )+
            }
        }
    };
    ( $decoder:ident; $($item:ident),+ ; crate) => {
        {
            Self {
            $(
                $item: $crate::StrictDecode::strict_decode(&mut $decoder)?,
            )+
            }
        }
    };
}
