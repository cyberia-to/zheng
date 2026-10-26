//! Verifying keys of the recursive (5) and wrapped (6) profiles, as bytes
//! a caller may persist and hand back to a later process.
//!
//! Deriving a key means running the circuit that fixes its layout: the IVC
//! key of profile 5 takes a few hundred ms; the final key of profile 6
//! needs the whole wrap chain (minutes, tens of GB — the inner levels
//! commit their keys). [`export`] writes what a verifier needs as a
//! bundle of key layouts (`recursion::vkey`); [`install`] rebuilds the
//! keys from such a bundle in milliseconds and puts them in the process
//! caches, as if derived.
//!
//! ```text
//! bundle   tag "ZHKEYS01" · profile u8 · per key: varint length, layout
//!          profile 5: the IVC key (shipped parameters, steps of 2^15 rows)
//!          profile 6: the IVC key, then the final wrap level's key
//! ```
//!
//! Trust: a bundle is accepted only if its digest equals the one pinned
//! here for its profile ([`pinned`]); the pins are the digests of the
//! derived keys, checked by `tests/keys.rs` (and, for profile 6, by the
//! ignored chain test). A bundle from a cache directory is therefore as
//! good as a derivation, and a tampered or stale one is refused before it
//! is parsed — the caller then derives. Keys stay the verifier's own: a
//! bundle never travels with a proof.

use super::{Profile, recursive, wrapped};
use crate::recursion::ivc;
use crate::recursion::vkey;
use crate::recursion::wrap::WrapKey;

const TAG: &[u8; 8] = b"ZHKEYS01";

/// Digest of the profile-5 bundle (IVC key at rate 1/16, 2^15 rows).
pub const RECURSIVE_DIGEST: [u8; 32] = [
    0xd5, 0x1e, 0xe6, 0x29, 0xea, 0x6e, 0x51, 0xbb, 0x07, 0x23, 0x07, 0x07, 0xd4, 0x5f, 0x1b, 0x12,
    0x63, 0xc0, 0x64, 0x9b, 0x58, 0xbc, 0x7d, 0x90, 0xda, 0xc3, 0x83, 0x0b, 0xd9, 0x9b, 0x26, 0xa7,
];
/// Digest of the profile-6 bundle (the IVC key at rate 1/8 and 16
/// grinding bits and the final key of `wrap::SHIPPED`).
pub const WRAPPED_DIGEST: [u8; 32] = [
    0x67, 0xbb, 0x3c, 0x06, 0x29, 0x82, 0x19, 0x73, 0x58, 0xce, 0xfb, 0x04, 0x99, 0xee, 0x22, 0xe2,
    0xa3, 0xb3, 0x8a, 0x0c, 0xa0, 0xb1, 0x63, 0x39, 0x9d, 0x93, 0xb3, 0xfa, 0x89, 0x92, 0xda, 0xdd,
];

/// The pinned digest of a profile's bundle (profiles 5 and 6 only).
pub fn pinned(profile: Profile) -> Option<[u8; 32]> {
    match profile {
        Profile::Recursive => Some(RECURSIVE_DIGEST),
        Profile::Wrapped => Some(WRAPPED_DIGEST),
        _ => None,
    }
}

/// The bundle's digest (what [`pinned`] holds).
pub fn digest(bundle: &[u8]) -> [u8; 32] {
    vkey::digest(bundle)
}

fn bundle(profile: Profile, layouts: &[Vec<u8>]) -> Vec<u8> {
    let mut w = super::codec::Writer::default();
    w.raw(TAG);
    w.raw(&[profile as u8]);
    for l in layouts {
        w.len(l.len());
        w.raw(l);
    }
    w.bytes
}

/// The bundle of keys a verifier of `profile` needs, deriving them if the
/// process has not (profile 6 without an installed final key derives the
/// whole chain).
pub fn export(profile: Profile) -> Result<Vec<u8>, String> {
    let ikey = |whir: &lens::WhirParams| {
        recursive::pinned_key(whir, ivc::key(whir, recursive::STEP_LOG_ROWS as usize)?)
    };
    match profile {
        Profile::Recursive => Ok(bundle(
            profile,
            &[ikey(&recursive::params())?.layout_bytes()],
        )),
        Profile::Wrapped => Ok(bundle(
            profile,
            &[
                ikey(&wrapped::chain().0)?.layout_bytes(),
                wrapped::final_key()?.layout_bytes(),
            ],
        )),
        _ => Err("keys: only profiles 5 and 6 have cached keys".into()),
    }
}

/// Whether the keys a verifier of `profile` needs are in the process.
pub fn cached(profile: Profile) -> bool {
    let i = |whir: &lens::WhirParams| ivc::cached(whir, recursive::STEP_LOG_ROWS as usize);
    match profile {
        Profile::Recursive => i(&recursive::params()),
        Profile::Wrapped => i(&wrapped::chain().0) && wrapped::final_key_cached(),
        _ => false,
    }
}

/// Rebuild the keys of a bundle whose digest is pinned for its profile and
/// install them in the process caches; the bundle's profile is returned.
pub fn install(bytes: &[u8]) -> Result<Profile, String> {
    let profile = match bytes.get(TAG.len()) {
        Some(5) => Profile::Recursive,
        Some(6) => Profile::Wrapped,
        _ => return Err("keys: not a key bundle of profile 5 or 6".into()),
    };
    if bytes[..TAG.len()] != TAG[..] {
        return Err("keys: not a key bundle".into());
    }
    if Some(digest(bytes)) != pinned(profile) {
        return Err("keys: the bundle's digest is not the pinned one".into());
    }
    let e = |e: super::EnvelopeError| format!("keys: {e}");
    let mut r = super::codec::Reader::new(&bytes[TAG.len() + 1..]);
    let mut next = || -> Result<&[u8], String> {
        let n = r.len(usize::MAX, 1).map_err(e)?;
        r.raw(n).map_err(e)
    };
    let ik = ivc::Key::from_layout(next()?)?;
    let fk = if profile == Profile::Wrapped {
        Some(WrapKey::from_layout(next()?)?)
    } else {
        None
    };
    r.finish().map_err(e)?;
    ivc::install(ik);
    if let Some(k) = fk {
        wrapped::install_final(k)?;
    }
    Ok(profile)
}
