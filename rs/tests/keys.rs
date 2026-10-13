//! Verifying-key bundles of profiles 5 and 6: the pinned digests are the
//! digests of the keys zheng derives; a bundle rebuilds keys whose layouts
//! are its own bytes; a tampered bundle is refused before it is parsed.
//!
//! The profile-6 keys here are derived over the pinned inner roots; that
//! those roots are the ones the prover commits is checked by the ignored
//! `the_pinned_inner_roots_are_the_derived_ones` (the whole chain: minutes,
//! ~30 GB).

use zheng::envelope::{Profile, keys, recursive, wrapped};
use zheng::recursion::ivc;
use zheng::recursion::wrap::WrapKey;

#[test]
fn the_pinned_digests_are_the_derived_keys() {
    for profile in [Profile::Recursive, Profile::Wrapped] {
        let bundle = keys::export(profile).unwrap();
        assert_eq!(Some(keys::digest(&bundle)), keys::pinned(profile), "{profile:?}");
        assert_eq!(keys::install(&bundle), Ok(profile));
        assert!(keys::cached(profile));
    }
    assert!(keys::export(Profile::Machine).is_err());
}

#[test]
fn layouts_rebuild_the_same_keys() {
    let ik = ivc::key(&recursive::params(), recursive::STEP_LOG_ROWS as usize).unwrap();
    let lb = ik.layout_bytes();
    let back = ivc::Key::from_layout(&lb).unwrap();
    assert_eq!(back.layout_bytes(), lb);
    assert_eq!(back.kw_root, ik.kw_root);
    assert_eq!(back.sparse, ik.sparse);
    assert_eq!(back.g.nodes.len(), ik.g.nodes.len());
    // the words a prover commits from a rebuilt key have the key's root
    assert_eq!(back.words().root, ik.kw_root);
    let fk = wrapped::final_key().unwrap();
    let lb = fk.layout_bytes();
    let back = WrapKey::from_layout(&lb).unwrap();
    assert_eq!(back.layout_bytes(), lb);
    assert_eq!(back.params, fk.params);
    assert_eq!(back.cfg, fk.cfg);
    assert_eq!(back.next_cols, fk.next_cols);
    assert_eq!(back.sparse, fk.sparse);
    let (a, b) = (back.wiring.as_ref().unwrap(), fk.wiring.as_ref().unwrap());
    assert_eq!((a.reads, &a.read_cells, &a.write_reads, &a.write_at, &a.write_cells), (b.reads, &b.read_cells, &b.write_reads, &b.write_at, &b.write_cells));
    // every truncation and a trailing byte of a layout are refused
    for cut in (0..lb.len()).step_by(997).chain(lb.len() - 3..lb.len()) {
        assert!(WrapKey::from_layout(&lb[..cut]).is_err(), "cut {cut}");
    }
    let mut longer = lb.clone();
    longer.push(0);
    assert!(WrapKey::from_layout(&longer).is_err());
}

#[test]
fn a_tampered_bundle_is_refused() {
    let bundle = keys::export(Profile::Recursive).unwrap();
    for at in [0, 8, 9, 10, bundle.len() / 2, bundle.len() - 1] {
        let mut bad = bundle.clone();
        bad[at] ^= 1;
        assert!(keys::install(&bad).is_err(), "byte {at}");
    }
    assert!(keys::install(&bundle[..bundle.len() - 1]).is_err());
    let mut longer = bundle.clone();
    longer.push(0);
    assert!(keys::install(&longer).is_err());
    assert!(keys::install(&[]).is_err());
    // a profile-5 bundle relabelled as profile 6
    let mut bad = bundle.clone();
    bad[8] = 6;
    assert!(keys::install(&bad).is_err());
}

#[test]
#[ignore = "derives the whole wrap chain: minutes, ~30 GB"]
fn the_pinned_inner_roots_are_the_derived_ones() {
    // the prover's derivation commits the inner keys and checks their
    // roots against the pins; its final key is then the cache's
    wrapped::chain_keys().unwrap();
    let bundle = keys::export(Profile::Wrapped).unwrap();
    assert_eq!(Some(keys::digest(&bundle)), keys::pinned(Profile::Wrapped));
}
