//! Derive the verifying keys of profiles 5 and 6, print their bundles'
//! digests (the pins of `envelope::keys`) and sizes, and time rebuilding
//! the keys from their layouts.
//!
//! `cargo run --release -p zheng --example wrap_keys -- [out-dir]`
//! writes `recursive.keys` and `wrapped.keys` to `out-dir` when given.
//! `ZHENG_PROFILES=5` skips the wrap chain (minutes, tens of GB).
//! Profile 6 derives the prover's chain (printing the inner levels' key
//! roots: `wrapped::INNER_ROOTS`) unless `ZHENG_VERIFIER=1`, which times
//! the verifier's derivation over the pinned roots instead.

use std::time::Instant;
use zheng::envelope::{Profile, keys};
use zheng::recursion::ivc;
use zheng::recursion::wrap::WrapKey;

fn hex(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e3
}

fn main() {
    let out = std::env::args().nth(1);
    let profiles: Vec<u8> = std::env::var("ZHENG_PROFILES")
        .ok()
        .map(|v| v.split(',').filter_map(|p| p.parse().ok()).collect())
        .unwrap_or_else(|| vec![5, 6]);
    for p in profiles {
        let profile = if p == 5 { Profile::Recursive } else { Profile::Wrapped };
        if p == 6 {
            let t = Instant::now();
            if std::env::var_os("ZHENG_VERIFIER").is_some() {
                zheng::envelope::wrapped::final_key().expect("final key");
                println!("profile 6: verifier key derivation over pinned roots {:.0} ms", ms(t));
            } else {
                match zheng::envelope::wrapped::chain_keys() {
                    Ok(_) => println!("profile 6: prover chain {:.0} ms (roots match the pins)", ms(t)),
                    Err(e) => println!("profile 6: prover chain {:.0} ms: {e}", ms(t)),
                }
            }
        }
        let t = Instant::now();
        let bundle = keys::export(profile).expect("export");
        let derive = ms(t);
        let digest = keys::digest(&bundle);
        println!("profile {p}: derive {derive:.0} ms · bundle {} B · digest {}", bundle.len(), hex(&digest));
        // the layouts rebuild keys whose layouts are the same bytes
        let ik = ivc::key(&zheng::envelope::recursive::params(), 15).expect("ivc key");
        let t = Instant::now();
        let lb = ik.layout_bytes();
        let back = ivc::Key::from_layout(&lb).expect("ivc layout");
        println!("  ivc layout {} B · rebuild {:.1} ms · round trip {}", lb.len(), ms(t), back.layout_bytes() == lb);
        if p == 6 {
            let fk = zheng::envelope::wrapped::final_key().expect("final key");
            let t = Instant::now();
            let lb = fk.layout_bytes();
            let back = WrapKey::from_layout(&lb).expect("wrap layout");
            println!(
                "  final layout {} B · rebuild {:.1} ms · round trip {} · g nodes {} = {}",
                lb.len(),
                ms(t),
                back.layout_bytes() == lb,
                back.g.nodes.len(),
                fk.g.nodes.len()
            );
        }
        let t = Instant::now();
        let _ = keys::digest(&bundle);
        println!("  digest {:.1} ms", ms(t));
        if let Some(dir) = &out {
            let name = if p == 5 { "recursive.keys" } else { "wrapped.keys" };
            std::fs::write(format!("{dir}/{name}"), &bundle).expect("write");
        }
    }
}
