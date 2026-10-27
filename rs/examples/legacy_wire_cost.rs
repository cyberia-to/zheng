//! Measure the two legacy statement fixtures used by exhaustive wire tests.
//! These are statement-only proofs, not execution certificates or ZK proofs.
use nebu::Goldilocks as F;
use nox::{NullCalls, Reduction, VecTrace};
use zheng::{HashAux, ProofParams, Statement};

fn main() {
    for hash in [false, true] {
        let mut arena = Reduction::<1024>::new();
        let subject = arena.atom(F::new(if hash { 42 } else { 0 })).unwrap();
        let one = arena.atom(F::new(1)).unwrap();
        let constant = if hash { subject } else { arena.atom(F::new(5)).unwrap() };
        let quote = arena.pair(one, constant).unwrap();
        let formula = if hash {
            let tag = arena.atom(F::new(15)).unwrap();
            arena.pair(tag, quote).unwrap()
        } else { quote };
        let mut trace = VecTrace::default();
        nox::reduce(&mut arena, subject, formula, 100, &NullCalls, &mut trace);
        if !hash { nox::reduce(&mut arena, subject, formula, 100, &NullCalls, &mut trace); }
        let mut aux = Vec::new();
        if hash {
            let d = arena.digest(subject).unwrap();
            aux.push(HashAux { rate: [d[0],d[1],d[2],d[3],F::ZERO,F::ZERO,F::ZERO,F::ZERO] });
        }
        let statement = Statement { program_hash: [0;32], input_hash: [0;32], output_hash: [0;32], focus_bound: 0, bbg_root: [0;32] };
        let params = ProofParams::default();
        let proof = zheng::commit(&trace, &aux, &[], &[], &statement, &params).unwrap();
        let wire = postcard::to_allocvec(&proof).unwrap();
        let start = std::time::Instant::now();
        for _ in 0..10 { zheng::verify(&proof, &statement, &params).unwrap(); }
        println!("groups={} bytes={} mutation_cases={} mean_untampered_verification_us={}",
            proof.group_count(), wire.len(), wire.len() * if hash { 2 } else { 8 }, start.elapsed().as_micros()/10);
    }
}
