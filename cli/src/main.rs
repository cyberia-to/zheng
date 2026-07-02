// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! zheng command-line interface — see specs/cli.md.
//!
//! Drives the library's entry points from a shell and emits results as a
//! [[tape]] chunk stream on stdout (with a human summary on stderr).

mod capsule;
mod formula;
mod tape_out;

use std::time::Instant;

use nebu::Goldilocks;
use nox::{NullCalls, Reduction, VecTrace};
use zheng::{
    AxisOpening, HashAux, LookOpening, ProofParams, Statement, TraceProof,
};

use formula::ORDER_SIZE;

fn main() {
    // Reduction<65536> plus reduction recursion overflows the default stack;
    // run everything under a thread with an explicit large stack (mirrors nox).
    let code = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(run)
        .expect("failed to spawn zheng thread")
        .join()
        .expect("zheng thread panicked");
    std::process::exit(code);
}

fn run() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");
    let code = match cmd {
        "run" => cmd_run(&args[2..]),
        "demo" => cmd_demo(&args[2..]),
        "eval" => cmd_eval(),
        "pack" => cmd_pack(&args[2..]),
        "prove" => cmd_prove(&args[2..]),
        "help" | "-h" | "--help" => { print_help(); 0 }
        other => { tape_out::error(&format!("unknown command '{other}'")); usage_hint(); 2 }
    };
    tape_out::status(code);
    code
}

// ── run ────────────────────────────────────────────────────────────────────

fn cmd_run(args: &[String]) -> i32 {
    let opts = match Opts::parse(args) {
        Ok(o) => o,
        Err(e) => { tape_out::error(&e); return 2; }
    };
    let Some(formula_text) = opts.formula else {
        tape_out::error("run requires -e '<formula>'");
        return 2;
    };
    let mut reduction = Reduction::<ORDER_SIZE>::new();
    let object = match reduction.atom(Goldilocks::new(opts.object)) {
        Some(o) => o,
        None => { tape_out::error("order arena full building object"); return 1; }
    };
    let root = match formula::parse(&mut reduction, &formula_text) {
        Ok(r) => r,
        Err(e) => { tape_out::error(&e); return 2; }
    };
    let mut trace = VecTrace::default();
    let _ = nox::reduce(&mut reduction, object, root, opts.budget, &NullCalls, &mut trace);
    prove_and_report(&format!("run {formula_text}"), &trace, &[], &[], &[])
}

// ── demo ───────────────────────────────────────────────────────────────────

fn cmd_demo(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("hash") => demo_hash(),
        Some(other) => { tape_out::error(&format!("unknown demo '{other}' (try: hash)")); 2 }
        None => { tape_out::error("demo requires a name (try: hash)"); 2 }
    }
}

/// Prove `[15 [1 s]]` — a Poseidon2 hash of subject `s` — with the HashAux rate
/// derived from `s`'s structural digest. Mirrors the library's hash e2e test.
fn demo_hash() -> i32 {
    let mut r = Reduction::<ORDER_SIZE>::new();
    let g = Goldilocks::new;
    let (s, t1, t15) = match (r.atom(g(42)), r.atom(g(1)), r.atom(g(15))) {
        (Some(s), Some(a), Some(b)) => (s, a, b),
        _ => { tape_out::error("order arena full"); return 1; }
    };
    let quote = r.pair(t1, s).unwrap();
    let hash_f = r.pair(t15, quote).unwrap();

    let mut trace = VecTrace::default();
    let _ = nox::reduce(&mut r, s, hash_f, 100, &NullCalls, &mut trace);

    let digest = match r.digest(s) {
        Some(d) => *d,
        None => { tape_out::error("no digest for subject"); return 1; }
    };
    let z = Goldilocks::ZERO;
    let rate = [digest[0], digest[1], digest[2], digest[3], z, z, z, z];
    let aux = HashAux { rate };
    prove_and_report("demo hash [15 [1 42]]", &trace, &[aux], &[], &[])
}

// ── eval (PCS) ───────────────────────────────────────────────────────────────

fn cmd_eval() -> i32 {
    let params = ProofParams::default();
    let g = Goldilocks::new;
    let poly = [g(3), g(7), g(11), g(19)];
    let point = [g(2), g(5)];
    let expected = lens::MultilinearPoly::new(poly.to_vec()).evaluate(&point);

    let (commitment, opening) = match zheng::open(&poly, &point, &params) {
        Ok(v) => v,
        Err(e) => { tape_out::error(&format!("open failed: {e:?}")); return 1; }
    };
    let verified = zheng::verify_eval(&commitment, &point, expected, &opening, &params).is_ok();
    tape_out::report("eval (Brakedown PCS)", &[
        ("point", format!("[{}, {}]", point[0].as_u64(), point[1].as_u64())),
        ("value", expected.as_u64().to_string()),
        ("verify", if verified { "ok" } else { "fail" }.to_string()),
    ]);
    if verified { 0 } else { 1 }
}

// ── pack / prove (program capsule) ───────────────────────────────────────────

fn cmd_pack(args: &[String]) -> i32 {
    let opts = match Opts::parse(args) {
        Ok(o) => o,
        Err(e) => { tape_out::error(&e); return 2; }
    };
    let (Some(formula), Some(out)) = (opts.formula, opts.output) else {
        tape_out::error("pack requires -e '<formula>' and -o <file>");
        return 2;
    };
    let prog = capsule::Program { formula, object: opts.object, budget: opts.budget };
    match std::fs::write(&out, capsule::encode(&prog)) {
        Ok(()) => {
            tape_out::report("pack", &[
                ("file", out),
                ("formula", prog.formula),
            ]);
            0
        }
        Err(e) => { tape_out::error(&format!("write {out}: {e}")); 1 }
    }
}

fn cmd_prove(args: &[String]) -> i32 {
    let Some(path) = args.first() else {
        tape_out::error("prove requires a capsule file path");
        return 2;
    };
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => { tape_out::error(&format!("read {path}: {e}")); return 1; }
    };
    let prog = match capsule::decode(&bytes) {
        Ok(p) => p,
        Err(e) => { tape_out::error(&e); return 1; }
    };
    let mut reduction = Reduction::<ORDER_SIZE>::new();
    let object = match reduction.atom(Goldilocks::new(prog.object)) {
        Some(o) => o,
        None => { tape_out::error("order arena full building object"); return 1; }
    };
    let root = match formula::parse(&mut reduction, &prog.formula) {
        Ok(r) => r,
        Err(e) => { tape_out::error(&e); return 1; }
    };
    let mut trace = VecTrace::default();
    let _ = nox::reduce(&mut reduction, object, root, prog.budget, &NullCalls, &mut trace);
    prove_and_report(&format!("prove {}", prog.formula), &trace, &[], &[], &[])
}

// ── shared: prove a trace, verify, report ────────────────────────────────────

fn prove_and_report(
    title: &str,
    trace: &VecTrace,
    hash_aux: &[HashAux],
    axis: &[AxisOpening],
    look: &[LookOpening],
) -> i32 {
    // A trace row tagged 0 / 15 / 17 (axis / hash / look) needs an opening proof.
    // Report that precisely rather than letting commit() surface an opaque error.
    let (axis_rows, hash_rows, look_rows) = opening_pattern_counts(trace);
    let missing = (axis_rows > 0 && axis.is_empty())
        || (hash_rows > 0 && hash_aux.is_empty())
        || (look_rows > 0 && look.is_empty());
    if missing {
        tape_out::error(&format!(
            "trace needs opening data this path does not derive \
             (axis={axis_rows}, hash={hash_rows}, look={look_rows}; \
             trace rows: {}). try 'zheng demo hash'.",
            trace.0.len()
        ));
        return 1;
    }

    let stmt = zero_statement();
    let params = ProofParams::default();

    let t0 = Instant::now();
    let proof = match zheng::commit(trace, hash_aux, axis, look, &stmt, &params) {
        Ok(p) => p,
        Err(e) => {
            tape_out::error(&format!("prover error: {e:?} (trace rows: {})", trace.0.len()));
            return 1;
        }
    };
    let commit_ms = t0.elapsed().as_secs_f64() * 1e3;

    let t1 = Instant::now();
    let verified = zheng::verify(&proof, &stmt, &params).is_ok();
    let verify_ms = t1.elapsed().as_secs_f64() * 1e3;

    tape_out::report(title, &proof_rows(trace, &proof, verified, commit_ms, verify_ms));
    if verified { 0 } else { 1 }
}

fn proof_rows(
    trace: &VecTrace,
    proof: &TraceProof,
    verified: bool,
    commit_ms: f64,
    verify_ms: f64,
) -> Vec<tape_out::Row> {
    let steps: u64 = proof.groups.iter().map(|(_, acc)| acc.step_count).sum();
    let (outer, inner) = proof
        .groups
        .first()
        .map(|(p, _)| (p.outer_sumcheck_polys.len(), p.sumcheck_polys.len()))
        .unwrap_or((0, 0));
    vec![
        ("trace_rows", trace.0.len().to_string()),
        ("groups", proof.groups.len().to_string()),
        ("steps", steps.to_string()),
        ("outer_rounds", outer.to_string()),
        ("inner_rounds", inner.to_string()),
        ("verify", if verified { "ok" } else { "fail" }.to_string()),
        ("commit_ms", format!("{commit_ms:.2}")),
        ("verify_ms", format!("{verify_ms:.2}")),
    ]
}

/// Count trace rows whose pattern (tag in column 0) requires an opening proof:
/// axis (0), hash (15), look (17).
fn opening_pattern_counts(trace: &VecTrace) -> (usize, usize, usize) {
    let mut axis = 0;
    let mut hash = 0;
    let mut look = 0;
    for row in &trace.0 {
        match row.r()[0] {
            0 => axis += 1,
            15 => hash += 1,
            17 => look += 1,
            _ => {}
        }
    }
    (axis, hash, look)
}

fn zero_statement() -> Statement {
    Statement {
        program_hash: [0u8; 32],
        input_hash: [0u8; 32],
        output_hash: [0u8; 32],
        focus_bound: 0,
    }
}

// ── flag parsing ─────────────────────────────────────────────────────────────

#[derive(Default)]
struct Opts {
    formula: Option<String>,
    object: u64,
    budget: u64,
    output: Option<String>,
}

impl Opts {
    fn parse(args: &[String]) -> Result<Opts, String> {
        let mut o = Opts { object: 0, budget: 1_000_000, ..Default::default() };
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "-e" => { o.formula = Some(take(args, &mut i, "-e")?); }
                "-o" | "--output" => { o.output = Some(take(args, &mut i, "-o")?); }
                "--object" => { o.object = take(args, &mut i, "--object")?.parse()
                    .map_err(|e| format!("bad --object: {e}"))?; }
                "--budget" => { o.budget = take(args, &mut i, "--budget")?.parse()
                    .map_err(|e| format!("bad --budget: {e}"))?; }
                other => return Err(format!("unexpected argument '{other}'")),
            }
            i += 1;
        }
        Ok(o)
    }
}

fn take(args: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    *i += 1;
    args.get(*i).cloned().ok_or_else(|| format!("{flag} requires a value"))
}

// ── help ─────────────────────────────────────────────────────────────────────

fn print_help() {
    eprint!(
        "zheng — proof system CLI\n\
         \n\
         usage: zheng <command> [args]\n\
         \n\
         commands:\n\
         \x20 run   -e '<formula>' [--object N] [--budget B]   prove + verify a formula\n\
         \x20 demo  hash                                       prove the Poseidon2 hash program\n\
         \x20 eval                                             commit/open/verify a polynomial\n\
         \x20 pack  -e '<formula>' [--object N] [--budget B] -o <file>   write a program capsule\n\
         \x20 prove <file>                                     prove a program capsule\n\
         \x20 help                                             this message\n\
         \n\
         output: a tape chunk stream on stdout, human summary on stderr.\n\
         exit:   0 verified, 1 prover/verifier error, 2 usage error.\n"
    );
}

fn usage_hint() {
    eprintln!("run 'zheng help' for usage");
}
