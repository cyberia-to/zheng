//! Byte-transcript pins: the machine prover over lens's byte transcript
//! (zerocheck, shift reduction, accumulation sumcheck — the provers the
//! recursion profile made generic over `fs::FiatShamir`) yields exactly the
//! proofs it yielded before that refactor (`feat/accumulation`, #51).

mod common;

use zheng::machine;

fn whir() -> lens::WhirParams {
    lens::WhirParams { log_inv_rate: 3, pow_bits: 16, ..lens::WhirParams::default() }
}

fn digest(bytes: &[u8]) -> String {
    hemera::hash(bytes).to_hex()
}

#[test]
fn machine_proofs_are_byte_identical_to_the_pre_recursion_prover() {
    let w = whir();
    let add = common::parse(common::ADD);
    let (_, p) = machine::prove(&add, &[7, 5], 1 << 20, &w).unwrap();
    let one = digest(&p.to_bytes());
    let run = machine::execute_with(&common::tree_program(7), &[3], 1 << 30, 8).unwrap();
    assert!(run.segments() > 4);
    let p = machine::prove_run(&run, &w).unwrap();
    let many = digest(&p.to_bytes());
    eprintln!("add {one}\ntree-7 {many}");
    assert_eq!(one, PIN_ADD);
    assert_eq!(many, PIN_TREE);
}

const PIN_ADD: &str = "196debd33bb9ac1d1cdd83b4ba8fe62b706d7b47b20b0f720b377031962a16c4";
const PIN_TREE: &str = "ce2fd453e771029ec6cbf5f663e1a8099dab10f314f15280020d8cb45797dcbe";
