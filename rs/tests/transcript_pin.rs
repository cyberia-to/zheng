//! Byte-transcript pins: the machine prover over lens's byte transcript
//! (zerocheck, shift reduction, accumulation sumcheck — the provers the
//! recursion profile made generic over `fs::FiatShamir`) yields exactly the
//! proofs it yielded before that refactor (`feat/accumulation`, #51).
//! With the opcode coverage (#52) merged, the machine relation itself
//! changed: the pins are #52's prover output (`feat/machine-opcodes`
//! 9d758ed, checked byte for byte), which the recursion refactor keeps.

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

const PIN_ADD: &str = "ab2994916b45413cec6c63efd4a2086eb2637545786643e3fce0a6268909d812";
const PIN_TREE: &str = "46c1735da6ca518d195f43fc9b1076d3354758bdd0d5cb9a370e081f21815b86";
