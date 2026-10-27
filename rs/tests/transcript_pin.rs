//! Byte-transcript pins: the machine prover over lens's byte transcript
//! (zerocheck, shift reduction, accumulation sumcheck — the provers the
//! recursion profile made generic over `fs::FiatShamir`) yields exactly the
//! proofs it yielded before that refactor (`feat/accumulation`, #51).
//! With the opcode coverage (#52) merged, the machine relation itself
//! changed: the pins were #52's prover output (`feat/machine-opcodes`
//! 9d758ed, checked byte for byte), which the recursion refactor keeps.
//! Re-pinned once more when the statement bound its program by digest
//! (`MachineStatement::bytes` v2, the only input that changed).

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

const PIN_ADD: &str = "70dab40f5cebc514e05c79a969610528f382f7da7f97904227aa0e17e60d5760";
const PIN_TREE: &str = "cfeee685d4858a53b3f3bed9a5c57211ae6cae37bb159ab5a07306a73a53c05f";
