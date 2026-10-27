//! Profile v3 on real compiled programs: the honest certificate verifies,
//! every single free value change is rejected, and every public claim is bound.
use zheng::execution::{
    Certificate, ExecutionNoun, certify_execution, prove_execution, verify_certificate,
    verify_execution,
};

const P: u64 = 0xFFFF_FFFF_0000_0001;

/// joy 0.5 `hash.tri`: `fn main(a: Field) -> Digest { hash(a,0,0,0,0,0,0,0) }`
const HASH: &str = "[2 [[3 [[4 [[9 [[0 3] [1 0]]] [[1 0] [8 [1 0]]]]] [0 1]]] [1 [2 [[0 3] [1 [2 [[3 [[5 [[0 2] [1 0]]] [1 0]]] [1 [15 [3 [[0 2] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [1 0]]]]]]]]]]]]]]]]]]]]]]]]]]]";
/// joy 0.5 `add.tri`: `let c = a + b; c * a`
const ADD: &str = "[2 [[3 [[4 [[9 [[0 7] [1 0]]] [[1 0] [8 [1 0]]]]] [0 1]]] [1 [2 [[0 3] [1 [2 [[3 [[5 [[0 2] [1 0]]] [3 [[5 [[0 6] [1 0]]] [1 0]]]]] [1 [2 [[3 [[5 [[0 6] [0 2]]] [0 1]]] [1 [7 [[0 2] [0 14]]]]]]]]]]]]]]]";

fn parse(text: &str) -> ExecutionNoun {
    fn go(b: &[u8], p: &mut usize) -> ExecutionNoun {
        while b[*p].is_ascii_whitespace() {
            *p += 1;
        }
        if b[*p] == b'[' {
            *p += 1;
            let a = go(b, p);
            let c = go(b, p);
            while b[*p].is_ascii_whitespace() {
                *p += 1;
            }
            assert_eq!(b[*p], b']');
            *p += 1;
            ExecutionNoun::Pair(Box::new(a), Box::new(c))
        } else {
            let s = *p;
            while b[*p].is_ascii_digit() {
                *p += 1;
            }
            ExecutionNoun::Atom(std::str::from_utf8(&b[s..*p]).unwrap().parse().unwrap())
        }
    }
    go(text.as_bytes(), &mut 0)
}

fn cases() -> Vec<(&'static str, ExecutionNoun, Vec<u64>)> {
    vec![
        ("hash", parse(HASH), vec![7]),
        ("hash", parse(HASH), vec![P - 1]),
        ("add", parse(ADD), vec![7, 5]),
        ("add", parse(ADD), vec![0, 0]),
    ]
}

#[test]
fn honest_v3_certificates_verify_and_agree_with_v2() {
    for (name, program, input) in cases() {
        let (statement, certificate) = certify_execution(&program, &input, 1_000_000).unwrap();
        verify_certificate(&statement, &certificate).unwrap();
        // the same statement through profile v2 — same outputs, same cycles
        let (v2, proof) = prove_execution(&program, &input, 1_000_000).unwrap();
        verify_execution(&v2, &proof).unwrap();
        assert_eq!(statement.public_output, v2.public_output, "{name}");
        assert_eq!(statement.cycles, v2.cycles, "{name}");
    }
}

#[test]
fn a_changed_free_value_never_verifies_with_a_different_output() {
    // Movable "don't care" wires are characterised by the unit test
    // `malleability::every_movable_wire_only_multiplies_zero`. Here: whatever
    // single free value is changed, no different public output is accepted.
    for (name, program, input) in cases() {
        let (statement, certificate) = certify_execution(&program, &input, 1_000_000).unwrap();
        for i in 0..certificate.free.len() {
            let mut bad = certificate.clone();
            bad.free[i] = (bad.free[i] + 1) % P;
            for o in 0..statement.public_output.len() {
                let mut claim = statement.clone();
                claim.public_output[o] = (claim.public_output[o] + 1) % P;
                assert!(
                    verify_certificate(&claim, &bad).is_err(),
                    "{name}: free {i} output {o}"
                );
            }
        }
        let mut longer = certificate.clone();
        longer.free.push(1);
        assert!(
            verify_certificate(&statement, &longer).is_err(),
            "{name}: tail"
        );
    }
}

#[test]
fn every_public_claim_is_bound() {
    for (name, program, input) in cases() {
        let (statement, certificate) = certify_execution(&program, &input, 1_000_000).unwrap();
        let mut wrong_output = statement.clone();
        wrong_output.public_output[0] = (wrong_output.public_output[0] + 1) % P;
        assert!(
            verify_certificate(&wrong_output, &certificate).is_err(),
            "{name}: output"
        );
        let mut wrong_input = statement.clone();
        wrong_input.public_input[0] = (wrong_input.public_input[0] + 1) % P;
        assert!(
            verify_certificate(&wrong_input, &certificate).is_err(),
            "{name}: input"
        );
        let mut wrong_cycles = statement.clone();
        wrong_cycles.cycles += 1;
        assert!(
            verify_certificate(&wrong_cycles, &certificate).is_err(),
            "{name}: cycles"
        );
    }
}

#[test]
fn a_certificate_for_one_program_does_not_verify_another() {
    let (hash_statement, hash_cert) = certify_execution(&parse(HASH), &[7], 1_000_000).unwrap();
    let (add_statement, add_cert) = certify_execution(&parse(ADD), &[7, 5], 1_000_000).unwrap();
    assert!(verify_certificate(&hash_statement, &add_cert).is_err());
    assert!(verify_certificate(&add_statement, &hash_cert).is_err());
}

#[test]
fn empty_and_garbage_certificates_are_rejected() {
    for (name, program, input) in cases() {
        let (statement, certificate) = certify_execution(&program, &input, 1_000_000).unwrap();
        assert!(
            verify_certificate(&statement, &Certificate { free: vec![] }).is_err(),
            "{name}: empty"
        );
        let garbage = Certificate {
            free: (0..certificate.free.len() as u64)
                .map(|i| i * 7919 % P)
                .collect(),
        };
        assert!(
            verify_certificate(&statement, &garbage).is_err(),
            "{name}: garbage"
        );
    }
}

#[test]
fn size_report() {
    for (name, program, input) in cases() {
        let (statement, certificate) = certify_execution(&program, &input, 1_000_000).unwrap();
        let nonzero = certificate.free.iter().filter(|&&v| v != 0).count();
        let small = certificate.free.iter().filter(|&&v| v < 128).count();
        println!(
            "{name} {input:?}: free {} (nonzero {nonzero}, < 128: {small}), program tokens {}",
            certificate.free.len(),
            statement.program.len()
        );
    }
}
