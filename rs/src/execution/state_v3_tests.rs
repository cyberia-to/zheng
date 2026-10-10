//! State profile v3: certificate round trip, every public claim bound, the
//! state root and every read pinned, canonical certificates only, and every
//! movable wire a "don't care".
use super::certificate::malleability::movable_wires_only_multiply_zero;
use super::state::*;
use super::{Certificate, ExecutionNoun};
use nebu::field::P;

fn a(v: u64) -> ExecutionNoun {
    ExecutionNoun::Atom(v)
}
fn p(x: ExecutionNoun, y: ExecutionNoun) -> ExecutionNoun {
    ExecutionNoun::Pair(Box::new(x), Box::new(y))
}
fn q(v: u64) -> ExecutionNoun {
    p(a(1), a(v))
}
fn op(t: u64, x: ExecutionNoun, y: ExecutionNoun) -> ExecutionNoun {
    p(a(t), p(x, y))
}
/// (cell(2, 11)) · 3 — one active read.
fn read_times_three() -> ExecutionNoun {
    op(7, op(17, q(2), q(11)), q(3))
}
/// if 0 then 7 else cell(9, 1234) — the read is inactive.
fn unselected_read() -> ExecutionNoun {
    p(a(4), p(q(0), p(q(7), op(17, q(9), q(1234)))))
}
/// cell(0, key) + cell(0, key + 1) with the key a public input; the subject
/// is [root [key 0]], so the key sits at axis 6.
fn two_reads_from_input() -> ExecutionNoun {
    let key = p(a(0), a(6));
    let next = op(5, p(a(0), a(6)), q(1));
    op(5, op(17, q(0), key), op(17, q(0), next))
}
fn cell(ns: u64, key: u64) -> Option<u64> {
    match (ns, key) {
        (2, 11) => Some(42),
        (0, k) if k < 8 => Some(100 + k),
        _ => None,
    }
}
const ROOT: [u64; 4] = [1, 2, 3, 4];

fn certify(program: &ExecutionNoun, input: &[u64]) -> (StateStatement, Certificate) {
    certify_state_execution(program, input, 1000, ROOT, true, [7; 32], &mut cell).unwrap()
}

#[test]
fn state_certificates_verify_and_agree_with_v1() {
    for (program, input) in [
        (read_times_three(), vec![]),
        (unselected_read(), vec![]),
        (two_reads_from_input(), vec![3]),
    ] {
        let (statement, certificate) = certify(&program, &input);
        statement.verify_certificate(&certificate, &mut cell).unwrap();
        let (v1, proof) =
            prove_state_execution(&program, &input, 1000, ROOT, true, [7; 32], &mut cell).unwrap();
        v1.verify(&proof, &mut cell).unwrap();
        assert_eq!(statement, v1, "v3 and v1 state the same claim");
    }
    let (statement, _) = certify(&read_times_three(), &[]);
    assert_eq!(statement.execution.public_output, vec![126]);
    let (statement, _) = certify(&two_reads_from_input(), &[3]);
    assert_eq!(statement.execution.public_output, vec![207]);
}

/// A state certificate answers only for the root it was verified under.
fn authenticated(root: [u64; 4]) -> impl FnMut(u64, u64) -> Option<u64> {
    move |ns, key| if root == ROOT { cell(ns, key) } else { None }
}

/// cell(2, 11) · r0, where r0 is the first root limb read from the subject.
fn read_times_root_limb() -> ExecutionNoun {
    op(7, op(17, q(2), q(11)), p(a(0), a(4)))
}

#[test]
fn wrong_state_root_is_rejected() {
    // Reads are authenticated against the statement's root: a different root
    // makes every active read fail authentication.
    let (statement, certificate) = certify(&read_times_three(), &[]);
    statement.verify_certificate(&certificate, &mut authenticated(statement.state_root)).unwrap();
    for limb in 0..4 {
        let mut bad = statement.clone();
        bad.state_root[limb] += 1;
        let mut lookup = authenticated(bad.state_root);
        assert!(bad.verify_certificate(&certificate, &mut lookup).is_err(), "limb {limb}");
    }
    // The root is also pinned into the subject: a limb the program computes
    // on is rejected by the relation itself, even by a root-blind table.
    // (Limbs the program never reads are bound by authentication alone.)
    let (statement, certificate) = certify(&read_times_root_limb(), &[]);
    assert_eq!(statement.execution.public_output, vec![42]);
    statement.verify_certificate(&certificate, &mut cell).unwrap();
    let mut bad = statement.clone();
    bad.state_root[0] += 1;
    assert!(bad.verify_certificate(&certificate, &mut cell).is_err(), "subject limb 0");
    let mut noncanonical = statement.clone();
    noncanonical.state_root[0] = P;
    assert!(noncanonical.verify_certificate(&certificate, &mut cell).is_err());
}

#[test]
fn every_read_and_public_claim_is_bound() {
    let (s, certificate) = certify(&two_reads_from_input(), &[3]);
    let check = |bad: &StateStatement| bad.verify_certificate(&certificate, &mut cell).is_err();
    for i in 0..2 {
        let mut bad = s.clone();
        bad.reads[i].key += 1;
        assert!(check(&bad), "key {i}");
        let mut bad = s.clone();
        bad.reads[i].value += 1;
        assert!(check(&bad), "value {i}");
        let mut bad = s.clone();
        bad.reads[i].namespace = 1;
        assert!(check(&bad), "namespace {i}");
        let mut bad = s.clone();
        bad.reads[i].active = false;
        assert!(check(&bad), "active {i}");
    }
    let mut bad = s.clone();
    bad.execution.public_output[0] += 1;
    assert!(check(&bad), "output");
    let mut bad = s.clone();
    bad.execution.public_input[0] += 1;
    assert!(check(&bad), "input");
    let mut bad = s.clone();
    bad.execution.cycles += 1;
    assert!(check(&bad), "cycles");
    let mut bad = s.clone();
    bad.root_in_subject = false;
    assert!(check(&bad), "root placement");
    let mut bad = s.clone();
    bad.reads.swap(0, 1);
    assert!(check(&bad), "read order");
    let mut bad = s.clone();
    bad.reads.pop();
    assert!(check(&bad), "missing read");
    let mut bad = s.clone();
    bad.reads.push(bad.reads[0].clone());
    assert!(check(&bad), "extra read");
    // the lookup provider is the state certificate: a disagreeing cell fails
    assert!(s.verify_certificate(&certificate, &mut |_, _| None).is_err());
    assert!(s.verify_certificate(&certificate, &mut |_, _| Some(101)).is_err());
}

#[test]
fn inactive_reads_carry_no_data_and_cannot_become_active() {
    let (s, certificate) = certify_state_execution(
        &unselected_read(), &[], 1000, ROOT, true, [0; 32],
        &mut |_, _| panic!("an inactive read consults no state"),
    )
    .unwrap();
    s.verify_certificate(&certificate, &mut |_, _| panic!("inactive")).unwrap();
    let mut bad = s.clone();
    bad.reads[0].key = 1234;
    assert!(bad.verify_certificate(&certificate, &mut cell).is_err());
    let mut bad = s.clone();
    bad.reads[0].active = true;
    assert!(bad.verify_certificate(&certificate, &mut |_, _| Some(0)).is_err());
}

#[test]
fn statement_bounds_are_enforced() {
    let (s, certificate) = certify(&read_times_three(), &[]);
    let mut bad = s.clone();
    bad.reads = vec![s.reads[0].clone(); MAX_READS + 1];
    assert!(bad.verify_certificate(&certificate, &mut cell).is_err());
    let mut bad = s.clone();
    bad.execution.public_output[0] = P;
    assert!(bad.verify_certificate(&certificate, &mut cell).is_err());
    let mut bad = s.clone();
    bad.execution.budget = bad.execution.cycles - 1;
    assert!(bad.verify_certificate(&certificate, &mut cell).is_err());
}

#[test]
fn only_the_canonical_state_certificate_verifies() {
    for (program, input) in [(read_times_three(), vec![]), (unselected_read(), vec![])] {
        let (s, certificate) = certify(&program, &input);
        assert!(!certificate.free.is_empty());
        let check = |c: &Certificate| s.verify_certificate(c, &mut cell).is_err();
        let mut trailing_zero = certificate.clone();
        trailing_zero.free.push(0);
        assert!(check(&trailing_zero), "trailing zero");
        let mut padding = certificate.clone();
        padding.free.push(5);
        assert!(check(&padding), "value in padding");
        let mut noncanonical = certificate.clone();
        noncanonical.free[0] += P;
        assert!(check(&noncanonical), "noncanonical");
        assert!(check(&Certificate { free: vec![1; 1 << 16] }), "overlong");
    }
    // read · 3 has one free value, the product: dropping it is rejected
    let (s, certificate) = certify(&read_times_three(), &[]);
    assert_eq!(certificate.free.len(), 1);
    assert!(s.verify_certificate(&Certificate { free: vec![] }, &mut cell).is_err());
}

#[test]
fn every_movable_state_wire_only_multiplies_zero() {
    for (name, program, input) in [
        ("read", read_times_three(), vec![]),
        ("unselected", unselected_read(), vec![]),
        ("two-reads", two_reads_from_input(), vec![3]),
    ] {
        let (statement, certificate) = certify(&program, &input);
        let relation = statement.relation().unwrap();
        let public = statement.bindings(&relation, &mut cell).unwrap();
        let movable =
            movable_wires_only_multiply_zero(name, &relation.instance, &certificate, &public);
        println!("{name}: free {} movable {movable}", certificate.free.len());
    }
}
