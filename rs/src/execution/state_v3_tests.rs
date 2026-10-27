//! State profile v3: certificate round trip, every public claim bound, the
//! state root and every read pinned, canonical certificates only, and every
//! movable wire a "don't care".
use super::certificate::malleability::movable_wires_only_multiply_zero;
use super::state::*;
use super::state_evidence::tests::{evidence, table};
use super::state_evidence::{StateEvidence, StateTable, table_leaf};
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
/// cell(0, 3..8) = 103..107, cell(2, 11) = 42: two dimension tables.
fn tables() -> Vec<StateTable> {
    let mut ns2 = vec![0u64; 9];
    ns2[8] = 42;
    vec![table(0, &[103, 104, 105, 106, 107]), table(2, &ns2)]
}
fn state() -> StateEvidence {
    evidence(tables())
}
fn certify(program: &ExecutionNoun, input: &[u64]) -> (StateStatement, Certificate) {
    certify_state_execution(program, input, 1000, true, &state()).unwrap()
}

#[test]
fn state_certificates_verify_and_agree_with_v1() {
    for (program, input) in [
        (read_times_three(), vec![]),
        (unselected_read(), vec![]),
        (two_reads_from_input(), vec![3]),
    ] {
        let (statement, certificate) = certify(&program, &input);
        statement.verify_certificate(&certificate, &state()).unwrap();
        let (v1, proof) =
            prove_state_execution(&program, &input, 1000, true, &[7; 32], &state()).unwrap();
        v1.verify_v1(&[7; 32], &proof, &state()).unwrap();
        assert!(v1.verify_v1(&[8; 32], &proof, &state()).is_err(), "v1 binds its context");
        assert_eq!(statement, v1, "v3 and v1 state the same claim");
    }
    let (statement, _) = certify(&read_times_three(), &[]);
    assert_eq!(statement.execution.public_output, vec![126]);
    assert_eq!(statement.state_root, state().root().unwrap());
    let (statement, _) = certify(&two_reads_from_input(), &[3]);
    assert_eq!(statement.execution.public_output, vec![207]);
}

/// cell(2, 11) · r0, where r0 is the first root limb read from the subject.
fn read_times_root_limb() -> ExecutionNoun {
    op(7, op(17, q(2), q(11)), p(a(0), a(4)))
}

#[test]
fn wrong_state_root_is_rejected() {
    // zheng authenticates the evidence under the statement's own root: a
    // statement naming another root fails, whatever the caller holds.
    let (statement, certificate) = certify(&read_times_three(), &[]);
    statement.verify_certificate(&certificate, &state()).unwrap();
    for limb in 0..4 {
        let mut bad = statement.clone();
        bad.state_root[limb] = (bad.state_root[limb] + 1) % P;
        assert!(bad.verify_certificate(&certificate, &state()).is_err(), "limb {limb}");
    }
    // evidence for another state (one value changed) has another root
    let mut tables = tables();
    tables[1].fields[11] = 43;
    let other = evidence(tables);
    assert!(statement.verify_certificate(&certificate, &other).is_err(), "other state");
    // a statement re-rooted to the other state still reads 42: rejected
    let mut rerooted = statement.clone();
    rerooted.state_root = other.root().unwrap();
    assert!(rerooted.verify_certificate(&certificate, &other).is_err(), "re-rooted");
    // the root is also pinned into the subject
    let (statement, certificate) = certify(&read_times_root_limb(), &[]);
    let r0 = nebu::Goldilocks::new(statement.state_root[0]);
    assert_eq!(statement.execution.public_output, vec![(r0 * nebu::Goldilocks::new(42)).as_u64()]);
    statement.verify_certificate(&certificate, &state()).unwrap();
    let mut noncanonical = statement.clone();
    noncanonical.state_root[0] = P;
    assert!(noncanonical.verify_certificate(&certificate, &state()).is_err());
}

#[test]
fn an_unauthenticated_read_is_rejected_by_zheng_alone() {
    let (s, certificate) = certify(&two_reads_from_input(), &[3]);
    // evidence without the table the reads name
    let missing = evidence(vec![tables()[1].clone()]);
    let mut leaves_kept = missing.clone();
    leaves_kept.leaves = state().leaves;
    assert!(s.verify_certificate(&certificate, &missing).is_err(), "other root");
    assert!(s.verify_certificate(&certificate, &leaves_kept).is_err(), "table absent");
    // the table carried but altered under the honest leaves
    let mut altered = state();
    altered.tables[0].fields[3] = 104;
    assert!(s.verify_certificate(&certificate, &altered).is_err(), "altered table");
    // a leaf altered to match an altered table changes the root
    altered.leaves[0] = table_leaf(&altered.tables[0].fields);
    assert!(s.verify_certificate(&certificate, &altered).is_err(), "altered leaf");
    // the same execution certified against altered state is another statement
    let (forged, _) = certify_state_execution(&two_reads_from_input(), &[3], 1000, true, &altered)
        .unwrap();
    assert_ne!(forged.state_root, s.state_root);
    assert!(forged.verify_certificate(&certificate, &state()).is_err());
}

#[test]
fn every_read_and_public_claim_is_bound() {
    let (s, certificate) = certify(&two_reads_from_input(), &[3]);
    let check = |bad: &StateStatement| bad.verify_certificate(&certificate, &state()).is_err();
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
}

#[test]
fn inactive_reads_carry_no_data_and_cannot_become_active() {
    // the program reads cell(9, 1234), a table no evidence carries
    let (s, certificate) = certify(&unselected_read(), &[]);
    s.verify_certificate(&certificate, &state()).unwrap();
    let mut bad = s.clone();
    bad.reads[0].key = 1234;
    assert!(bad.verify_certificate(&certificate, &state()).is_err());
    let mut bad = s.clone();
    bad.reads[0].active = true;
    assert!(bad.verify_certificate(&certificate, &state()).is_err());
}

#[test]
fn statement_bounds_are_enforced() {
    let (s, certificate) = certify(&read_times_three(), &[]);
    let mut bad = s.clone();
    bad.reads = vec![s.reads[0].clone(); MAX_READS + 1];
    assert!(bad.verify_certificate(&certificate, &state()).is_err());
    let mut bad = s.clone();
    bad.execution.public_output[0] = P;
    assert!(bad.verify_certificate(&certificate, &state()).is_err());
    let mut bad = s.clone();
    bad.execution.budget = bad.execution.cycles - 1;
    assert!(bad.verify_certificate(&certificate, &state()).is_err());
}

#[test]
fn only_the_canonical_state_certificate_verifies() {
    for (program, input) in [(read_times_three(), vec![]), (unselected_read(), vec![])] {
        let (s, certificate) = certify(&program, &input);
        assert!(!certificate.free.is_empty());
        let check = |c: &Certificate| s.verify_certificate(c, &state()).is_err();
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
    assert!(s.verify_certificate(&Certificate { free: vec![] }, &state()).is_err());
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
        let public = statement.authenticated_bindings(&state()).unwrap().1;
        let movable =
            movable_wires_only_multiply_zero(name, &relation.instance, &certificate, &public);
        println!("{name}: free {} movable {movable}", certificate.free.len());
    }
}
