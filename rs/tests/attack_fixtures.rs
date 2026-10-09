//! Phase-1 attack fixtures (proof-system repair §5–6): every one must be
//! rejected on the default build. The retired legacy path accepts the
//! meaningless-witness and zeroed-constant attacks; see
//! `retired_path_hole_*` in `rs/src/folding/fold.rs` (feature `legacy`).
use nebu::Goldilocks as F;
use zheng::envelope::{Envelope, EnvelopeError, MAGIC};
use zheng::execution::relation::{SubjectShape, compile_relation};
use zheng::execution::state::certify_state_execution;
use zheng::execution::{Certificate, ExecutionNoun, certificate, certify_execution, verify_certificate};
use zheng::types::CCSWitness;

const P: u64 = 0xFFFF_FFFF_0000_0001;
/// joy 0.5 `hash.tri` and `add.tri`, as compiled.
const HASH: &str = "[2 [[3 [[4 [[9 [[0 3] [1 0]]] [[1 0] [8 [1 0]]]]] [0 1]]] [1 [2 [[0 3] [1 [2 [[3 [[5 [[0 2] [1 0]]] [1 0]]] [1 [15 [3 [[0 2] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [3 [[1 0] [1 0]]]]]]]]]]]]]]]]]]]]]]]]]]]";
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

fn public(program: &str, input: &[u64]) -> Envelope {
    let (statement, certificate) = certify_execution(&parse(program), input, 1_000_000).unwrap();
    Envelope::Public { statement, certificate }
}

fn rejected(envelope: &Envelope) -> bool {
    let bytes = envelope.to_bytes();
    Envelope::from_bytes(&bytes).map_or(true, |e| e.verify(&mut |_, _| None).is_err())
}

#[test]
fn fixture_forged_io_is_rejected() {
    for (program, input) in [(HASH, vec![7]), (ADD, vec![7, 5])] {
        let honest = public(program, &input);
        assert!(!rejected(&honest));
        let Envelope::Public { statement, certificate } = honest else { unreachable!() };
        let forge = |edit: &dyn Fn(&mut zheng::execution::ExecutionStatement)| {
            let mut s = statement.clone();
            edit(&mut s);
            rejected(&Envelope::Public { statement: s, certificate: certificate.clone() })
        };
        assert!(forge(&|s| s.public_input[0] = (s.public_input[0] + 1) % P), "input");
        assert!(forge(&|s| s.public_output[0] = (s.public_output[0] + 1) % P), "output");
        assert!(forge(&|s| s.public_output.push(0)), "extra output");
        assert!(forge(&|s| s.cycles += 1), "cycles");
        assert!(forge(&|s| s.cycles -= 1), "fewer cycles");
    }
}

#[test]
fn fixture_forged_program_is_rejected() {
    let Envelope::Public { statement, certificate } = public(ADD, &[7, 5]) else { unreachable!() };
    // swap the final multiplication (tag 7) for an addition (tag 5)
    let mut other = statement.clone();
    let mul = other
        .program
        .iter()
        .rposition(|t| *t == zheng::execution::NounToken::Atom(7))
        .unwrap();
    other.program[mul] = zheng::execution::NounToken::Atom(5);
    assert!(rejected(&Envelope::Public { statement: other, certificate: certificate.clone() }));
    // a valid certificate of another program
    let Envelope::Public { statement: hash, certificate: hash_cert } = public(HASH, &[7]) else {
        unreachable!()
    };
    assert!(rejected(&Envelope::Public { statement: hash, certificate: certificate.clone() }));
    assert!(rejected(&Envelope::Public { statement, certificate: hash_cert }));
}

#[test]
fn fixture_zeroed_constant_is_rejected() {
    // Constants reference wire 0, so every row is homogeneous: the all-zero
    // vector satisfies the compiled relation. The verifier pins z[0] = 1;
    // the prover cannot address it.
    let shape = SubjectShape::Pair(
        Box::new(SubjectShape::Atom),
        Box::new(SubjectShape::Pair(Box::new(SubjectShape::Atom), Box::new(SubjectShape::Atom))),
    );
    let relation = compile_relation(&parse(ADD), &shape).unwrap();
    let zero = CCSWitness { z: vec![F::ZERO; relation.instance.num_cols] };
    assert!(relation.instance.is_satisfied_by(&zero), "the hole the pin closes");
    assert!(certificate::verify(&relation.instance, &Certificate { free: vec![] }, &[]).is_err());
    assert!(
        certificate::verify(&relation.instance, &Certificate { free: vec![] }, &[(0, F::ZERO)])
            .is_err(),
        "z[0] is not a public coordinate a statement can set"
    );
    // the all-zero claim through the statement API
    let Envelope::Public { mut statement, .. } = public(ADD, &[0, 0]) else { unreachable!() };
    statement.public_output = vec![0];
    statement.cycles = 0;
    assert!(verify_certificate(&statement, &Certificate { free: vec![] }).is_err());
}

#[test]
fn fixture_meaningless_witness_is_rejected() {
    // A genuinely satisfying certificate (an honest run of ADD on 7, 5) shown
    // for statements it does not prove: other inputs, other outputs, other
    // programs. The relation and its public prefix come from the statement.
    let Envelope::Public { certificate, .. } = public(ADD, &[7, 5]) else { unreachable!() };
    for (program, input) in [(ADD, vec![1, 2]), (ADD, vec![0, 0]), (HASH, vec![7])] {
        let Envelope::Public { statement, .. } = public(program, &input) else { unreachable!() };
        assert!(verify_certificate(&statement, &certificate).is_err(), "{input:?}");
    }
}

#[test]
fn fixture_truncated_and_overlong_certificates_are_rejected() {
    for (program, input) in [(HASH, vec![7]), (ADD, vec![7, 5])] {
        let Envelope::Public { statement, certificate } = public(program, &input) else {
            unreachable!()
        };
        let check = |c: Certificate| verify_certificate(&statement, &c).is_err();
        let mut truncated = certificate.clone();
        truncated.free.truncate(certificate.free.len() / 2);
        assert!(check(truncated), "truncated");
        let mut overlong = certificate.clone();
        overlong.free.extend([1; 64]);
        assert!(check(overlong), "overlong");
        assert!(check(Certificate { free: vec![] }), "empty");
        // and on the wire: a cut envelope, a longer envelope
        let bytes = Envelope::Public { statement: statement.clone(), certificate }.to_bytes();
        assert!(Envelope::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        assert!(Envelope::from_bytes(&[bytes.as_slice(), &[1]].concat()).is_err());
    }
}

#[test]
fn fixture_wrong_state_root_is_rejected() {
    let pair = |a, b| ExecutionNoun::Pair(Box::new(a), Box::new(b));
    let q = |v| pair(ExecutionNoun::Atom(1), ExecutionNoun::Atom(v));
    let read = pair(ExecutionNoun::Atom(17), pair(q(2), q(11)));
    let program = pair(ExecutionNoun::Atom(7), pair(read, q(3)));
    const ROOT: [u64; 4] = [1, 2, 3, 4];
    let table = |root: [u64; 4]| move |ns, key| (root == ROOT && (ns, key) == (2, 11)).then_some(42);
    let (statement, certificate) =
        certify_state_execution(&program, &[], 1000, ROOT, true, [0; 32], &mut table(ROOT)).unwrap();
    let honest = Envelope::StatePublic { statement: statement.clone(), certificate: certificate.clone() };
    honest.verify(&mut table(ROOT)).unwrap();
    for limb in 0..4 {
        let mut wrong = statement.clone();
        wrong.state_root[limb] += 1;
        let root = wrong.state_root;
        let envelope = Envelope::StatePublic { statement: wrong, certificate: certificate.clone() };
        let decoded = Envelope::from_bytes(&envelope.to_bytes()).unwrap();
        assert!(decoded.verify(&mut table(root)).is_err(), "limb {limb}");
    }
}

#[test]
fn fixture_envelope_with_wrong_magic_version_or_profile_is_rejected() {
    let bytes = public(ADD, &[7, 5]).to_bytes();
    assert_eq!(&bytes[..8], MAGIC);
    let mut magic = bytes.clone();
    magic[0] ^= 1;
    assert_eq!(Envelope::from_bytes(&magic), Err(EnvelopeError::BadMagic));
    let mut version = bytes.clone();
    version[8] = 2;
    assert_eq!(Envelope::from_bytes(&version), Err(EnvelopeError::UnsupportedVersion(2)));
    for profile in [1u8, 2, 3, 4] {
        let mut wrong = bytes.clone();
        wrong[10] = profile;
        let accepted = Envelope::from_bytes(&wrong).is_ok_and(|e| e.verify(&mut |_, _| None).is_ok());
        assert!(!accepted, "profile {profile}");
    }
}
