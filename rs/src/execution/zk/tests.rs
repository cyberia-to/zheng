use super::*;
use crate::types::SparseMatrix;

fn example() -> (CCSInstance, CCSWitness, Vec<(usize, F)>) {
    // z[2] is a hidden square root of public z[1].
    let mut a = SparseMatrix::new(2, 4);
    let mut b = a.clone();
    let mut c = a.clone();
    a.set(0, 2, F::ONE);
    b.set(0, 2, F::ONE);
    c.set(0, 1, F::ONE);
    (
        CCSInstance {
            matrices: vec![a, b, c],
            multisets: vec![vec![0, 1], vec![2]],
            coeffs: vec![F::ONE, -F::ONE],
            num_rows: 2,
            num_cols: 4,
        },
        CCSWitness {
            z: vec![F::ONE, F::new(49), F::new(7), F::ZERO],
        },
        vec![(1, F::new(49))],
    )
}
fn seeds() -> Vec<[Seed; 3]> {
    (0..REPETITIONS)
        .map(|r| {
            std::array::from_fn(|i| {
                let mut seed = [0; 32];
                seed[..8].copy_from_slice(&(r as u64).to_le_bytes());
                seed[8] = i as u8;
                seed
            })
        })
        .collect()
}

#[test]
fn private_proofs_bind_relation_statement_and_every_public_coordinate() {
    let (instance, witness, public) = example();
    let proof = prove(&instance, &witness, b"program", &public).unwrap();
    verify(&instance, &proof, b"program", &public).unwrap();
    assert!(verify(&instance, &proof, b"different", &public).is_err());
    assert!(verify(&instance, &proof, b"program", &[(1, F::new(50))]).is_err());
    let mut changed = instance.clone();
    changed.coeffs[1] = F::ONE;
    assert!(verify(&changed, &proof, b"program", &public).is_err());
    let another = prove(&instance, &witness, b"program", &public).unwrap();
    assert_ne!(proof, another);
    verify(&instance, &another, b"program", &public).unwrap();
    let opposite = CCSWitness {
        z: vec![F::ONE, F::new(49), -F::new(7), F::ZERO],
    };
    let opposite_proof = prove(&instance, &opposite, b"program", &public).unwrap();
    verify(&instance, &opposite_proof, b"program", &public).unwrap();
}

#[test]
fn verifier_rejects_unsatisfied_and_zero_constant_witnesses_without_honest_gate() {
    let (instance, mut witness, public) = example();
    let circuit = Circuit::new(&instance, b"program", &public).unwrap();
    witness.z[2] = F::new(8);
    assert_eq!(
        prove(&instance, &witness, b"program", &public),
        Err(PrivateError::InvalidWitness)
    );
    let forged = prove_seeded(&circuit, &witness.z, &seeds());
    assert!(verify(&instance, &forged, b"program", &public).is_err());
    witness.z.fill(F::ZERO);
    assert!(instance.is_satisfied_by(&witness));
    let circuit = Circuit::new(&instance, b"program", &[]).unwrap();
    let forged = prove_seeded(&circuit, &witness.z, &seeds());
    assert!(verify(&instance, &forged, b"program", &[]).is_err());
}

#[test]
fn malformed_or_spliced_transcripts_fail_closed() {
    let (instance, witness, public) = example();
    let circuit = Circuit::new(&instance, b"program", &public).unwrap();
    let proof = prove_seeded(&circuit, &witness.z, &seeds());
    verify(&instance, &proof, b"program", &public).unwrap();
    let bytes = proof.as_bytes();
    for offset in [8, 12, 16, 20, 21, 52, 53, 60, 61, bytes.len() - 1] {
        let mut changed = proof.clone();
        changed.bytes[offset] ^= 1;
        assert!(
            verify(&instance, &changed, b"program", &public).is_err(),
            "offset {offset}"
        );
    }
    let mut noncanonical = proof.clone();
    noncanonical.bytes[53..61].copy_from_slice(&nebu::field::P.to_le_bytes());
    assert!(verify(&instance, &noncanonical, b"program", &public).is_err());
    let mut truncated = proof.clone();
    truncated.bytes.pop();
    assert!(verify(&instance, &truncated, b"program", &public).is_err());
    let mut trailing = proof.clone();
    trailing.bytes.push(0);
    assert!(verify(&instance, &trailing, b"program", &public).is_err());
    let round_length = |offset: usize| {
        97 + 8
            * (circuit.outputs.len()
                + circuit.products.len()
                + if bytes[offset] == 0 {
                    0
                } else {
                    circuit.inputs
                })
    };
    let first_end = 20 + round_length(20);
    let second_end = first_end + round_length(first_end);
    let mut spliced = proof.clone();
    spliced.bytes = [
        &bytes[..20],
        &bytes[first_end..second_end],
        &bytes[20..first_end],
        &bytes[second_end..],
    ]
    .concat();
    assert!(verify(&instance, &spliced, b"program", &public).is_err());
    let mut wrong_challenge = proof;
    wrong_challenge.bytes[20] = 3;
    assert!(verify(&instance, &wrong_challenge, b"program", &public).is_err());
    assert!(PrivateProof::from_bytes(b"ZHMITH01").is_err());
}

#[test]
fn every_opened_pair_reconstructs_the_original_views_and_outputs() {
    let (instance, witness, public) = example();
    let circuit = Circuit::new(&instance, b"", &public).unwrap();
    let seeds = seeds();
    let originals = views::simulate(&circuit, &witness.z, &seeds[0]);
    for e in 0..3 {
        let n = (e + 1) % 3;
        let mut opened = [
            View {
                seed: originals[e].seed,
                wires: originals[e].wires[..circuit.inputs].to_vec(),
            },
            View {
                seed: originals[n].seed,
                wires: originals[n].wires.clone(),
            },
        ];
        views::replay(&circuit, e, &mut opened);
        assert_eq!(opened[0].wires, originals[e].wires);
        assert_eq!(
            circuit.outputs(&opened[0].wires, e),
            circuit.outputs(&originals[e].wires, e)
        );
    }
}

#[test]
fn relation_admission_precedes_proof_allocation() {
    let (mut instance, witness, public) = example();
    assert_eq!(
        prove(&instance, &witness, b"", &[(0, F::ONE)]),
        Err(PrivateError::InvalidPublicCoordinates)
    );
    assert!(prove(&instance, &witness, b"", &[(1, F::ONE), (1, F::ONE)]).is_err());
    instance.matrices[0].entries[0][0].0 = 4;
    assert_eq!(
        prove(&instance, &witness, b"", &public),
        Err(PrivateError::InvalidRelation)
    );
    instance.num_rows = usize::MAX;
    assert!(prove(&instance, &witness, b"", &public).is_err());
}

#[test]
fn linear_relations_and_higher_degree_ccs_are_supported() {
    let (mut instance, mut witness, _) = example();
    instance.multisets[0] = vec![0, 0, 0];
    witness.z[1] = F::new(343);
    let public = vec![(1, F::new(343))];
    let proof = prove(&instance, &witness, b"cube", &public).unwrap();
    verify(&instance, &proof, b"cube", &public).unwrap();
    instance.multisets = vec![vec![0], vec![0]];
    let proof = prove(&instance, &witness, b"linear", &[]).unwrap();
    verify(&instance, &proof, b"linear", &[]).unwrap();
}

#[cfg(feature = "serde")]
#[test]
fn serde_keeps_the_bounded_fixed_width_payload() {
    let (instance, witness, public) = example();
    let proof = prove(&instance, &witness, b"", &public).unwrap();
    let bytes = postcard::to_allocvec(&proof).unwrap();
    let decoded: PrivateProof = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(decoded, proof);
    assert!(bytes.len() < proof.as_bytes().len() + 8);
    let length_bomb = postcard::to_allocvec(&(MAX_BYTES as u64 + 1)).unwrap();
    assert!(postcard::from_bytes::<PrivateProof>(&length_bomb).is_err());
    let admitted_but_truncated = postcard::to_allocvec(&(MAX_BYTES as u64)).unwrap();
    assert!(postcard::from_bytes::<PrivateProof>(&admitted_but_truncated).is_err());
}

// Exhaustive finite-ring model of the arithmetic decomposition, including the
// exposed tapes. Two distinct roots of x²=1 induce the same two-view distribution
// as the witness-free simulator. This checks privacy beyond searching raw bytes.
#[test]
fn two_view_distribution_matches_a_witness_free_simulator_over_f3() {
    use std::collections::BTreeMap;
    let reduce = |v: i32| v.rem_euclid(3) as u8;
    for e in 0..3 {
        let n = (e + 1) % 3;
        let h = (e + 2) % 3;
        let mut distributions = Vec::new();
        for secret in [1, 2] {
            let mut counts = BTreeMap::new();
            for bits in 0..243 {
                let mut v = bits;
                let mut random = [0i32; 5];
                for r in &mut random {
                    *r = v % 3;
                    v /= 3;
                }
                let shares = [
                    random[0],
                    random[1],
                    (secret - random[0] - random[1]).rem_euclid(3),
                ];
                let tapes = [random[2], random[3], random[4]];
                let products: [u8; 3] = std::array::from_fn(|i| {
                    let j = (i + 1) % 3;
                    reduce(shares[i] * shares[i] + 2 * shares[i] * shares[j] + tapes[i] - tapes[j])
                });
                let outputs: [u8; 3] =
                    std::array::from_fn(|i| reduce(products[i] as i32 - i32::from(i == 0)));
                let key = [
                    shares[e] as u8,
                    shares[n] as u8,
                    tapes[e] as u8,
                    tapes[n] as u8,
                    products[e],
                    products[n],
                    outputs[h],
                ];
                *counts.entry(key).or_insert(0) += 1;
            }
            distributions.push(counts);
        }
        let mut simulated = BTreeMap::new();
        for bits in 0..243 {
            let mut v = bits;
            let mut random = [0i32; 5];
            for r in &mut random {
                *r = v % 3;
                v /= 3;
            }
            let [a, b, ra, rb, neighbor] = random;
            let own = reduce(a * a + 2 * a * b + ra - rb);
            let out_a = reduce(own as i32 - i32::from(e == 0));
            let out_b = reduce(neighbor - i32::from(n == 0));
            let hidden = reduce(-(out_a as i32) - out_b as i32);
            let key = [
                a as u8,
                b as u8,
                ra as u8,
                rb as u8,
                own,
                neighbor as u8,
                hidden,
            ];
            *simulated.entry(key).or_insert(0) += 1;
        }
        assert_eq!(distributions[0], distributions[1]);
        assert_eq!(distributions[0], simulated);
    }
}
