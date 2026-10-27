use super::circuit::{Circuit, fields, number};
use hemera::{Hasher, OutputReader};
use nebu::{Goldilocks as F, field::P};
use zeroize::Zeroize;

pub(super) type Seed = [u8; 32];

pub(super) fn stream(seed: &Seed, domain: &[u8]) -> OutputReader {
    let mut hash = Hasher::new();
    hash.update(b"zheng-ccs-mith-stream-v1");
    number(&mut hash, domain.len());
    hash.update(domain);
    hash.update(seed);
    hash.finalize_xof()
}

pub(super) fn field(stream: &mut OutputReader) -> F {
    // Hemera's XOF emits canonical field limbs. Rejection also makes the
    // conversion safe for any future uniform-byte XOF implementation.
    loop {
        let mut bytes = [0; 8];
        stream.fill(&mut bytes);
        let value = u64::from_le_bytes(bytes);
        if value < P {
            return F::new(value);
        }
    }
}

pub(super) fn input_share(seed: &Seed, length: usize) -> Vec<F> {
    let mut tape = stream(seed, b"input");
    (0..length).map(|_| field(&mut tape)).collect()
}

pub(super) struct View {
    pub seed: Seed,
    pub wires: Vec<F>,
}
pub(super) fn clear_fields(values: &mut [F]) {
    // SAFETY: Goldilocks is repr(transparent) over u64, with the same alignment;
    // zero is a valid representation. The exclusive slice borrow is preserved.
    let words =
        unsafe { core::slice::from_raw_parts_mut(values.as_mut_ptr().cast::<u64>(), values.len()) };
    words.zeroize();
}
impl Drop for View {
    fn drop(&mut self) {
        self.seed.zeroize();
        clear_fields(&mut self.wires);
    }
}

pub(super) fn simulate(circuit: &Circuit, witness: &[F], seeds: &[Seed; 3]) -> [View; 3] {
    let first = input_share(&seeds[0], circuit.inputs);
    let second = input_share(&seeds[1], circuit.inputs);
    let third = witness
        .iter()
        .zip(&first)
        .zip(&second)
        .map(|((&z, &a), &b)| z - a - b)
        .collect();
    let mut views = [
        View {
            seed: seeds[0],
            wires: first,
        },
        View {
            seed: seeds[1],
            wires: second,
        },
        View {
            seed: seeds[2],
            wires: third,
        },
    ];
    let mut tapes = seeds.map(|seed| stream(&seed, b"multiplication"));
    for (a, b) in &circuit.products {
        let av = std::array::from_fn::<_, 3, _>(|i| a.evaluate(&views[i].wires, i));
        let bv = std::array::from_fn::<_, 3, _>(|i| b.evaluate(&views[i].wires, i));
        let masks = std::array::from_fn::<_, 3, _>(|i| field(&mut tapes[i]));
        for i in 0..3 {
            let j = (i + 1) % 3;
            views[i]
                .wires
                .push(av[i] * bv[i] + av[j] * bv[i] + av[i] * bv[j] + masks[i] - masks[j]);
        }
    }
    views
}

pub(super) fn commitment(circuit: &Circuit, repetition: usize, party: usize, view: &View) -> Seed {
    let mut hash = Hasher::new();
    hash.update(b"zheng-ccs-mith-view-v1");
    hash.update(&circuit.digest);
    number(&mut hash, repetition);
    number(&mut hash, party);
    hash.update(&view.seed);
    fields(&mut hash, &view.wires[..circuit.inputs]);
    fields(&mut hash, &view.wires[circuit.inputs..]);
    *hash.finalize().as_bytes()
}

pub(super) struct FirstMessage {
    pub commitments: [Seed; 3],
    pub outputs: [Vec<F>; 3],
}
impl FirstMessage {
    pub fn new(circuit: &Circuit, repetition: usize, views: &[View; 3]) -> Self {
        Self {
            commitments: std::array::from_fn(|i| commitment(circuit, repetition, i, &views[i])),
            outputs: std::array::from_fn(|i| circuit.outputs(&views[i].wires, i)),
        }
    }
    pub fn absorb(&self, transcript: &mut Hasher) {
        for c in &self.commitments {
            transcript.update(c);
        }
        for values in &self.outputs {
            fields(transcript, values);
        }
    }
    pub fn is_zero(&self) -> bool {
        self.outputs[0]
            .iter()
            .zip(&self.outputs[1])
            .zip(&self.outputs[2])
            .all(|((&a, &b), &c)| a + b + c == F::ZERO)
    }
}

pub(super) fn transcript(circuit: &Circuit) -> Hasher {
    let mut hash = Hasher::new();
    hash.update(b"zheng-ccs-mith-challenges-v1");
    hash.update(&circuit.digest);
    hash
}

pub(super) fn challenges(hash: &Hasher) -> [u8; super::REPETITIONS] {
    let mut tape = hash.finalize_xof();
    std::array::from_fn(|_| {
        loop {
            let value = field(&mut tape).as_u64();
            // P-1 is divisible by three: exact uniform trits from field limbs.
            if value < P - 1 {
                break (value % 3) as u8;
            }
        }
    })
}

/// Reconstruct the first opened view; the neighbor supplies its product shares.
pub(super) fn replay(circuit: &Circuit, party: usize, views: &mut [View; 2]) {
    let neighbor = (party + 1) % 3;
    let mut tapes = [
        stream(&views[0].seed, b"multiplication"),
        stream(&views[1].seed, b"multiplication"),
    ];
    for (a, b) in &circuit.products {
        let av = a.evaluate(&views[0].wires, party);
        let bv = b.evaluate(&views[0].wires, party);
        let an = a.evaluate(&views[1].wires, neighbor);
        let bn = b.evaluate(&views[1].wires, neighbor);
        let mask = field(&mut tapes[0]) - field(&mut tapes[1]);
        views[0].wires.push(av * bv + an * bv + av * bn + mask);
    }
}
