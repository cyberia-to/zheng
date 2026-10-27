use super::*;
use crate::execution::disclosed::memory::{Definition, Memory, Value, VerifiedNode};
use nebu::Goldilocks as F;
use nox::{Order, Outcome, Reduction, data::Data};

mod adversarial;
mod differential;

const N: usize = 4096;
type Arena = Reduction<N>;

fn atom(ar: &mut Arena, value: u64) -> Order {
    ar.atom(F::new(value)).unwrap()
}
fn op(ar: &mut Arena, tag: u64, body: Order) -> Order {
    let head = atom(ar, tag);
    ar.pair(head, body).unwrap()
}
fn quote(ar: &mut Arena, value: u64) -> Order {
    let value = atom(ar, value);
    op(ar, 1, value)
}
fn binary(ar: &mut Arena, tag: u64, a: Order, b: Order) -> Order {
    let body = ar.pair(a, b).unwrap();
    op(ar, tag, body)
}
fn branch(ar: &mut Arena, test: Order, yes: Order, no: Order) -> Order {
    let arms = ar.pair(yes, no).unwrap();
    binary(ar, 4, test, arms)
}
fn pair(ar: &Arena, id: u32) -> (u32, u32) {
    (ar.head(id).unwrap(), ar.tail(id).unwrap())
}
fn particle(ar: &Arena, id: u32) -> Particle {
    ar.digest(id).unwrap().map(F::as_u64)
}
fn import(ar: &Arena) -> Memory {
    let mut memory =
        Memory::new(ar.count(), ar.count() as usize * size_of::<VerifiedNode>()).unwrap();
    for i in 0..ar.count() {
        let n = ar.get(i).unwrap();
        memory
            .append(Definition {
                value: match n.inner {
                    Data::Atom { value } => Value::Atom(value.as_u64()),
                    Data::Pair { left, right } => Value::Pair { left, right },
                },
                particle: n.hash.map(F::as_u64),
                cost: if n.bound.is_dynamic() {
                    Cost::Dynamic(n.bound.value())
                } else {
                    Cost::Exact(n.bound.value())
                },
            })
            .unwrap();
    }
    memory
}
fn limits() -> Limits {
    Limits {
        max_evaluations: 1024,
        max_buffer_bytes: 1024 * size_of::<VerifiedEvaluation>(),
        max_cost: u64::MAX,
        max_frames: 512,
        max_steps: u64::MAX,
    }
}
fn store(memory: &Memory) -> Evaluations<'_> {
    Evaluations::new(memory.view(memory.len()).unwrap(), limits()).unwrap()
}

#[derive(Clone, Copy)]
struct Native {
    candidate: Candidate,
    cost: u64,
    peak: u32,
}

/// Test-only producer obtains each result from the real native evaluator.
fn derive(ar: &mut Arena, object: u32, formula: u32, records: &mut Vec<Native>) -> u32 {
    let (tag, body) = pair(ar, formula);
    let tag = ar.atom_value(tag).unwrap().as_u64();
    let premises = match tag {
        0 | 1 => Premises::None,
        8 | 13 | 15 => Premises::One(derive(ar, object, body, records)),
        4 => {
            let (test, rest) = pair(ar, body);
            let (yes, no) = pair(ar, rest);
            let test = derive(ar, object, test, records);
            let v = ar
                .atom_value(records[test as usize].candidate.result)
                .unwrap();
            let chosen = if v == F::ZERO { yes } else { no };
            Premises::Two([test, derive(ar, object, chosen, records)])
        }
        _ => {
            let (a, b) = pair(ar, body);
            let a = derive(ar, object, a, records);
            let b = derive(ar, object, b, records);
            if tag == 2 {
                let c = derive(
                    ar,
                    records[a as usize].candidate.result,
                    records[b as usize].candidate.result,
                    records,
                );
                Premises::Three([a, b, c])
            } else {
                Premises::Two([a, b])
            }
        }
    };
    let run = nox::sequential::reduce_cached(
        ar,
        object,
        formula,
        u64::MAX,
        nox::sequential::Limits { max_frames: 512 },
    )
    .unwrap();
    let Outcome::Ok(result, remaining) = run.outcome else {
        panic!("{:?}", run.outcome)
    };
    let id = records.len() as u32;
    records.push(Native {
        candidate: Candidate {
            object,
            formula,
            result,
            premises,
        },
        cost: u64::MAX - remaining,
        peak: run.peak_frames,
    });
    id
}

fn verified<'a>(memory: &'a Memory, records: &[Native]) -> Evaluations<'a> {
    let mut evals = store(memory);
    for (i, record) in records.iter().enumerate() {
        assert_eq!(evals.append(record.candidate), Ok(i as u32));
        let result = evals.get(i as u32).unwrap();
        assert_eq!(result.cost(), record.cost);
        assert_eq!(result.peak_frames(), record.peak);
    }
    evals
}

fn claim(ar: &Arena, native: Native) -> Claim {
    Claim {
        object: particle(ar, native.candidate.object),
        formula: particle(ar, native.candidate.formula),
        result: particle(ar, native.candidate.result),
        cost: native.cost,
        budget: native.cost,
        max_frames: native.peak,
    }
}
