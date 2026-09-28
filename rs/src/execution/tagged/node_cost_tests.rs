use super::{
    build::{Builder, Parts},
    node_cost::*,
    *,
};
use nox::data::Data;
use nox::{Order, Reduction};

#[path = "node_cost_tests/adversarial.rs"]
mod adversarial;
#[path = "node_cost_tests/arithmetic.rs"]
mod arithmetic;
#[path = "node_cost_tests/backend.rs"]
mod backend;

struct Component {
    parts: Parts,
    pending: PendingNodeCost,
    usage: (usize, usize),
}

fn build(limit: usize) -> Result<Component, Error> {
    let mut builder = Builder::with_gate_limit(INPUT_FIELDS, limit)?;
    let records: [Record; 7] = std::array::from_fn(|r| {
        Record::from_fields(std::array::from_fn(|i| 3 + r * RECORD_FIELDS + i))
    });
    let pending = builder.noun_cost(2, records[0], records[1..].try_into().unwrap())?;
    let usage = builder.usage();
    Ok(Component {
        parts: builder.component_parts(),
        pending,
        usage,
    })
}

fn witness(component: &Component, inputs: &[u64]) -> CCSWitness {
    candidate_witness(
        &component.parts.instance,
        component.parts.inputs.len(),
        &component.parts.ops,
        inputs,
    )
    .unwrap()
}

fn pins(inputs: &[u64]) -> Vec<(usize, F)> {
    std::iter::once((ZERO, F::ZERO))
        .chain(
            inputs
                .iter()
                .enumerate()
                .map(|(i, &value)| (2 + i, F::new(value))),
        )
        .collect()
}

fn atom(arena: &mut Reduction<1024>, value: u64) -> Order {
    arena.atom(F::new(value)).unwrap()
}
fn pair(arena: &mut Reduction<1024>, left: Order, right: Order) -> Order {
    arena.pair(left, right).unwrap()
}
fn quote(arena: &mut Reduction<1024>, value: u64) -> Order {
    let tag = atom(arena, 1);
    let value = atom(arena, value);
    pair(arena, tag, value)
}
fn binary(arena: &mut Reduction<1024>, tag: u64, a: Order, b: Order) -> Order {
    let body = pair(arena, a, b);
    let tag = atom(arena, tag);
    pair(arena, tag, body)
}
fn branch(arena: &mut Reduction<1024>, test: Order, yes: Order, no: Order) -> Order {
    let rest = pair(arena, yes, no);
    binary(arena, 4, test, rest)
}

fn record(arena: &Reduction<1024>, id: Order) -> [u64; RECORD_FIELDS] {
    let entry = arena.get(id).unwrap();
    let mut row = [0; RECORD_FIELDS];
    row[0] = 1;
    row[3..7].copy_from_slice(&entry.hash.map(|f| f.as_u64()));
    match entry.inner {
        Data::Atom { value } => row[2] = value.as_u64(),
        Data::Pair { left, right } => {
            row[1] = 1;
            row[7..11].copy_from_slice(&arena.get(left).unwrap().hash.map(|f| f.as_u64()));
            row[11..15].copy_from_slice(&arena.get(right).unwrap().hash.map(|f| f.as_u64()));
        }
    }
    row[15] = u64::from(entry.bound.is_dynamic());
    row[16] = entry.bound.value() & u32::MAX as u64;
    row[17] = entry.bound.value() >> 32;
    row
}

// Independent host fixture extraction from actual native cached data entries.
// The relation receives only these fixed slots, never the host arena topology.
fn inputs(arena: &Reduction<1024>, candidate: Order) -> Vec<u64> {
    let mut rows = [[0; RECORD_FIELDS]; 7];
    rows[0] = record(arena, candidate);
    if let Data::Pair { left, right } = arena.get(candidate).unwrap().inner {
        rows[1] = record(arena, left);
        rows[2] = record(arena, right);
        if let Some(tag) = arena.atom_value(left) {
            if let Data::Pair { left: a, right: b } = arena.get(right).unwrap().inner {
                match tag.as_u64() {
                    2 | 3 | 5 | 6 | 7 | 9 | 10 | 11 | 12 | 14 | 17 => {
                        rows[3] = record(arena, a);
                        rows[4] = record(arena, b);
                    }
                    16 => rows[3] = record(arena, a),
                    4 => {
                        rows[4] = record(arena, b);
                        if let Data::Pair { left: y, right: n } = arena.get(b).unwrap().inner {
                            rows[3] = record(arena, a);
                            rows[5] = record(arena, y);
                            rows[6] = record(arena, n);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    std::iter::once(VERSION)
        .chain(rows.into_iter().flatten())
        .collect()
}

fn valid(component: &Component, inputs: &[u64]) -> CCSWitness {
    let w = witness(component, inputs);
    assert!(
        component.parts.instance.is_satisfied_by(&w),
        "native fixture {inputs:?}"
    );
    assert!(pins(inputs).iter().all(|&(i, expected)| w.z[i] == expected));
    for read in component.pending.reads {
        assert_eq!(w.z[read.active], w.z[read.returned.active]);
        for i in 0..4 {
            assert_eq!(
                w.z[read.requested_particle[i]],
                w.z[read.returned.particle[i]]
            );
        }
    }
    w
}

#[test]
fn exact_gate_cap_accepts_and_one_below_cannot_finish_partial_component() {
    let c = build(MAX_GATES).unwrap();
    let required = c.usage.0.max(c.usage.1);
    assert_eq!(build(required).unwrap().usage, c.usage);
    assert!(matches!(build(required - 1), Err(Error::Limit)));
    assert!(matches!(
        Builder::with_gate_limit(INPUT_FIELDS, MAX_GATES + 1),
        Err(Error::Limit)
    ));
    let mut b = Builder::with_gate_limit(INPUT_FIELDS, 1).unwrap();
    // Prepare the output before exhausting the allowance, so finish's failure
    // tests pending-read protection independently of any later row allocation.
    let output = Rc::new(Node {
        id: 0,
        tag: ZERO,
        value: ZERO,
        children: None,
    });
    let records: [Record; 7] = std::array::from_fn(|r| {
        Record::from_fields(std::array::from_fn(|i| 3 + r * RECORD_FIELDS + i))
    });
    assert!(
        b.noun_cost(2, records[0], records[1..].try_into().unwrap())
            .is_err()
    );
    assert_eq!(b.unresolved_reads, READ_PORTS);
    assert!(matches!(
        b.finish(output, ZERO, 0),
        Err(Error::Unsupported(_))
    ));
}

#[test]
fn fixed_schema_fits_declared_cap_and_requires_public_read_premises() {
    let c = build(MAX_GATES).expect("fixed one-definition schema must fit unchanged cap");
    let nnz: usize = c
        .parts
        .instance
        .matrices
        .iter()
        .flat_map(|m| &m.entries)
        .map(Vec::len)
        .sum();
    assert!(nnz <= 1 << 20);
    assert!(c.parts.instance.num_cols <= 65536);
    println!(
        "node-cost-v1 rows_used={} ops_used={} padded_rows={} padded_columns={} nnz={} witness_bytes={}",
        c.usage.0,
        c.usage.1,
        c.parts.instance.num_rows,
        c.parts.instance.num_cols,
        nnz,
        c.parts.instance.num_cols * 8
    );
    let mut b = Builder::new(INPUT_FIELDS);
    let records: [Record; 7] = std::array::from_fn(|r| {
        Record::from_fields(std::array::from_fn(|i| 3 + r * RECORD_FIELDS + i))
    });
    let pending = b
        .noun_cost(2, records[0], records[1..].try_into().unwrap())
        .unwrap();
    assert_eq!(pending.reads.len(), 6);
    assert_eq!(pending.candidate.fields(), records[0].fields());
    let usage = b.usage();
    assert!(matches!(
        b.noun_cost(2, records[0], records[1..].try_into().unwrap()),
        Err(Error::Limit)
    ));
    assert_eq!(
        usage,
        b.usage(),
        "second definition rejects without extending builder"
    );
    let output = b.zero().unwrap();
    assert!(matches!(
        b.finish(output, ZERO, 0),
        Err(Error::Unsupported(_))
    ));
}

#[test]
fn every_metadata_opcode_and_malformed_body_matches_native_cost() {
    let component = build(MAX_GATES).unwrap();
    let mut count = 0;
    for tag in 0..=18 {
        let mut ar = Reduction::<1024>::new();
        let x = quote(&mut ar, 100);
        let y = quote(&mut ar, 101);
        let dynamic = binary(&mut ar, 2, x, y);
        let rest = pair(&mut ar, y, dynamic);
        let body = pair(&mut ar, x, rest);
        let code = atom(&mut ar, tag);
        let malformed = atom(&mut ar, 555);
        for value in [body, dynamic, malformed] {
            let root = pair(&mut ar, code, value);
            valid(&component, &inputs(&ar, root));
            count += 1;
        }
        let bad_head = pair(&mut ar, x, y);
        let root = pair(&mut ar, bad_head, body);
        valid(&component, &inputs(&ar, root));
        count += 1;
    }
    for value in [0, 1, 1 << 32, nebu::field::P - 1] {
        let mut ar = Reduction::<1024>::new();
        let root = atom(&mut ar, value);
        valid(&component, &inputs(&ar, root));
        count += 1;
    }
    valid(
        &component,
        &std::iter::once(VERSION).chain([0; 126]).collect::<Vec<_>>(),
    );
    println!("native metadata vectors={}", count + 1);
}
