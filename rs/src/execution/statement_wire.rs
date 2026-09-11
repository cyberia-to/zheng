//! Bound public vectors while decoding, before allocating attacker-sized data.
use super::statement::{MAX_INPUTS, MAX_OUTPUTS, MAX_PROGRAM_NODES, NounToken};
use serde::{
    Deserialize, Deserializer,
    de::{Error, SeqAccess, Visitor},
};
use std::{fmt, marker::PhantomData};
fn bounded<'de, D, T, const LIMIT: usize>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Bounded<T, const N: usize>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for Bounded<T, N> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "at most {N} elements")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            if seq.size_hint().is_some_and(|n| n > N) {
                return Err(A::Error::custom("public statement vector exceeds bound"));
            }
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(N));
            while let Some(value) = seq.next_element()? {
                if out.len() == N {
                    return Err(A::Error::custom("public statement vector exceeds bound"));
                }
                out.push(value);
            }
            Ok(out)
        }
    }
    d.deserialize_seq(Bounded::<T, LIMIT>(PhantomData))
}
pub fn program<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<NounToken>, D::Error> {
    bounded::<D, NounToken, MAX_PROGRAM_NODES>(d)
}
pub fn inputs<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u64>, D::Error> {
    bounded::<D, u64, MAX_INPUTS>(d)
}
pub fn outputs<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u64>, D::Error> {
    bounded::<D, u64, MAX_OUTPUTS>(d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::ExecutionStatement;
    #[test]
    fn oversized_public_vectors_are_rejected_during_decoding() {
        let base = ExecutionStatement {
            program: vec![NounToken::Atom(1)],
            public_input: vec![],
            public_output: vec![],
            cycles: 0,
            budget: 1,
        };
        for which in 0..3 {
            let mut s = base.clone();
            match which {
                0 => s.program = vec![NounToken::Pair; MAX_PROGRAM_NODES + 1],
                1 => s.public_input = vec![0; MAX_INPUTS + 1],
                _ => s.public_output = vec![0; MAX_OUTPUTS + 1],
            }
            let bytes = postcard::to_allocvec(&s).unwrap();
            assert!(postcard::from_bytes::<ExecutionStatement>(&bytes).is_err());
        }
    }
}
