// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! Wire form of the lens opening inside a [`Proof`](crate::types::Proof).
//!
//! `lens::Opening::Tensor` carries, per proximity query, the queried
//! codeword index AND the 8-byte codeword symbol at that index. The
//! Brakedown verifier reads the index (it must equal the transcript-derived
//! one) and never the symbol: the commitment is a flat hemera hash of the
//! whole codeword, so a single symbol cannot be authenticated against it,
//! and the verifier does not try. Those symbols were 2 080 inert bytes in a
//! 4.5 KiB proof — bytes a flipped bit could not disturb. The rule for the
//! wire is that every byte outside the artifact's operational metadata is
//! verifier-checked, so the opening travels as the indices only; on
//! deserialization the symbols come back empty, which is exactly what the
//! verifier reads.
//!
//! Only `Opening::Tensor` (Brakedown) is a zheng proof opening; any other
//! variant is a serialization error, never silently mapped.

#[cfg(feature = "serde")]
pub mod opening {
    use lens::{Commitment, Opening};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// The bytes a Brakedown opening puts on the wire.
    #[derive(Serialize, Deserialize)]
    struct TensorWire {
        round_commitments: Vec<Commitment>,
        final_poly: Vec<u8>,
        query_indices: Vec<u32>,
    }

    pub fn serialize<S: Serializer>(opening: &Opening, s: S) -> Result<S::Ok, S::Error> {
        let Opening::Tensor { round_commitments, final_poly, query_responses } = opening else {
            return Err(serde::ser::Error::custom("zheng proof opening is Brakedown Tensor"));
        };
        let query_indices = query_responses
            .iter()
            .map(|(idx, _)| u32::try_from(*idx).map_err(serde::ser::Error::custom))
            .collect::<Result<Vec<u32>, _>>()?;
        TensorWire {
            round_commitments: round_commitments.clone(),
            final_poly: final_poly.clone(),
            query_indices,
        }
        .serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Opening, D::Error> {
        let w = TensorWire::deserialize(d)?;
        Ok(Opening::Tensor {
            round_commitments: w.round_commitments,
            final_poly: w.final_poly,
            query_responses: w.query_indices.into_iter().map(|i| (i as usize, Vec::new())).collect(),
        })
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use lens::Opening;
    use lens::brakedown::Brakedown;
    use lens::{Lens, MultilinearPoly, Transcript as LensTranscript};
    use nebu::Goldilocks;

    #[derive(serde::Serialize, serde::Deserialize)]
    struct Holder {
        #[serde(with = "super::opening")]
        opening: Opening,
    }

    /// Round-tripping drops the codeword symbols and keeps everything the
    /// Brakedown verifier reads; the restored opening still verifies.
    #[test]
    fn wire_opening_keeps_what_the_verifier_reads() {
        let poly = MultilinearPoly::new((1u64..=16).map(Goldilocks::new).collect());
        let commitment = Brakedown::commit(&poly);
        let point: Vec<Goldilocks> = (3u64..7).map(Goldilocks::new).collect();
        let value = poly.evaluate(&point);
        let mut lt = LensTranscript::new(b"wire");
        let opening = Brakedown::open(&poly, &point, &mut lt);

        let bytes = postcard::to_allocvec(&Holder { opening: opening.clone() }).unwrap();
        let back: Holder = postcard::from_bytes(&bytes).unwrap();
        let Opening::Tensor { query_responses: full, round_commitments: rc, final_poly: fp } = &opening
        else {
            panic!("Brakedown opening is Tensor");
        };
        let Opening::Tensor { query_responses: thin, round_commitments: rc2, final_poly: fp2 } =
            &back.opening
        else {
            panic!("wire form restores a Tensor opening");
        };
        assert_eq!(rc, rc2);
        assert_eq!(fp, fp2);
        assert_eq!(full.len(), thin.len());
        assert!(full.iter().zip(thin).all(|((a, _), (b, v))| a == b && v.is_empty()));
        let full_bytes: usize = full.iter().map(|(_, v)| v.len()).sum();
        assert_eq!(full_bytes, 4 * 20 * 8, "the symbols the wire drops: 20 queries × 8 B per round");

        let mut vt = LensTranscript::new(b"wire");
        assert!(Brakedown::verify(&commitment, &point, value, &back.opening, &mut vt));
    }
}
