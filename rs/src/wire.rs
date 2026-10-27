//! Authenticated Brakedown opening wire format.
//!
//! Every queried column and Merkle path is retained. The former Tensor
//! encoding discarded symbols and cannot represent the authenticated PCS.
//! Legacy unauthenticated openings are explicitly rejected.

#[cfg(feature = "serde")]
pub mod opening {
    use lens::Opening;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(opening: &Opening, s: S) -> Result<S::Ok, S::Error> {
        if !matches!(opening, Opening::TensorMerkle { .. }) {
            return Err(serde::ser::Error::custom(
                "zheng requires an authenticated TensorMerkle opening",
            ));
        }
        opening.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Opening, D::Error> {
        let opening = Opening::deserialize(d)?;
        if !matches!(opening, Opening::TensorMerkle { .. }) {
            return Err(serde::de::Error::custom(
                "zheng requires an authenticated TensorMerkle opening",
            ));
        }
        Ok(opening)
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use lens::brakedown::Brakedown;
    use lens::{Lens, MultilinearPoly, Opening, Transcript};
    use nebu::Goldilocks;

    #[derive(serde::Serialize, serde::Deserialize)]
    struct Holder {
        #[serde(with = "super::opening")]
        opening: Opening,
    }

    #[test]
    fn authenticated_opening_roundtrip_preserves_columns_and_paths() {
        let poly = MultilinearPoly::new((1u64..=16).map(Goldilocks::new).collect());
        let commitment = Brakedown::commit(&poly);
        let point: Vec<Goldilocks> = (3u64..7).map(Goldilocks::new).collect();
        let value = poly.evaluate(&point);
        let opening = Brakedown::open(&poly, &point, &mut Transcript::new(b"wire"));
        let bytes = postcard::to_allocvec(&Holder {
            opening: opening.clone(),
        })
        .unwrap();
        let mut back: Holder = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(opening, back.opening);
        assert!(Brakedown::verify(
            &commitment,
            &point,
            value,
            &back.opening,
            &mut Transcript::new(b"wire")
        ));
        let Opening::TensorMerkle { columns, .. } = &mut back.opening else {
            unreachable!()
        };
        columns[0].column[0] ^= 1;
        assert!(!Brakedown::verify(
            &commitment,
            &point,
            value,
            &back.opening,
            &mut Transcript::new(b"wire")
        ));
    }

    #[test]
    fn legacy_unauthenticated_openings_are_rejected_on_both_wire_directions() {
        let opening = Opening::Tensor {
            round_commitments: vec![],
            final_poly: vec![],
            query_responses: vec![],
        };
        assert!(
            postcard::to_allocvec(&Holder {
                opening: opening.clone()
            })
            .is_err()
        );
        let bytes = postcard::to_allocvec(&opening).unwrap();
        assert!(postcard::from_bytes::<Holder>(&bytes).is_err());
    }
}
