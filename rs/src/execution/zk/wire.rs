use super::{
    PrivateError,
    circuit::Circuit,
    views::{FirstMessage, Seed, View},
};
use nebu::{Goldilocks as F, field::P};

pub(super) const MAGIC: &[u8; 8] = b"ZHMITH01";

pub(super) fn header(circuit: &Circuit, out: &mut Vec<u8>) {
    out.extend_from_slice(MAGIC);
    for dimension in [
        circuit.inputs,
        circuit.products.len(),
        circuit.outputs.len(),
    ] {
        out.extend_from_slice(&(dimension as u32).to_le_bytes());
    }
}

fn fields(values: &[F], out: &mut Vec<u8>) {
    for v in values {
        out.extend_from_slice(&v.as_u64().to_le_bytes());
    }
}

pub(super) fn encode_round(
    circuit: &Circuit,
    challenge: u8,
    message: &FirstMessage,
    views: &[View; 3],
    out: &mut Vec<u8>,
) {
    let e = challenge as usize;
    let neighbor = (e + 1) % 3;
    let hidden = (e + 2) % 3;
    out.push(challenge);
    out.extend_from_slice(&message.commitments[hidden]);
    fields(&message.outputs[hidden], out);
    out.extend_from_slice(&views[e].seed);
    out.extend_from_slice(&views[neighbor].seed);
    if e != 0 {
        fields(&views[2].wires[..circuit.inputs], out);
    }
    fields(&views[neighbor].wires[circuit.inputs..], out);
}

pub(super) struct Reader<'a> {
    bytes: &'a [u8],
}
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8], circuit: &Circuit) -> Result<Self, PrivateError> {
        let mut reader = Self { bytes };
        if reader.take(8)? != MAGIC {
            return Err(PrivateError::InvalidProof);
        }
        for expected in [
            circuit.inputs,
            circuit.products.len(),
            circuit.outputs.len(),
        ] {
            let actual = u32::from_le_bytes(
                reader
                    .take(4)?
                    .try_into()
                    .map_err(|_| PrivateError::InvalidProof)?,
            );
            if actual as usize != expected {
                return Err(PrivateError::InvalidProof);
            }
        }
        Ok(reader)
    }
    pub fn take(&mut self, length: usize) -> Result<&'a [u8], PrivateError> {
        let result = self.bytes.get(..length).ok_or(PrivateError::InvalidProof)?;
        self.bytes = &self.bytes[length..];
        Ok(result)
    }
    pub fn seed(&mut self) -> Result<Seed, PrivateError> {
        self.take(32)?
            .try_into()
            .map_err(|_| PrivateError::InvalidProof)
    }
    pub fn fields(&mut self, length: usize) -> Result<Vec<F>, PrivateError> {
        let length = length.checked_mul(8).ok_or(PrivateError::InvalidProof)?;
        self.take(length)?
            .chunks_exact(8)
            .map(|bytes| {
                let value =
                    u64::from_le_bytes(bytes.try_into().map_err(|_| PrivateError::InvalidProof)?);
                if value >= P {
                    return Err(PrivateError::InvalidProof);
                }
                Ok(F::new(value))
            })
            .collect()
    }
    pub fn complete(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[cfg(feature = "serde")]
pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    use serde::de::{Error, SeqAccess, Visitor};
    struct Bounded;
    impl<'de> Visitor<'de> for Bounded {
        type Value = Vec<u8>;
        fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "at most {} proof bytes", super::MAX_BYTES)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
            if seq.size_hint().is_some_and(|n| n > super::MAX_BYTES) {
                return Err(A::Error::custom("private proof exceeds byte limit"));
            }
            // An admitted but truncated length hint cannot allocate its claim.
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(4096));
            while let Some(byte) = seq.next_element()? {
                if out.len() == super::MAX_BYTES {
                    return Err(A::Error::custom("private proof exceeds byte limit"));
                }
                out.push(byte);
            }
            Ok(out)
        }
    }
    d.deserialize_seq(Bounded)
}
