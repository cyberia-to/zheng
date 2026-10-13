//! Canonical, bounded byte codec for envelope bodies.
//!
//! Integers are unsigned LEB128 with the shortest encoding only; a field
//! value must also be below p. Lengths are checked against a static bound and
//! against the bytes that remain (every element takes at least one byte)
//! before anything is allocated. Booleans are exactly 0 or 1. Every value has
//! one encoding, so `encode(decode(b)) == b` for every accepted `b`.

use super::EnvelopeError as E;
use nebu::field::P;

#[derive(Default)]
pub(crate) struct Writer {
    pub bytes: Vec<u8>,
}

impl Writer {
    pub fn varint(&mut self, mut v: u64) {
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                self.bytes.push(byte);
                return;
            }
            self.bytes.push(byte | 0x80);
        }
    }
    pub fn len(&mut self, n: usize) {
        self.varint(n as u64);
    }
    pub fn bool(&mut self, b: bool) {
        self.bytes.push(u8::from(b));
    }
    pub fn raw(&mut self, b: &[u8]) {
        self.bytes.extend_from_slice(b);
    }
}

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
    pub fn remaining(&self) -> usize {
        self.bytes.len()
    }
    pub fn raw(&mut self, n: usize) -> Result<&'a [u8], E> {
        if self.bytes.len() < n {
            return Err(E::Truncated);
        }
        let (head, tail) = self.bytes.split_at(n);
        self.bytes = tail;
        Ok(head)
    }
    pub fn byte(&mut self) -> Result<u8, E> {
        Ok(self.raw(1)?[0])
    }
    pub fn varint(&mut self) -> Result<u64, E> {
        let mut value = 0u64;
        for i in 0..10 {
            let byte = self.byte()?;
            let bits = u64::from(byte & 0x7f);
            if i == 9 && bits > 1 {
                return Err(E::NonCanonical); // beyond 64 bits
            }
            value |= bits << (7 * i);
            if byte & 0x80 == 0 {
                if i > 0 && byte == 0 {
                    return Err(E::NonCanonical); // overlong
                }
                return Ok(value);
            }
        }
        Err(E::NonCanonical)
    }
    pub fn field(&mut self) -> Result<u64, E> {
        let v = self.varint()?;
        if v >= P {
            return Err(E::NonCanonical);
        }
        Ok(v)
    }
    /// A length bounded by `max` and by the remaining bytes divided by the
    /// minimum encoded size of one element.
    pub fn len(&mut self, max: usize, min_element_bytes: usize) -> Result<usize, E> {
        let n = self.varint()?;
        let n = usize::try_from(n).map_err(|_| E::TooLarge)?;
        if n > max {
            return Err(E::TooLarge);
        }
        if n.saturating_mul(min_element_bytes) > self.remaining() {
            return Err(E::Truncated);
        }
        Ok(n)
    }
    pub fn bool(&mut self) -> Result<bool, E> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(E::NonCanonical),
        }
    }
    pub fn fields(&mut self, max: usize) -> Result<Vec<u64>, E> {
        let n = self.len(max, 1)?;
        (0..n).map(|_| self.field()).collect()
    }
    pub fn finish(self) -> Result<(), E> {
        if self.bytes.is_empty() { Ok(()) } else { Err(E::TrailingBytes) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(v: u64) -> Vec<u8> {
        let mut w = Writer::default();
        w.varint(v);
        let mut r = Reader::new(&w.bytes);
        assert_eq!(r.varint().unwrap(), v);
        r.finish().unwrap();
        w.bytes
    }

    #[test]
    fn varints_round_trip_with_shortest_encodings() {
        for v in [0, 1, 127, 128, 16383, 16384, P - 1, P, u64::MAX] {
            let bytes = roundtrip(v);
            assert_eq!(bytes.len(), (64 - v.leading_zeros() as usize).div_ceil(7).max(1));
        }
    }

    #[test]
    fn overlong_and_oversized_varints_are_rejected() {
        for bad in [
            vec![0x80, 0x00],             // 0 in two bytes
            vec![0xff, 0x00],             // 127 with a zero continuation
            vec![0x80; 10],               // never terminates within 10 bytes
            [vec![0xff; 9], vec![0x02]].concat(), // 2^64
            vec![0x80],                   // truncated
        ] {
            assert!(Reader::new(&bad).varint().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn fields_bools_and_lengths_are_strict() {
        let mut w = Writer::default();
        w.varint(P);
        assert_eq!(Reader::new(&w.bytes).field(), Err(E::NonCanonical));
        assert_eq!(Reader::new(&[2]).bool(), Err(E::NonCanonical));
        // a length larger than its bound, or than the bytes that follow
        assert_eq!(Reader::new(&[5, 0, 0, 0, 0, 0]).len(4, 1), Err(E::TooLarge));
        assert_eq!(Reader::new(&[3, 0, 0]).len(10, 1), Err(E::Truncated));
        assert_eq!(Reader::new(&[0, 9]).finish(), Err(E::TrailingBytes));
    }
}
