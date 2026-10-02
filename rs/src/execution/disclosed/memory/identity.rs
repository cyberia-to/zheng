use super::Particle;

fn unpack(hash: hemera::Hash) -> Particle {
    std::array::from_fn(|i| {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&hash.as_bytes()[i * 8..i * 8 + 8]);
        nebu::Goldilocks::new(u64::from_le_bytes(bytes)).as_u64()
    })
}

fn pack(particle: Particle) -> hemera::Hash {
    let mut bytes = [0; 32];
    for (i, limb) in particle.into_iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    hemera::Hash::from_bytes(bytes)
}

pub(super) fn atom(value: u64) -> Particle {
    unpack(hemera::tree::hash_leaf(&value.to_le_bytes(), 0, false))
}

pub(super) fn pair(left: Particle, right: Particle) -> Particle {
    unpack(hemera::tree::hash_node(&pack(left), &pack(right), false))
}
