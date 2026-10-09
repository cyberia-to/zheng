//! The recursion circuit: the verifier of a step as rows of a uniform AIR
//! (`specs/recursion.md` § circuit).

pub mod air;
pub mod layout;
pub mod builder;
pub mod trace;

#[cfg(test)]
mod tests;
