use super::{
    facts::{atom, pair, particle},
    types::{Metrics, Output},
    *,
};

impl Activation {
    pub fn enter(
        memory: &View<'_>,
        object: u32,
        formula: u32,
        expected: InputKey,
        limits: Limits,
    ) -> Result<Self, Error> {
        let key = InputKey {
            object: particle(memory, object)?,
            formula: particle(memory, formula)?,
        };
        if key != expected {
            return Err(Error::Key);
        }
        let bound = memory.get(formula).map_err(|_| Error::Noun)?.cost();
        let (tag, body) = pair(memory, formula)?;
        let tag = atom(memory, tag)?;
        if tag > 15 {
            return Err(Error::UnsupportedOpcode);
        }
        let cost = [1, 1, 1, 1, 1, 1, 1, 1, 64, 1, 64, 32, 32, 32, 32, 25][tag as usize];
        let metrics = Metrics::leaf(cost, limits)?;
        let stage = match tag {
            0 => Stage::Ready(Output::axis(memory, object, body)?),
            1 => Stage::Ready(Output::Equal(particle(memory, body)?)),
            8 | 13 | 15 => Stage::Unary {
                tag,
                formula: particle(memory, body)?,
            },
            4 => {
                let (test, arms) = pair(memory, body)?;
                let (yes, no) = pair(memory, arms)?;
                Stage::BranchTest {
                    test: particle(memory, test)?,
                    yes: particle(memory, yes)?,
                    no: particle(memory, no)?,
                }
            }
            _ => {
                let (a, b) = pair(memory, body)?;
                Stage::BinaryLeft {
                    tag,
                    a: particle(memory, a)?,
                    b: particle(memory, b)?,
                }
            }
        };
        Ok(Self {
            key,
            bound,
            metrics,
            stage,
        })
    }

    pub fn expected(&self) -> Option<InputKey> {
        let formula = match self.stage {
            Stage::Ready(_) => return None,
            Stage::Unary { formula, .. } | Stage::BranchChosen { formula } => formula,
            Stage::BinaryLeft { a, .. } => a,
            Stage::BinaryRight { b, .. } => b,
            Stage::BranchTest { test, .. } => test,
            Stage::Continuation(key) => return Some(key),
        };
        Some(InputKey {
            object: self.key.object,
            formula,
        })
    }

    pub fn accept(&mut self, summary: VerifiedSummary, limits: Limits) -> Result<(), Error> {
        if self.expected() != Some(summary.key) {
            return Err(Error::Key);
        }
        let metrics = self.metrics.add(summary.metrics, limits)?;
        let result = summary.result;
        let stage = match self.stage {
            Stage::Unary { tag, .. } => Stage::Ready(Output::unary(tag, result)?),
            Stage::BinaryLeft { tag, b, .. } => Stage::BinaryRight {
                tag,
                b,
                left: result,
            },
            Stage::BinaryRight { tag: 2, left, .. } => Stage::Continuation(InputKey {
                object: left.particle(),
                formula: result.particle(),
            }),
            Stage::BinaryRight { tag, left, .. } => {
                Stage::Ready(Output::binary(tag, left, result)?)
            }
            Stage::BranchTest { yes, no, .. } => Stage::BranchChosen {
                formula: if result.atom()? == 0 { yes } else { no },
            },
            Stage::BranchChosen { .. } | Stage::Continuation(_) => {
                Stage::Ready(Output::Equal(result.particle()))
            }
            Stage::Ready(_) => return Err(Error::State),
        };
        self.metrics = metrics;
        self.stage = stage;
        Ok(())
    }
}
