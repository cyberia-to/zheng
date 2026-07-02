// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! Bracket-syntax formula parser: `[a b c]` → right-nested nox pairs.
//!
//! Same grammar as the `nox` CLI. Atoms are u64 decimals; `[a b c]` builds
//! `pair(a, pair(b, c))`. A bracket needs at least two elements.

use nebu::Goldilocks;
use nox::{Order, Reduction};

/// Order arena size for CLI programs (~6 MB; run under a large-stack thread).
pub const ORDER_SIZE: usize = 65536;

/// Cap on formula nesting depth — bounds parser recursion on adversarial input.
const MAX_DEPTH: usize = 64;

#[derive(PartialEq, Eq, Debug)]
enum Token {
    Open,
    Close,
    Num(u64),
}

fn tokenize(input: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            '[' => { tokens.push(Token::Open); chars.next(); }
            ']' => { tokens.push(Token::Close); chars.next(); }
            c if c.is_whitespace() => { chars.next(); }
            c if c.is_ascii_digit() => {
                let mut num = String::new();
                while let Some(&d) = chars.peek() {
                    if d.is_ascii_digit() { num.push(d); chars.next(); } else { break; }
                }
                let v: u64 = num.parse().map_err(|e| format!("bad number '{num}': {e}"))?;
                tokens.push(Token::Num(v));
            }
            other => return Err(format!("unexpected character '{other}' in formula")),
        }
    }
    Ok(tokens)
}

/// Parse `input` into a noun tree allocated in `reduction`; return its root Order.
pub fn parse<const N: usize>(
    reduction: &mut Reduction<N>,
    input: &str,
) -> Result<Order, String> {
    let tokens = tokenize(input)?;
    let mut pos = 0;
    let root = parse_expr(reduction, &tokens, &mut pos, 0)?;
    if pos != tokens.len() {
        return Err(format!("unexpected trailing tokens after position {pos}"));
    }
    Ok(root)
}

fn parse_expr<const N: usize>(
    reduction: &mut Reduction<N>,
    tokens: &[Token],
    pos: &mut usize,
    depth: usize,
) -> Result<Order, String> {
    if depth > MAX_DEPTH {
        return Err("formula nesting too deep".to_string());
    }
    match tokens.get(*pos) {
        Some(Token::Num(v)) => {
            *pos += 1;
            reduction.atom(Goldilocks::new(*v)).ok_or_else(|| "order arena full".to_string())
        }
        Some(Token::Open) => {
            *pos += 1;
            let mut elems = Vec::new();
            while tokens.get(*pos) != Some(&Token::Close) {
                if *pos >= tokens.len() {
                    return Err("unterminated '['".to_string());
                }
                elems.push(parse_expr(reduction, tokens, pos, depth + 1)?);
            }
            *pos += 1; // consume ']'
            if elems.len() < 2 {
                return Err("a bracket pair needs at least two elements".to_string());
            }
            // Right-nested pairs: [a b c] → pair(a, pair(b, c)).
            let mut it = elems.into_iter().rev();
            let mut acc = it.next().unwrap();
            for e in it {
                acc = reduction.pair(e, acc).ok_or_else(|| "order arena full".to_string())?;
            }
            Ok(acc)
        }
        Some(Token::Close) => Err("unexpected ']'".to_string()),
        None => Err("empty formula".to_string()),
    }
}
