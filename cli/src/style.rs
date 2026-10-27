// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! Terminal styling — matched to the rune / hemera CLI aesthetic: a gradient
//! ASCII-art mark, a white tagline, a gray spec block, aligned command lists,
//! and colored status. Color is gated on a `bool` the caller derives from
//! `stdout().is_terminal()` (off when piped, so machine output stays clean).

pub const R: &str = "\x1b[31m"; // red
pub const Y: &str = "\x1b[33m"; // yellow
pub const G: &str = "\x1b[32m"; // green
pub const C: &str = "\x1b[36m"; // cyan
pub const B: &str = "\x1b[34m"; // blue
pub const M: &str = "\x1b[35m"; // magenta
pub const W: &str = "\x1b[37m"; // white
pub const GR: &str = "\x1b[90m"; // gray
pub const DIM: &str = "\x1b[2m"; // dim
pub const X: &str = "\x1b[0m"; // reset

/// Color `s` with `col` when `color`, else return it plain.
pub fn paint(color: bool, col: &str, s: &str) -> String {
    if color { format!("{col}{s}{X}") } else { s.to_string() }
}

/// The gradient ZHENG mark + tagline + spec block (ANSI Shadow font).
pub fn banner(color: bool) -> String {
    let l = |col: &str, s: &str| paint(color, col, s);
    let mut o = String::new();
    o.push('\n');
    o.push_str(&l(R, "  ███████╗██╗  ██╗███████╗███╗   ██╗ ██████╗ \n"));
    o.push_str(&l(Y, "  ╚══███╔╝██║  ██║██╔════╝████╗  ██║██╔════╝ \n"));
    o.push_str(&l(G, "    ███╔╝ ███████║█████╗  ██╔██╗ ██║██║  ███╗\n"));
    o.push_str(&l(C, "   ███╔╝  ██╔══██║██╔══╝  ██║╚██╗██║██║   ██║\n"));
    o.push_str(&l(B, "  ███████╗██║  ██║███████╗██║ ╚████║╚██████╔╝\n"));
    o.push_str(&l(M, "  ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ \n"));
    o.push_str(&l(W, "  証 — native proof system for soft3\n"));
    o.push('\n');
    o.push_str(&l(GR, "  execution proofs: joy prove · joy verify\n"));
    o
}

/// The command list shown by `zheng help`.
pub fn help(color: bool) -> String {
    let g = |s: &str| paint(color, GR, s);
    let mut o = banner(color);
    o.push('\n');
    o.push_str("  zheng run   -e '<formula>' [--object N] [--budget B]   legacy trace statement check\n");
    o.push_str("  zheng demo  hash                                       legacy hash trace statement\n");
    o.push_str("  zheng eval                                             commit/open/verify a polynomial\n");
    o.push_str("  zheng pack  -e '<formula>' … -o <file>                 write a program capsule\n");
    o.push_str("  zheng prove <file>                                     legacy trace proof for a capsule\n");
    o.push('\n');
    o.push_str(&g("  zheng help                                             print this help\n"));
    o.push('\n');
    o.push_str(&g("  output renders to the terminal; piped, it is a tape chunk stream.\n"));
    o.push_str(&g("  exit: 0 verified · 1 prover/verifier error · 2 usage error\n"));
    o
}
