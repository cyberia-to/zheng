// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! Output layer. Interactive (stdout is a terminal): styled ANSI on stdout.
//! Piped: a [[tape]] chunk stream on stdout (machine channel), each run ending
//! with a `render::STATUS` exit-code chunk. Same data, two renderings.

use std::io::{IsTerminal, Write};

use tape::{encode_nested, kv, render, sigil, Chunk, Writer};

use crate::style::{self, paint};

/// One `(label, value)` row of a proof report.
pub type Row = (&'static str, String);

fn tty() -> bool {
    std::io::stdout().is_terminal()
}

fn color() -> bool {
    tty() && std::env::var_os("NO_COLOR").is_none()
}

/// Emit a titled report — styled table when interactive, tape STRUCT chunk when piped.
pub fn report(title: &str, rows: &[Row]) {
    if tty() {
        print_report(title, rows, color());
    } else {
        let pairs: Vec<Chunk> = rows.iter().map(|(k, v)| kv(k, Chunk::text(v))).collect();
        write_tape(&Chunk::new(sigil::BAR, render::STRUCT, encode_nested(&pairs)));
    }
}

fn print_report(title: &str, rows: &[Row], color: bool) {
    let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    println!();
    println!("  {}  {}", paint(color, style::C, "証"), paint(color, style::W, title));
    for (k, v) in rows {
        let key = paint(color, style::GR, &format!("{k:<width$}"));
        let val = match *k {
            "verify" => {
                let col = if v == "ok" { style::G } else { style::R };
                paint(color, col, v)
            }
            k if k.ends_with("_ms") => paint(color, style::DIM, v),
            _ => paint(color, style::W, v),
        };
        println!("    {key}  {val}");
    }
    println!();
}

/// Emit a typed error — red line when interactive, tape error chunk when piped.
pub fn error(message: &str) {
    if tty() {
        println!("  {} {}", paint(color(), style::R, "✗"), paint(color(), style::R, message));
    } else {
        write_tape(&Chunk::error(message));
    }
}

/// Emit the end-of-command status sentinel. Machine stream only — interactively
/// the process exit code carries the same information.
pub fn status(code: i32) {
    if !tty() {
        write_tape(&Chunk::status(code));
    }
}

fn write_tape(chunk: &Chunk) {
    let stdout = std::io::stdout();
    let mut writer = Writer::new(stdout.lock());
    // A broken pipe on stdout is not worth aborting the process over.
    let _ = writer.write_chunk(chunk);
    let _ = writer.into_inner().flush();
}
