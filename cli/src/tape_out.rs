// ---
// tags: zheng, rust
// crystal-type: source
// crystal-domain: comp
// ---
//! Tape output layer: proof reports, errors, and status as [[tape]] chunks.
//!
//! stdout carries a tape chunk stream (machine / cyb-terminal channel); every
//! run ends with a `render::STATUS` chunk holding the exit code. A matching
//! human-readable summary goes to stderr.

use std::io::Write;

use tape::{encode_nested, kv, render, sigil, Chunk, Writer};

/// One `(label, value)` row of a proof report.
pub type Row = (&'static str, String);

/// Emit a report as a `(sigil::BAR, render::STRUCT)` chunk of `kv` pairs to
/// stdout, and a readable table to stderr.
pub fn report(title: &str, rows: &[Row]) {
    let pairs: Vec<Chunk> = rows
        .iter()
        .map(|(k, v)| kv(k, Chunk::text(v)))
        .collect();
    let payload = encode_nested(&pairs);
    let chunk = Chunk::new(sigil::BAR, render::STRUCT, payload);
    write_stdout(&chunk);

    eprintln!("── {title} ──");
    let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    for (k, v) in rows {
        eprintln!("  {k:<width$}  {v}");
    }
}

/// Emit a typed error chunk to stdout and a readable line to stderr.
pub fn error(message: &str) {
    write_stdout(&Chunk::error(message));
    eprintln!("error: {message}");
}

/// Emit the end-of-command status sentinel (exit code) to stdout.
pub fn status(code: i32) {
    write_stdout(&Chunk::status(code));
}

fn write_stdout(chunk: &Chunk) {
    let stdout = std::io::stdout();
    let mut writer = Writer::new(stdout.lock());
    // A broken pipe on stdout is not worth aborting the process over.
    let _ = writer.write_chunk(chunk);
    let _ = writer.into_inner().flush();
}
