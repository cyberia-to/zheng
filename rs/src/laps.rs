//! `ZHENG_TIMING` laps for the one-relation prover: wall milliseconds since
//! the timer started, on stderr, only when the variable is set.

pub(crate) fn timer(scope: &'static str) -> impl Fn(&str) {
    let on = std::env::var_os("ZHENG_TIMING").is_some();
    let clock = std::time::Instant::now();
    move |what: &str| {
        if on {
            eprintln!("  {scope} {what}: {:.1} ms", clock.elapsed().as_secs_f64() * 1e3);
        }
    }
}
