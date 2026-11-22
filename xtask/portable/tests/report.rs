//! The report of the portable consumer on the native host. `cargo xtask portable` compares the report of each browser
//! with the same expected text.

use core::time::Duration;

#[test]
fn each_case_gives_its_expected_line_on_the_native_host() {
    let report = rsauthnz_portable::report([7; 32], Duration::from_secs(1_800_000_000));
    assert_eq!(report, include_str!("../report.txt"));
}
