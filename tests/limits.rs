//! The contract of the cost classes: each public operation of the crate names one class in its documentation, so a
//! host can admit it. The `unreachable_pub` lint denies a `pub` item that the crate root cannot reach, so each
//! `pub fn` in the source is public API.

use std::fs;
use std::path::{Path, PathBuf};

/// The classes of `rsauthnz::limits::Class`, as the documentation names them.
const CLASSES: [&str; 4] = ["Parse", "Verify", "Mutate", "External"];

/// Each Rust source file under `dir`.
fn sources(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("source directory") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            sources(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

/// The classes that the documentation above line `at` names, in the form "Cost class: [`Parse`]".
fn named_classes(lines: &[&str], at: usize) -> Vec<String> {
    lines[..at]
        .iter()
        .rev()
        .map(|line| line.trim_start())
        .skip_while(|line| line.starts_with("#["))
        .take_while(|line| line.starts_with("///"))
        .filter_map(|line| line.split("Cost class: [`").nth(1))
        .map(|rest| rest.split('`').next().unwrap_or_default().to_owned())
        .collect()
}

#[test]
fn each_public_operation_names_one_cost_class() {
    let mut files = Vec::new();
    sources(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut files);
    let (mut operations, mut wrong) = (0, Vec::new());
    for file in &files {
        let text = fs::read_to_string(file).expect("source file");
        let lines: Vec<&str> = text.lines().collect();
        for (at, line) in lines.iter().enumerate() {
            let code = line.trim_start();
            let Some(rest) = code
                .strip_prefix("pub fn ")
                .or_else(|| code.strip_prefix("pub const fn "))
            else {
                continue;
            };
            // The signature runs to the line that opens the body.
            let end = lines[at..]
                .iter()
                .position(|line| line.trim_end().ends_with('{'))
                .map_or(at, |end| at + end);
            let signature = lines[at..=end].join(" ");
            let parameters = signature.split_once('(').map_or("", |(_, parameters)| parameters);
            // A method that takes only `&self` and returns no `Result` reads a bounded value: it is not an operation.
            if parameters.starts_with("&self)") && !signature.contains("Result<") {
                continue;
            }
            operations += 1;
            let classes = named_classes(&lines, at);
            if classes.len() != 1 || !CLASSES.contains(&classes[0].as_str()) {
                let name = rest.split(['(', '<']).next().unwrap_or_default();
                wrong.push(format!("{}: {name} names {classes:?}", file.display()));
            }
        }
    }
    assert!(operations > 0, "the scan found no public operation");
    assert!(
        wrong.is_empty(),
        "each public operation must name one cost class:\n{}",
        wrong.join("\n")
    );
}
