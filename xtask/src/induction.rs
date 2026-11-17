//! Complete inductive steps, split into native jobs under one result budget.
//!
//! `induction.matrix` names the proof domains. `preservation.matrix` names the
//! modules that a Step reads and the native jobs of its logical groups.

use core::time::Duration;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    time::Instant,
};

use crate::{Checkers, Failure, Kind, PROFILE_SECONDS, Profile, evidence};
use rscrypto::Sha256;

/// The available memory that one native job reserves before it starts. It is
/// an admission estimate, not a hard limit.
const JOB_RESERVATION_GIB: u64 = 6;

struct Domain {
    module: String,
    cinit: String,
    init: String,
}

/// The job plan of `preservation.matrix`.
struct Plan {
    /// The module and operator of the next-state relation.
    next: [String; 2],
    /// The module and operator of the inductive invariant, and its type predicate.
    invariant: [String; 3],
    /// The operator that makes a group's starting set from its assumptions.
    start: String,
    /// The shared module and its disjunction of logical groups.
    shared: [String; 2],
    /// Each component that the named groups check one clause at a time.
    clauses: Vec<(String, BTreeSet<String>)>,
    /// For each domain, the groups that start first, in order.
    first: BTreeMap<String, Vec<String>>,
    /// For each domain and group, its native jobs.
    splits: BTreeMap<(String, String), Split>,
}

enum Split {
    /// One job for each suffix and target. A suffix with no target takes the remaining targets.
    Targets(Vec<(String, Option<String>)>),
    /// One job for each action, through aliases in the named generated module.
    Actions(String),
}

struct Batch {
    name: String,
    actions: Vec<String>,
    assumptions: Vec<String>,
    components: Vec<String>,
    targets: Vec<String>,
    init: String,
    /// The body of the group's step relation.
    relation: String,
}

struct Coverage {
    batches: Vec<Batch>,
    components: Vec<String>,
}

#[derive(Clone)]
struct Job {
    name: String,
    group: String,
    actions: Vec<String>,
    targets: Vec<String>,
    init: String,
    next: String,
}

fn read(path: &Path) -> Result<String, Failure> {
    fs::read_to_string(path).map_err(|error| Failure::new(format!("{}: {error}", path.display())))
}

/// The rows of a matrix file: no empty line and no `#` comment.
fn rows(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|row| !row.is_empty() && !row.starts_with('#'))
}

fn domains(dir: &Path) -> Result<Vec<Domain>, Failure> {
    let text = read(&dir.join("induction.matrix"))?;
    let mut found = BTreeSet::new();
    let mut domains = Vec::new();
    for row in rows(&text) {
        let fields: Vec<_> = row.split_whitespace().collect();
        let [module, cinit, init] = fields.as_slice() else {
            return Err(Failure::new(
                "induction.matrix: a row needs module, constant initializer, and invariant initializer".to_owned(),
            ));
        };
        if !fields.iter().all(|name| identifier(name)) || !found.insert(*module) {
            return Err(Failure::new(format!(
                "induction.matrix: invalid or repeated domain {row}"
            )));
        }
        domains.push(Domain {
            module: (*module).to_owned(),
            cinit: (*cinit).to_owned(),
            init: (*init).to_owned(),
        });
    }
    if domains.is_empty() {
        return Err(Failure::new("induction.matrix: no proof domains".to_owned()));
    }
    // Removing a manifest row must not silently remove an existing proof group.
    for path in crate::sorted_entries(dir)? {
        if let Some(module) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".Init.apalache"))
            && dir.join(format!("{module}Step.tla")).is_file()
            && !found.contains(module)
        {
            return Err(Failure::new(format!("induction.matrix: missing domain {module}")));
        }
    }
    Ok(domains)
}

/// Read `preservation.matrix`. Each name in it must be a TLA+ identifier.
fn plan(dir: &Path) -> Result<Plan, Failure> {
    let text = read(&dir.join("preservation.matrix"))?;
    let (mut next, mut invariant, mut start, mut shared) = (None, None, None, None);
    let mut clauses = Vec::new();
    let mut first = BTreeMap::new();
    let mut splits = BTreeMap::new();
    let owned = |names: &[&str]| names.iter().map(|name| (*name).to_owned()).collect::<Vec<_>>();
    for row in rows(&text) {
        let fields: Vec<_> = row.split_whitespace().collect();
        let names = fields.iter().flat_map(|field| field.split('='));
        let unsupported = || Failure::new(format!("preservation.matrix: unsupported row {row}"));
        if !names.clone().all(|name| name.is_empty() || identifier(name)) {
            return Err(unsupported());
        }
        let once = match fields.as_slice() {
            ["next", module, operator] => next.replace([(*module).to_owned(), (*operator).to_owned()]).is_none(),
            ["invariant", module, operator, type_predicate] => invariant
                .replace([
                    (*module).to_owned(),
                    (*operator).to_owned(),
                    (*type_predicate).to_owned(),
                ])
                .is_none(),
            ["start", operator] => start.replace((*operator).to_owned()).is_none(),
            ["shared", module, groups] => shared.replace([(*module).to_owned(), (*groups).to_owned()]).is_none(),
            ["clauses", component, groups @ ..] if !groups.is_empty() => {
                clauses.push(((*component).to_owned(), owned(groups).into_iter().collect()));
                true
            }
            ["first", domain, groups @ ..] if !groups.is_empty() => {
                first.insert((*domain).to_owned(), owned(groups)).is_none()
            }
            ["targets", domain, group, parts @ ..] if !parts.is_empty() => {
                let parts = parts
                    .iter()
                    .map(|part| match part.split_once('=') {
                        Some((suffix, target)) => ((*suffix).to_owned(), Some(target.to_owned())),
                        None => ((*part).to_owned(), None),
                    })
                    .collect();
                splits
                    .insert(((*domain).to_owned(), (*group).to_owned()), Split::Targets(parts))
                    .is_none()
            }
            ["actions", domain, group, module] => splits
                .insert(
                    ((*domain).to_owned(), (*group).to_owned()),
                    Split::Actions((*module).to_owned()),
                )
                .is_none(),
            _ => return Err(unsupported()),
        };
        if !once {
            return Err(Failure::new(format!("preservation.matrix: repeated row {row}")));
        }
    }
    let missing = |row: &str| Failure::new(format!("preservation.matrix: no {row} row"));
    Ok(Plan {
        next: next.ok_or_else(|| missing("next"))?,
        invariant: invariant.ok_or_else(|| missing("invariant"))?,
        start: start.ok_or_else(|| missing("start"))?,
        shared: shared.ok_or_else(|| missing("shared"))?,
        clauses,
        first,
        splits,
    })
}

fn identifier(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_alphabetic()) && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Read one top-level definition with an exact signature and an explicit boundary.
/// This is a source format contract, not a general TLA+ parser.
fn body(source: &str, name: &str) -> Result<String, Failure> {
    let clean = evidence::literal_source(source);
    if clean.split_whitespace().filter(|word| *word == "MODULE").count() != 1 {
        return Err(Failure::new(format!("{name}: nested or missing module header")));
    }
    let header = format!("{name} ==");
    let mut found = None;
    let mut collecting = false;
    let mut value = String::new();
    for line in clean.lines().filter(|line| !line.trim().is_empty()) {
        if let Some(rest) = line.strip_prefix(&header) {
            if found.is_some() || collecting {
                return Err(Failure::new(format!("{name}: repeated definition")));
            }
            collecting = true;
            value.push_str(rest);
            value.push('\n');
        } else if collecting {
            if line.starts_with(char::is_whitespace) {
                value.push_str(line);
                value.push('\n');
            } else {
                let next_definition = line.split_once("==").is_some_and(|(lhs, _)| signature(lhs.trim()));
                if !next_definition && declaration(line).is_none() && !line.chars().all(|c| c == '=' || c == '-') {
                    return Err(Failure::new(format!("{name}: unsupported definition boundary {line}")));
                }
                collecting = false;
                found = Some(core::mem::take(&mut value));
            }
        }
    }
    found.ok_or_else(|| Failure::new(format!("{name}: missing or unterminated flat definition")))
}

fn signature(text: &str) -> bool {
    if identifier(text) {
        return true;
    }
    let Some((name, args)) = text.split_once('(') else {
        return false;
    };
    identifier(name)
        && args.strip_suffix(')').is_some_and(|args| {
            args.split(',').all(|arg| {
                let arg = arg.trim();
                identifier(arg) || arg.strip_suffix("(_)").is_some_and(identifier)
            })
        })
}

fn declaration(line: &str) -> Option<&str> {
    let (kind, names) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
    matches!(kind, "CONSTANT" | "CONSTANTS" | "VARIABLE" | "VARIABLES").then_some(names)
}

fn terms(source: &str, name: &str, connective: &str) -> Result<Vec<String>, Failure> {
    let value = body(source, name)?;
    let words: Vec<_> = value.split_whitespace().collect();
    let mut names = Vec::new();
    let mut seen = BTreeSet::new();
    for pair in words.chunks(2) {
        let [operator, term] = pair else {
            return Err(Failure::new(format!("{name}: use a flat list of named operators")));
        };
        if *operator != connective || !identifier(term) || !seen.insert(*term) {
            return Err(Failure::new(format!("{name}: unsupported or repeated term {pair:?}")));
        }
        names.push((*term).to_owned());
    }
    if names.is_empty() {
        return Err(Failure::new(format!("{name}: empty list")));
    }
    Ok(names)
}

/// Read the logical groups of the shared module. Together they must check each
/// action of the next-state relation against each component of the invariant
/// exactly once, each from a start that holds every invariant state.
fn coverage(dir: &Path, plan: &Plan, domains: &[Domain]) -> Result<Coverage, Failure> {
    let [next_module, next] = &plan.next;
    let actions: BTreeSet<_> = terms(&read(&dir.join(format!("{next_module}.tla")))?, next, "\\/")?
        .into_iter()
        .collect();
    let [invariant_module, invariant, type_predicate] = &plan.invariant;
    let components = terms(&read(&dir.join(format!("{invariant_module}.tla")))?, invariant, "/\\")?;
    if !components.contains(type_predicate) {
        return Err(Failure::new(format!(
            "{invariant}: the type predicate {type_predicate} is required"
        )));
    }
    let [shared, groups] = &plan.shared;
    let source = read(&dir.join(format!("{shared}.tla")))?;
    // The checker reads OVERRIDE_<component>, so priming distributes over its clauses.
    let mut clause_targets = BTreeMap::new();
    for (component, split_groups) in &plan.clauses {
        let clauses = terms(&source, &format!("OVERRIDE_{component}"), "/\\")?;
        for group in split_groups {
            clause_targets.insert((component.clone(), group.clone()), clauses.clone());
        }
    }
    let selected = |list: &str| -> Result<Vec<String>, Failure> {
        if body(&source, list)?.trim() == invariant {
            return Ok(components.clone());
        }
        let names = terms(&source, list, "/\\")?;
        if names.iter().any(|term| !components.contains(term)) {
            return Err(Failure::new(format!("{list}: use only {invariant} components")));
        }
        Ok(names)
    };
    let mut protected = vec![plan.start.clone(), groups.clone()];
    let mut covered = BTreeSet::new();
    let mut batches = Vec::new();
    for name in terms(&source, groups, "\\/")? {
        let actions_name = format!("{name}Actions");
        let assumptions_name = format!("{name}Assumptions");
        let components_name = format!("{name}Components");
        let init = format!("{name}Init");
        let batch_actions = terms(&source, &actions_name, "\\/")?;
        let assumptions = selected(&assumptions_name)?;
        let batch_components = selected(&components_name)?;
        if !assumptions.contains(type_predicate) {
            return Err(Failure::new(format!(
                "{assumptions_name}: {type_predicate} is required"
            )));
        }
        // Each wrapper of the start only adds auxiliary variables (the model README, "Inductive proofs").
        if !body(&source, &init)?.contains(&format!("{}({assumptions_name})", plan.start)) {
            return Err(Failure::new(format!(
                "{init}: must start from {}({assumptions_name})",
                plan.start
            )));
        }
        for action in &batch_actions {
            if !actions.contains(action) {
                return Err(Failure::new(format!("{name}: {action} is not in {next}")));
            }
            for component in &batch_components {
                if !covered.insert((action.clone(), component.clone())) {
                    return Err(Failure::new(format!(
                        "{action}/{component}: repeated preservation pair"
                    )));
                }
            }
        }
        let mut targets = Vec::new();
        for component in &batch_components {
            match clause_targets.get(&(component.clone(), name.clone())) {
                Some(clauses) => targets.extend(clauses.iter().map(|clause| format!("{clause}Post"))),
                None => targets.push(format!("{component}Post")),
            }
        }
        protected.extend([
            name.clone(),
            actions_name,
            assumptions_name,
            components_name,
            init.clone(),
        ]);
        batches.push(Batch {
            relation: body(&source, &name)?.trim().to_owned(),
            name,
            actions: batch_actions,
            assumptions,
            components: batch_components,
            targets,
            init,
        });
    }
    let expected: BTreeSet<_> = actions
        .iter()
        .flat_map(|action| {
            components
                .iter()
                .map(move |component| (action.clone(), component.clone()))
        })
        .collect();
    if covered != expected {
        return Err(Failure::new(format!(
            "preservation groups omit action/component pairs: {:?}",
            expected.difference(&covered).collect::<Vec<_>>()
        )));
    }
    let posts: BTreeSet<_> = batches.iter().flat_map(|batch| batch.targets.iter()).collect();
    for post in posts {
        let primed = post.strip_suffix("Post").map(|name| format!("{name}'"));
        if body(&source, post)?.split_whitespace().collect::<Vec<_>>() != [primed.unwrap_or_default()] {
            return Err(Failure::new(format!(
                "{post}: must be exactly its component or clause, primed"
            )));
        }
        protected.push(post.clone());
    }
    // An override could narrow a checked relation, start, or target to a vacuous one.
    let modules = [next_module, invariant_module, shared]
        .into_iter()
        .chain(domains.iter().map(|domain| &domain.module));
    for module in modules {
        let text = evidence::literal_source(&read(&dir.join(format!("{module}.tla")))?);
        for line in text.lines() {
            let overridden = line
                .strip_prefix("OVERRIDE_")
                .and_then(|rest| rest.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).next());
            if let Some(name) = overridden.filter(|name| protected.iter().any(|known| known == name)) {
                return Err(Failure::new(format!(
                    "{module}: OVERRIDE_{name} bypasses a checked preservation definition"
                )));
            }
        }
    }
    Ok(Coverage { batches, components })
}

fn tokens(source: &str) -> Vec<String> {
    evidence::literal_source(source)
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

fn options(path: &Path) -> Result<BTreeMap<String, String>, Failure> {
    let text = read(path)?;
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    if lines.next() != Some("check") {
        return Err(Failure::new(format!(
            "{}: an induction obligation must use check",
            path.display()
        )));
    }
    let mut options = BTreeMap::new();
    for line in lines {
        let Some((key, value)) = line.split_once('=') else {
            return Err(Failure::new(format!(
                "{}: unsupported induction argument {line}",
                path.display()
            )));
        };
        if options.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(Failure::new(format!(
                "{}: duplicate induction argument {key}",
                path.display()
            )));
        }
    }
    Ok(options)
}

/// Validate complete initialization, preservation coverage, and safety for every domain.
pub(crate) fn matrix(dir: &Path) -> Result<(), Failure> {
    if !dir.join("induction.matrix").exists() {
        return Ok(());
    }
    let plan = plan(dir)?;
    let domains = domains(dir)?;
    let coverage = coverage(dir, &plan, &domains)?;
    let shared = &plan.shared[0];
    for domain in &domains {
        let wrapper = format!("{}Step", domain.module);
        let expected = format!(
            "----------------------- MODULE {wrapper} -----------------------\nEXTENDS {}, {shared}\n=============================================================================\n",
            domain.module
        );
        if tokens(&read(&dir.join(format!("{wrapper}.tla")))?) != tokens(&expected) {
            return Err(Failure::new(format!(
                "{wrapper}: must extend only {} and {shared}",
                domain.module
            )));
        }
        for (role, init, invariant, length) in [
            ("Init", "Init", "IndInv", "0"),
            ("Step", domain.init.as_str(), "IndInv", "1"),
            ("Safety", domain.init.as_str(), "Safety", "0"),
        ] {
            let name = format!("{}.{role}.apalache", domain.module);
            let mut actual = options(&dir.join(&name))?;
            let expected: BTreeMap<_, _> = [
                ("--cinit", domain.cinit.as_str()),
                ("--init", init),
                ("--next", "Next"),
                ("--inv", invariant),
                ("--length", length),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
            match (
                actual.remove("--discard-disabled").as_deref(),
                actual.remove("--no-deadlock").as_deref(),
            ) {
                (None, None) | (Some("false"), Some("true")) => {}
                _ => {
                    return Err(Failure::new(format!(
                        "{name}: use --discard-disabled=false and --no-deadlock=true together"
                    )));
                }
            }
            if actual != expected {
                return Err(Failure::new(format!(
                    "{name}: must check the complete {role} obligation"
                )));
            }
        }
        jobs(&coverage, &plan, &domain.module)?;
    }
    let known = |domain: &String| domains.iter().any(|known| known.module == *domain);
    for (domain, groups) in &plan.first {
        if !known(domain)
            || groups
                .iter()
                .any(|group| !coverage.batches.iter().any(|batch| batch.name == *group))
        {
            return Err(Failure::new(format!(
                "preservation.matrix: unknown domain or group in the first row of {domain}"
            )));
        }
    }
    if let Some((domain, group)) = plan.splits.keys().find(|(domain, _)| !known(domain)) {
        return Err(Failure::new(format!(
            "preservation.matrix: unknown domain {domain} for {group}"
        )));
    }
    Ok(())
}

/// An aggregate Step has no separately selectable native cells in the model directory.
pub(crate) fn is_step(profile: &Profile) -> Result<bool, Failure> {
    if !profile.dir.join("induction.matrix").exists() {
        return Ok(false);
    }
    Ok(domains(&profile.dir)?.iter().any(|domain| {
        profile
            .file
            .file_name()
            .is_some_and(|name| name == format!("{}.Step.apalache", domain.module).as_str())
    }))
}

/// Start the listed groups first, in their listed order. Each other group keeps its source order.
fn order(batches: &mut [Batch], first: &[String]) {
    batches.sort_by_key(|batch| first.iter().position(|name| *name == batch.name).unwrap_or(first.len()));
}

/// The native jobs of one domain, in group order. A split keeps the group's start and relation.
fn jobs(coverage: &Coverage, plan: &Plan, domain: &str) -> Result<Vec<Job>, Failure> {
    let mut jobs = Vec::new();
    for batch in &coverage.batches {
        let original = Job {
            name: batch.name.clone(),
            group: batch.name.clone(),
            actions: batch.actions.clone(),
            targets: batch.targets.clone(),
            init: batch.init.clone(),
            next: batch.name.clone(),
        };
        match plan.splits.get(&(domain.to_owned(), batch.name.clone())) {
            None => jobs.push(original),
            Some(Split::Targets(parts)) => {
                for (suffix, target) in parts {
                    let mut job = original.clone();
                    job.name.push_str(suffix);
                    job.targets = match target {
                        Some(target) => vec![target.clone()],
                        None => batch
                            .targets
                            .iter()
                            .filter(|remaining| !parts.iter().any(|(_, named)| named.as_ref() == Some(*remaining)))
                            .cloned()
                            .collect(),
                    };
                    jobs.push(job);
                }
            }
            Some(Split::Actions(_)) => {
                for action in &batch.actions {
                    let mut job = original.clone();
                    job.name.push_str(action);
                    job.next.clone_from(&job.name);
                    job.actions = vec![action.clone()];
                    jobs.push(job);
                }
            }
        }
    }
    validate_jobs(coverage, &jobs)?;
    Ok(jobs)
}

/// Each job keeps its group's start and relation, and the jobs check each group pair once.
fn validate_jobs(coverage: &Coverage, jobs: &[Job]) -> Result<(), Failure> {
    let expected: BTreeSet<_> = coverage
        .batches
        .iter()
        .flat_map(|batch| {
            batch.actions.iter().flat_map(move |action| {
                batch
                    .targets
                    .iter()
                    .map(move |target| (batch.name.clone(), action.clone(), target.clone()))
            })
        })
        .collect();
    let mut names = BTreeSet::new();
    let mut actual = BTreeSet::new();
    for job in jobs {
        let batch = coverage
            .batches
            .iter()
            .find(|batch| batch.name == job.group)
            .ok_or_else(|| Failure::new(format!("{}: unknown logical group", job.name)))?;
        let relation = if job.next == job.group {
            job.actions == batch.actions
        } else {
            job.actions.len() == 1 && job.next == job.name && job.targets == batch.targets
        };
        if !names.insert(&job.name) || job.init != batch.init || job.targets.is_empty() || !relation {
            return Err(Failure::new(format!(
                "{}: repeated job, empty target list, or changed start or relation",
                job.name
            )));
        }
        for action in &job.actions {
            for target in &job.targets {
                let pair = (job.group.clone(), action.clone(), target.clone());
                if !expected.contains(&pair) || !actual.insert(pair) {
                    return Err(Failure::new(format!(
                        "{}: unknown or repeated action/target pair",
                        job.name
                    )));
                }
            }
        }
    }
    if actual != expected {
        return Err(Failure::new("native jobs omit original action/target pairs".to_owned()));
    }
    Ok(())
}

fn batch_record(batch: &Batch) -> String {
    format!(
        "coverage={}:{}:{}\ntargets={}:{}\nassumptions={}:{}\ninitializer={}:{}",
        batch.name,
        batch.actions.join(","),
        batch.components.join(","),
        batch.name,
        batch.targets.join(","),
        batch.name,
        batch.assumptions.join(","),
        batch.name,
        batch.init
    )
}

fn job_record(job: &Job, native: &Profile, cinit: &str) -> String {
    format!(
        "job={}:{}:{}:{}:{}:{}:{}:{}",
        job.name,
        job.group,
        job.actions.join(","),
        job.targets.join(","),
        job.init,
        job.next,
        native.module,
        cinit
    )
}

/// One alias for each action of the group: its relation with the action list
/// replaced by that action. Conjunction distributes over the action disjunction,
/// so the aliases together keep the group's transitions.
fn action_module(module: &str, parent: &str, batch: &Batch) -> Result<String, Failure> {
    let actions_name = format!("{}Actions", batch.name);
    if batch.relation.matches(&actions_name).count() != 1 {
        return Err(Failure::new(format!(
            "{}: an action split needs exactly one {actions_name} in its relation",
            batch.name
        )));
    }
    let mut text = format!("----------------------- MODULE {module} -----------------------\nEXTENDS {parent}\n");
    for action in &batch.actions {
        text.push_str(&format!(
            "{}{action} == {}\n",
            batch.name,
            batch.relation.replace(&actions_name, action)
        ));
    }
    text.push_str("=============================================================================\n");
    Ok(text)
}

/// Generate the exact profiles that the scheduler passes to the native checker.
fn prepare_jobs(
    profile: &Profile,
    coverage: &Coverage,
    plan: &Plan,
    jobs: &[Job],
    out: &Path,
) -> Result<Vec<(Profile, PathBuf)>, Failure> {
    let module = profile
        .module
        .strip_suffix(".tla")
        .ok_or_else(|| Failure::new("Step module has no .tla suffix".to_owned()))?;
    let parent = format!("{module}Step");
    let generated = out.join("action-source");
    let mut action_modules = BTreeMap::new();
    for batch in &coverage.batches {
        if let Some(Split::Actions(name)) = plan.splits.get(&(module.to_owned(), batch.name.clone())) {
            if action_modules.is_empty() {
                evidence::freeze(&profile.dir, &generated)?;
            }
            let file = format!("{name}.tla");
            if generated.join(&file).exists() {
                return Err(Failure::new(format!("{file}: a generated module is already present")));
            }
            let text = action_module(name, &parent, batch)?;
            fs::write(generated.join(&file), text).map_err(|error| Failure::new(error.to_string()))?;
            action_modules.insert(batch.name.clone(), file);
        }
    }
    let mut arguments = options(&profile.file)?;
    // A partial action may be disabled. Preservation checks successors, not enabledness.
    arguments.insert("--discard-disabled".to_owned(), "false".to_owned());
    arguments.insert("--no-deadlock".to_owned(), "true".to_owned());
    let mut prepared = Vec::new();
    for job in jobs {
        arguments.insert("--next".to_owned(), job.next.clone());
        arguments.insert("--init".to_owned(), job.init.clone());
        arguments.insert("--inv".to_owned(), job.targets.join(","));
        let file = out.join(format!("{parent}.{}.apalache", job.name));
        let mut text = "check\n".to_owned();
        for (key, value) in &arguments {
            text.push_str(&format!("{key}={value}\n"));
        }
        text.push_str("--smtprof\n");
        fs::write(&file, text).map_err(|error| Failure::new(error.to_string()))?;
        let (directory, native_module) = match action_modules.get(&job.group) {
            Some(name) if job.next != job.group => (generated.clone(), name.clone()),
            _ => (profile.dir.clone(), format!("{parent}.tla")),
        };
        prepared.push((
            Profile {
                name: format!("{}/{}", profile.name, job.name),
                dir: directory,
                module: native_module,
                file,
                apalache: true,
                kind: Kind::Holds,
                expected: None,
            },
            out.join(&job.name),
        ));
    }
    Ok(prepared)
}

/// The native jobs that this host admits at once: one for each core with 6 GiB
/// of available memory. Only Linux reports available memory, so other hosts run
/// one job at a time.
fn concurrency() -> Result<(usize, Option<u64>), Failure> {
    if !cfg!(target_os = "linux") {
        return Ok((1, None));
    }
    let available_kib = crate::available_memory_kib(&read(Path::new("/proc/meminfo"))?)?;
    let cores = std::thread::available_parallelism().map_or(1, core::num::NonZero::get);
    Ok((slots(cores, available_kib), Some(available_kib)))
}

fn slots(cores: usize, available_kib: u64) -> usize {
    let by_memory = available_kib / JOB_RESERVATION_GIB.saturating_mul(1024 * 1024);
    usize::try_from(by_memory)
        .map_or(cores, |by_memory| by_memory.min(cores))
        .max(1)
}
/// Poll every active result before starting another group. One clock covers all waves.
fn schedule(
    checkers: &Checkers,
    jobs: &[(Profile, PathBuf)],
    slots: usize,
    started: Instant,
    budget: Duration,
    record: &mut fs::File,
) -> (usize, Result<(), Failure>) {
    let mut pending = jobs.iter();
    let mut active: Vec<crate::NativeRun> = Vec::new();
    let mut completed = 0_usize;
    let io_error = |error: std::io::Error| Failure::new(error.to_string());
    let within_budget = || {
        if started.elapsed() >= budget {
            Err(Failure::new(format!(
                "aggregate preservation exceeded {:.3} seconds",
                budget.as_secs_f64()
            )))
        } else {
            Ok(())
        }
    };
    let result = (|| {
        loop {
            within_budget()?;
            let mut index = 0;
            while index < active.len() {
                let status = active[index].child.try_wait().map_err(io_error)?;
                within_budget()?;
                if let Some(status) = status {
                    let native = active.remove(index);
                    let name = native.profile.name.clone();
                    let result = native.finish(status);
                    writeln!(
                        record,
                        "job-{}={name}\nstatus={status}\nelapsed-seconds={:.6}",
                        if result.is_ok() { "pass" } else { "fail" },
                        started.elapsed().as_secs_f64()
                    )
                    .map_err(io_error)?;
                    record.sync_all().map_err(io_error)?;
                    result?;
                    completed = completed.saturating_add(1);
                } else {
                    index = index.saturating_add(1);
                }
            }
            within_budget()?;
            if active.len() < slots
                && let Some((profile, out)) = pending.next()
            {
                writeln!(
                    record,
                    "job-start={}\nelapsed-seconds={:.6}",
                    profile.name,
                    started.elapsed().as_secs_f64()
                )
                .map_err(io_error)?;
                record.sync_all().map_err(io_error)?;
                match checkers.start_native(profile, out) {
                    Ok(native) => active.push(native),
                    Err(error) => {
                        writeln!(record, "job-fail={}\nreason={}", profile.name, error.message).map_err(io_error)?;
                        return Err(error);
                    }
                }
                continue;
            }
            if active.is_empty() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    })();
    if let Err(error) = &result {
        for native in active {
            let name = native.profile.name.clone();
            // Do not let one cleanup or record error skip the other children.
            let cancelled = native.cancel(&error.message);
            let status = match cancelled {
                Ok(status) => status.to_string(),
                Err(failure) => format!("cleanup failed: {}", failure.message),
            };
            eprintln!("   cancelled {name}: {status}");
            if let Err(error) = writeln!(record, "job-cancel={name}\nstatus={status}") {
                eprintln!("   cannot record cancellation: {error}");
            }
        }
    }
    (completed, result)
}

/// Run all native jobs of one Step from one retained revision and one clock
/// start. At the budget, the scheduler kills each running checker, and the
/// Step fails. A late or partial aggregate never passes.
pub(crate) fn run(checkers: &Checkers, profile: &Profile, out: &Path) -> Result<(), Failure> {
    let started = Instant::now();
    let out = evidence::directory(out)?;
    let io_error = |error: std::io::Error| Failure::new(format!("{}: {error}", out.display()));
    let module = profile
        .module
        .strip_suffix(".tla")
        .ok_or_else(|| Failure::new("Step module has no .tla suffix".to_owned()))?;
    let plan = plan(&profile.dir)?;
    let mut coverage = coverage(&profile.dir, &plan, &domains(&profile.dir)?)?;
    order(&mut coverage.batches, plan.first.get(module).map_or(&[], Vec::as_slice));
    let jobs = jobs(&coverage, &plan, module)?;
    let (slots, available_kib) = concurrency()?;
    eprintln!(
        "── preservation {}: {} groups, {} native jobs, {slots} concurrent, one {PROFILE_SECONDS}s budget\n   evidence: {}",
        profile.name,
        coverage.batches.len(),
        jobs.len(),
        out.display()
    );
    let native = Profile {
        name: profile.name.clone(),
        dir: profile.dir.clone(),
        module: format!("{module}Step.tla"),
        file: profile.file.clone(),
        apalache: true,
        kind: Kind::Holds,
        expected: None,
    };
    let closure = evidence::snapshot(&out, &native, &["preservation.matrix"])?;
    let mut record = fs::File::create(out.join("run.txt")).map_err(io_error)?;
    writeln!(record, "state=started\nprofile={}\nrole=aggregate-preservation\nbudget-seconds={PROFILE_SECONDS}\ncheckers={}\nmodel={}\nclosure=sha256:{}\n{closure}", profile.name, checkers.versions, crate::digest(&profile.dir)?, crate::hex(&Sha256::digest(closure.as_bytes()))).map_err(io_error)?;
    writeln!(
        record,
        "concurrency={slots}\nmemory-reservation-gib-per-checker={JOB_RESERVATION_GIB}\nmemory-reservation-kind=admission-not-hard-cap\nhost-available-memory-kib={available_kib:?}"
    )
    .map_err(io_error)?;
    writeln!(
        record,
        "components={}\nlogical-groups={}\nnative-jobs={}",
        coverage.components.join(","),
        coverage.batches.len(),
        jobs.len()
    )
    .map_err(io_error)?;
    for batch in &coverage.batches {
        writeln!(record, "{}", batch_record(batch)).map_err(io_error)?;
    }
    record.sync_all().map_err(io_error)?;
    let result = (|| {
        let prepared = prepare_jobs(profile, &coverage, &plan, &jobs, &out)?;
        let cinit = options(&profile.file)?
            .remove("--cinit")
            .ok_or_else(|| Failure::new("the profile has no constant initializer".to_owned()))?;
        for (job, (native, _)) in jobs.iter().zip(&prepared) {
            writeln!(record, "{}", job_record(job, native, &cinit)).map_err(io_error)?;
        }
        record.sync_all().map_err(io_error)?;
        Ok(prepared)
    })();
    let (completed, result) = match result {
        Ok(jobs) => schedule(
            checkers,
            &jobs,
            slots,
            started,
            Duration::from_secs(PROFILE_SECONDS),
            &mut record,
        ),
        Err(error) => (0, Err(error)),
    };
    let elapsed = started.elapsed();
    let result = if result.is_ok() && elapsed.as_secs() >= PROFILE_SECONDS {
        Err(Failure::new(format!(
            "aggregate preservation exceeded {PROFILE_SECONDS} seconds"
        )))
    } else {
        result
    };
    writeln!(
        record,
        "state=finished\nseconds={:.6}\ncompleted-jobs={completed}\nverdict={}",
        elapsed.as_secs_f64(),
        if result.is_ok() { "pass" } else { "fail" }
    )
    .map_err(io_error)?;
    if let Err(error) = &result {
        writeln!(record, "reason={}", error.message).map_err(io_error)?;
    }
    record.sync_all().map_err(io_error)?;
    if result.is_ok() {
        eprintln!(
            "   all {completed} native preservation jobs passed in {:.2}s",
            elapsed.as_secs_f64()
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use super::matrix;

    /// A small proof directory with two actions, three invariant components, and
    /// one domain whose groups the job plan splits by target and by action.
    struct ProofFixture {
        dir: std::path::PathBuf,
    }

    fn module(name: &str, body: &str) -> String {
        format!(
            "----------------------- MODULE {name} -----------------------\n{body}\n=============================================================================\n"
        )
    }

    const SHARED: &str = "EXTENDS Inv
OVERRIDE_ClauseInv ==
  /\\ ClauseA
  /\\ ClauseB
GroupTakeActions ==
  \\/ Take
GroupTake == Wrap(GroupTakeActions)
GroupTakeAssumptions == IndInv
GroupTakeComponents == IndInv
GroupTakeInit == Lift(Start(GroupTakeAssumptions))
GroupRestoreActions ==
  \\/ Restore
GroupRestore == Wrap(GroupRestoreActions)
GroupRestoreAssumptions ==
  /\\ TypeInd
GroupRestoreComponents == IndInv
GroupRestoreInit == Lift(Start(GroupRestoreAssumptions))
Groups ==
  \\/ GroupTake
  \\/ GroupRestore
TypeIndPost == TypeInd'
RelationInvPost == RelationInv'
ClauseInvPost == ClauseInv'
ClauseAPost == ClauseA'
ClauseBPost == ClauseB'";

    const PLAN: &str = "next Spec Next
invariant Inv IndInv TypeInd
start Start
shared Shared Groups
clauses ClauseInv GroupTake
first Proof GroupRestore
targets Proof GroupTake Type=TypeIndPost Rest
actions Proof GroupRestore ProofStepRestoreJobs
";

    impl ProofFixture {
        fn new(name: &str) -> Self {
            let dir = crate::evidence::directory(&std::env::temp_dir().join(format!("xtask-induction-{name}")))
                .map_err(|error| error.message)
                .expect("scratch directory");
            let fixture = Self { dir };
            fixture.write(
                "Spec.tla",
                &module(
                    "Spec",
                    "EXTENDS Integers\nVARIABLES\n  state\nTake == state' = state + 1\nRestore == state' = state\nNext ==\n  \\/ Take\n  \\/ Restore",
                ),
            );
            fixture.write(
                "Inv.tla",
                &module(
                    "Inv",
                    "EXTENDS Spec\nTypeInd == state \\in Int\nRelationInv == TRUE\nClauseA == TRUE\nClauseB == TRUE\nClauseInv == TRUE\nStart(assumptions) == assumptions\nLift(I) == I\nWrap(A) == A\nIndInv ==\n  /\\ TypeInd\n  /\\ RelationInv\n  /\\ ClauseInv",
                ),
            );
            fixture.write("Shared.tla", &module("Shared", SHARED));
            fixture.write("Proof.tla", &module("Proof", "EXTENDS Inv\nCInit == TRUE"));
            fixture.write("ProofStep.tla", &module("ProofStep", "EXTENDS Proof, Shared"));
            fixture.write("induction.matrix", "Proof CInit IndInit\n");
            fixture.write("preservation.matrix", PLAN);
            for (role, init, inv, length) in [
                ("Init", "Init", "IndInv", 0),
                ("Step", "IndInit", "IndInv", 1),
                ("Safety", "IndInit", "Safety", 0),
            ] {
                fixture.write(
                    &format!("Proof.{role}.apalache"),
                    &format!(
                        "check\n--cinit=CInit\n--init={init}\n--next=Next\n--inv={inv}\n--length={length}\n--discard-disabled=false\n--no-deadlock=true\n"
                    ),
                );
            }
            fixture
        }

        fn write(&self, name: &str, text: &str) {
            std::fs::write(self.dir.join(name), text).expect("write proof input");
        }

        /// The matrix check of this directory after one replacement in one file.
        fn check_with(&self, file: &str, from: &str, to: &str) -> Result<(), String> {
            let path = self.dir.join(file);
            let original = std::fs::read_to_string(&path).expect("proof input");
            assert!(original.contains(from), "{file} lacks {from}");
            self.write(file, &original.replacen(from, to, 1));
            let result = matrix(&self.dir).map_err(|error| error.message);
            self.write(file, &original);
            result
        }
    }

    impl Drop for ProofFixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.dir).expect("remove proof fixture");
        }
    }

    /// The groups must check each action against each invariant component once,
    /// from a start that holds every invariant state, against exact primed targets.
    #[test]
    fn preservation_groups_require_the_complete_product_from_every_invariant_state() {
        let fixture = ProofFixture::new("coverage");
        matrix(&fixture.dir)
            .map_err(|error| error.message)
            .expect("complete product");
        for (file, from, to, message) in [
            (
                "Shared.tla",
                "GroupRestoreComponents == IndInv",
                "GroupRestoreComponents ==\n  /\\ TypeInd",
                "omit",
            ),
            (
                "Shared.tla",
                "  \\/ GroupRestore\n",
                "  \\/ GroupRestore\n  \\/ GroupTake\n",
                "repeated",
            ),
            (
                "Shared.tla",
                "/\\ TypeInd\nGroupRestoreComponents",
                "/\\ TypeInd\n  /\\ Extra\nGroupRestoreComponents",
                "use only IndInv",
            ),
            (
                "Shared.tla",
                "GroupRestoreAssumptions ==\n  /\\ TypeInd",
                "GroupRestoreAssumptions ==\n  /\\ RelationInv",
                "TypeInd is required",
            ),
            (
                "Shared.tla",
                "Lift(Start(GroupRestoreAssumptions))",
                "Lift(GroupRestoreAssumptions)",
                "must start from",
            ),
            (
                "Shared.tla",
                "RelationInvPost == RelationInv'",
                "RelationInvPost == TypeInd'",
                "primed",
            ),
            (
                "Proof.tla",
                "CInit == TRUE",
                "CInit == TRUE\nOVERRIDE_GroupRestoreActions == FALSE",
                "bypasses",
            ),
            (
                "Proof.tla",
                "CInit == TRUE",
                "CInit == TRUE\nOVERRIDE_Start(assumptions) == FALSE",
                "bypasses",
            ),
        ] {
            let result = fixture.check_with(file, from, to);
            assert!(
                matches!(&result, Err(error) if error.contains(message)),
                "{file}: {to:?} gave {result:?}"
            );
        }
    }

    /// A target split must check each target of its group exactly once.
    #[test]
    fn target_splits_must_cover_each_pair_once() {
        let fixture = ProofFixture::new("splits");
        for (to, message) in [
            (
                "targets Proof GroupTake Type=TypeIndPost Relation=RelationInvPost",
                "omit",
            ),
            (
                "targets Proof GroupTake Type=TypeIndPost Again=TypeIndPost Rest",
                "repeated",
            ),
            (
                "targets Proof GroupTake Type=TypeIndPost Other=ClauseInvPost Rest",
                "unknown or repeated",
            ),
        ] {
            let result = fixture.check_with(
                "preservation.matrix",
                "targets Proof GroupTake Type=TypeIndPost Rest",
                to,
            );
            assert!(
                matches!(&result, Err(error) if error.contains(message)),
                "{to} gave {result:?}"
            );
        }
    }

    /// A profile that outlives its cap fails, and its checker is killed and reaped.
    #[cfg(unix)]
    #[test]
    fn profile_cap_kills_the_checker() {
        let mut fixture = CheckerFixture::new();
        fixture.job("late", "time.sleep(60)", "NoError", 0);
        let (profile, out) = fixture.jobs[0].clone();
        let result = fixture
            .checkers
            .run_native(&profile, &out, core::time::Duration::from_millis(500));
        assert!(matches!(&result, Err(error) if error.message.contains("exceeded its cap")));
        fixture.assert_reaped();
    }

    #[cfg(unix)]
    struct CheckerFixture {
        root: std::path::PathBuf,
        checkers: crate::Checkers,
        jobs: Vec<(crate::Profile, std::path::PathBuf)>,
    }

    #[cfg(unix)]
    impl CheckerFixture {
        fn new() -> Self {
            let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("repository root");
            let root = crate::evidence::directory(&repo.join("target/induction-tests"))
                .map_err(|error| error.message)
                .expect("scheduler inputs");
            let source = root.join("source");
            std::fs::create_dir(&source).expect("source directory");
            std::fs::write(source.join("Model.tla"), "---- MODULE Model ----\n====\n").expect("model input");
            let checker = root.join("checker");
            let python = std::process::Command::new("python3")
                .args(["-c", "import sys; print(sys.executable)"])
                .output()
                .expect("installed Python executable");
            assert!(python.status.success(), "cannot find the installed Python executable");
            let python = std::fs::canonicalize(String::from_utf8(python.stdout).expect("Python path").trim())
                .expect("resolve Python launcher");
            std::os::unix::fs::symlink(python, &checker).expect("native fixture executable");
            Self {
                checkers: crate::Checkers {
                    java_bin: root.join("bin"),
                    tla2tools: root.join("unused.jar"),
                    apalache: checker,
                    versions: "scheduler fixture".to_owned(),
                },
                root,
                jobs: Vec::new(),
            }
        }

        fn job(&mut self, name: &str, body: &str, outcome: &str, status: i32) {
            let source = self.root.join("source");
            let file = source.join(format!("Model.{name}.apalache"));
            let program = format!(
                "import os,sys,time; from pathlib import Path; root=Path({:?}); name={name:?}; events=root/'events'; open(events,'a').write(f'start {{name}} {{os.getpid()}}\\n'); {body}; open(events,'a').write(f'finish {{name}} {{os.getpid()}}\\n'); print('The outcome is: {outcome}',flush=True); sys.exit({status})",
                self.root.to_string_lossy()
            );
            std::fs::write(&file, format!("-c\n{program}\n")).expect("fixture profile");
            self.jobs.push((
                crate::Profile {
                    name: name.to_owned(),
                    dir: source,
                    module: "Model.tla".to_owned(),
                    file,
                    apalache: true,
                    kind: crate::Kind::Holds,
                    expected: None,
                },
                self.root.join(name),
            ));
        }

        fn run(&self, slots: usize, budget: core::time::Duration) -> (usize, Result<(), crate::Failure>) {
            let mut record = std::fs::File::create(self.root.join("run.txt")).expect("aggregate record");
            super::schedule(
                &self.checkers,
                &self.jobs,
                slots,
                std::time::Instant::now(),
                budget,
                &mut record,
            )
        }

        fn events(&self) -> String {
            std::fs::read_to_string(self.root.join("events")).expect("native child events")
        }

        fn assert_reaped(&self) {
            for line in self.events().lines().filter(|line| line.starts_with("start ")) {
                let pid = line.split_whitespace().nth(2).expect("child PID");
                let probe = std::process::Command::new("kill")
                    .args(["-0", pid])
                    .output()
                    .expect("probe child");
                assert!(!probe.status.success(), "checker {pid} remains after its aggregate");
            }
        }
    }

    #[cfg(unix)]
    impl Drop for CheckerFixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).expect("remove scheduler fixture");
        }
    }

    /// Out-of-order completion starts each group once and never exceeds the selected slot count.
    #[cfg(unix)]
    #[test]
    fn preservation_scheduler_reuses_only_completed_slots() {
        let mut fixture = CheckerFixture::new();
        fixture.job(
            "first",
            "exec(\"while not (root/'release').exists():\\n time.sleep(0.01)\")",
            "NoError",
            0,
        );
        fixture.job("second", "pass", "NoError", 0);
        fixture.job("third", "(root/'release').touch()", "NoError", 0);
        fixture.job("fourth", "pass", "NoError", 0);
        let (completed, result) = fixture.run(2, core::time::Duration::from_secs(10));
        result.map_err(|error| error.message).expect("complete preservation");
        assert_eq!(completed, 4);
        let events = fixture.events();
        let mut active = std::collections::BTreeSet::new();
        let mut starts = Vec::new();
        for line in events.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            let name = fields[1];
            if fields[0] == "start" {
                assert!(active.insert(name), "duplicate active group {name}");
                starts.push(name);
                assert!(active.len() <= 2, "more than two active groups: {events}");
            } else {
                assert!(active.remove(name), "finished group was not active: {line}");
            }
        }
        starts.sort();
        assert_eq!(starts, ["first", "fourth", "second", "third"]);
        assert!(active.is_empty());
        let record = std::fs::read_to_string(fixture.root.join("run.txt")).expect("aggregate results");
        let second = record.find("job-pass=second").expect("second group result");
        let first = record.find("job-pass=first").expect("first group result");
        assert!(second < first);
        fixture.assert_reaped();
    }

    /// A failed native verdict, including exit zero, cancels siblings and leaves queued groups unstarted.
    #[cfg(unix)]
    #[test]
    fn preservation_scheduler_rejects_failed_and_inconclusive_children() {
        for (outcome, status) in [("Error", 12), ("SmtTimeout", 0)] {
            let mut fixture = CheckerFixture::new();
            fixture.job("blocked", "(root/'ready').touch(); time.sleep(60)", "NoError", 0);
            fixture.job(
                "failed",
                "exec(\"while not (root/'ready').exists():\\n time.sleep(0.01)\")",
                outcome,
                status,
            );
            fixture.job("queued", "pass", "NoError", 0);
            let (completed, result) = fixture.run(2, core::time::Duration::from_secs(10));
            assert_eq!(completed, 0);
            assert!(matches!(result, Err(error) if error.message.contains(outcome)));
            assert!(!fixture.events().contains("queued"));
            let record = std::fs::read_to_string(fixture.root.join("run.txt")).expect("aggregate results");
            assert!(record.contains("job-fail=failed"));
            assert!(record.contains("job-cancel=blocked"));
            fixture.assert_reaped();
        }
    }

    /// A spawn failure after a completed group cancels the active sibling and stops the remaining queue.
    #[cfg(unix)]
    #[test]
    fn preservation_scheduler_cancels_siblings_on_spawn_failure() {
        let mut fixture = CheckerFixture::new();
        fixture.job("blocked", "(root/'ready').touch(); time.sleep(60)", "NoError", 0);
        fixture.job(
            "remove",
            "exec(\"while not (root/'ready').exists():\\n time.sleep(0.01)\"); (root/'checker').unlink()",
            "NoError",
            0,
        );
        fixture.job("unspawned", "pass", "NoError", 0);
        fixture.job("queued", "pass", "NoError", 0);
        let (completed, result) = fixture.run(2, core::time::Duration::from_secs(10));
        assert_eq!(completed, 1);
        assert!(matches!(result, Err(error) if error.message.contains("cannot start apalache")));
        let events = fixture.events();
        assert!(!events.contains("unspawned") && !events.contains("queued"));
        let record = std::fs::read_to_string(fixture.root.join("run.txt")).expect("aggregate results");
        assert!(record.contains("job-fail=unspawned"));
        assert!(record.contains("job-cancel=blocked"));
        fixture.assert_reaped();
    }

    /// A later wave receives only the time left in the aggregate budget.
    #[cfg(unix)]
    #[test]
    fn preservation_scheduler_keeps_one_deadline_across_waves() {
        let mut fixture = CheckerFixture::new();
        fixture.job("first", "time.sleep(1)", "NoError", 0);
        fixture.job("second", "time.sleep(1.5)", "NoError", 0);
        fixture.job("queued", "pass", "NoError", 0);
        let (completed, result) = fixture.run(1, core::time::Duration::from_secs(2));
        assert_eq!(completed, 1);
        assert!(matches!(result, Err(error) if error.message.contains("exceeded 2.000 seconds")));
        let events = fixture.events();
        assert!(events.contains("start second"));
        assert!(!events.contains("finish second") && !events.contains("queued"));
        fixture.assert_reaped();
    }
}
