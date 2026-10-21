//! FLICKER CLI — `flicker-plan`
//!
//! Точка входа нормативного ядра. Реализует команды, заявленные в ТЗ V30
//! Приложение А §5: check / ground / plan / validate / replay-verify / selftest.
//!
//! Гарантии, обеспечиваемые этим бинарником:
//!   G1 — отклоняет любой вход вне FPS-1 с machine-readable диагностикой;
//!   G2 — план выдаётся ТОЛЬКО при `valid && goal_satisfied` (R7.4.1);
//!   G3 — детерминизм: seed фиксируется, вывод каноничен;
//!   G4 — каждая команда может писать hash-chain replay (`--replay`).
//!
//! std-only: внешних зависимостей нет (supply-chain cleanliness, §14.1).
//! `unwrap`/`expect` не используются — правило §4.3, критерий A6.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use symbolic_core::error::FlickerError;
use symbolic_core::ground::ground_actions;
use symbolic_core::json::{parse_json, Json};
use symbolic_core::pddl::{self, Model};
use symbolic_core::planner::{plan, PlanMode, PlanOptions};
use symbolic_core::replay::{verify_chain, ReplayWriter};
use symbolic_core::validator::{validate_plan, PlanStep};
use symbolic_core::{FPS1_VERSION, VERSION};

/// Коды выхода — стабильный контракт для CI и для вызывающей стороны.
mod exit {
    pub const OK: u8 = 0;
    /// план невалиден или цель не достигнута (G2)
    pub const INVALID: u8 = 1;
    /// ошибка использования CLI
    pub const USAGE: u8 = 2;
    /// ошибка ввода-вывода
    pub const IO: u8 = 3;
    /// ошибка разбора/семантики PDDL (G1)
    pub const PARSE: u8 = 4;
    /// исчерпан бюджет поиска
    pub const LIMIT: u8 = 5;
    /// повреждена replay-цепь (G4)
    pub const CHAIN: u8 = 6;
}

const USAGE: &str = r#"flicker-plan — FLICKER FPS-1 deterministic planner CLI

USAGE:
    flicker-plan <COMMAND> [OPTIONS]

COMMANDS:
    check          Проверить домен и задачу на соответствие FPS-1
    ground         Сообщить размер пространства grounding
    plan           Найти план (best-first | mcts | auto)
    validate       Проверить готовый план JSON против домена и задачи
    replay-verify  Верифицировать целостность replay-цепи (JSONL)
    selftest       Встроенные проверки согласованности ядра
    version        Версии ядра и спецификации

OPTIONS:
    --domain <path>          PDDL-домен                      (check/ground/plan/validate)
    --problem <path>         PDDL-задача                     (check/ground/plan/validate)
    --plan <path>            JSON-план для validate
    --chain <path>           JSONL-цепь для replay-verify
    --mode <auto|best-first|mcts>   Режим поиска             [default: auto]
    --seed <u64>             Seed детерминизма               [default: 42]
    --max-nodes <n>          Предел экспансий best-first     [default: 200000]
    --budget-ms <n>          Бюджет времени, мс              [default: 5000]
    --iterations <n>         Итерации MCTS                   [default: 20000]
    --replay <path>          Писать hash-chain replay в файл
    --json                   Машинно-читаемый вывод
    --quiet                  Только код выхода

EXIT CODES:
    0 ok · 1 план невалиден · 2 usage · 3 io · 4 parse/semantic · 5 limit · 6 chain broken

EXAMPLES:
    flicker-plan check  --domain domains/logistics.pddl --problem domains/logistics_p1.pddl
    flicker-plan plan   --domain d.pddl --problem p.pddl --mode auto --json
    flicker-plan plan   --domain d.pddl --problem p.pddl --replay trace.jsonl
    flicker-plan validate --domain d.pddl --problem p.pddl --plan plan.json
    flicker-plan replay-verify --chain trace.jsonl
"#;

// ---------------------------------------------------------------------------
// Разбор аргументов (std-only)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Args {
    command: String,
    domain: Option<PathBuf>,
    problem: Option<PathBuf>,
    plan_file: Option<PathBuf>,
    chain: Option<PathBuf>,
    replay: Option<PathBuf>,
    mode: String,
    seed: u64,
    max_nodes: usize,
    budget_ms: u64,
    iterations: u32,
    json: bool,
    quiet: bool,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut a = Args {
        mode: "auto".into(),
        seed: 42,
        max_nodes: 200_000,
        budget_ms: 5_000,
        iterations: 20_000,
        ..Args::default()
    };
    let mut i = 1usize;
    let take = |i: &mut usize, flag: &str| -> Result<String, String> {
        *i += 1;
        argv.get(*i)
            .cloned()
            .ok_or_else(|| format!("flag '{}' requires a value", flag))
    };

    while i < argv.len() {
        let arg = argv[i].clone();
        if !arg.starts_with('-') {
            if a.command.is_empty() {
                a.command = arg;
            } else {
                return Err(format!("unexpected positional argument '{}'", arg));
            }
            i += 1;
            continue;
        }
        match arg.as_str() {
            "--domain" => a.domain = Some(PathBuf::from(take(&mut i, "--domain")?)),
            "--problem" => a.problem = Some(PathBuf::from(take(&mut i, "--problem")?)),
            "--plan" => a.plan_file = Some(PathBuf::from(take(&mut i, "--plan")?)),
            "--chain" => a.chain = Some(PathBuf::from(take(&mut i, "--chain")?)),
            "--replay" => a.replay = Some(PathBuf::from(take(&mut i, "--replay")?)),
            "--mode" => a.mode = take(&mut i, "--mode")?,
            "--seed" => {
                a.seed = take(&mut i, "--seed")?
                    .parse::<u64>()
                    .map_err(|e| format!("--seed must be an integer: {}", e))?
            }
            "--max-nodes" => {
                a.max_nodes = take(&mut i, "--max-nodes")?
                    .parse::<usize>()
                    .map_err(|e| format!("--max-nodes must be an integer: {}", e))?
            }
            "--budget-ms" => {
                a.budget_ms = take(&mut i, "--budget-ms")?
                    .parse::<u64>()
                    .map_err(|e| format!("--budget-ms must be an integer: {}", e))?
            }
            "--iterations" => {
                a.iterations = take(&mut i, "--iterations")?
                    .parse::<u32>()
                    .map_err(|e| format!("--iterations must be an integer: {}", e))?
            }
            "--json" => a.json = true,
            "--quiet" => a.quiet = true,
            "-h" | "--help" => {
                a.command = "help".into();
            }
            other => return Err(format!("unknown flag '{}'", other)),
        }
        i += 1;
    }
    Ok(a)
}

fn read_file(p: &PathBuf) -> Result<String, FlickerError> {
    fs::read_to_string(p).map_err(|e| FlickerError::io(format!("{}: {}", p.display(), e)))
}

fn require<'a>(v: &'a Option<PathBuf>, flag: &str) -> Result<&'a PathBuf, String> {
    v.as_ref().ok_or_else(|| format!("{} requires {}", "this command", flag))
}

// ---------------------------------------------------------------------------
// Вывод
// ---------------------------------------------------------------------------

fn emit(a: &Args, human: &str, machine: Json) {
    if a.quiet {
        return;
    }
    if a.json {
        // `to_pretty` is infallible (unlike `to_canonical`, which reports
        // non-finite/unsupported values).
        println!("{}", machine.to_pretty());
    } else {
        println!("{}", human);
    }
}

fn err_json(kind: &str, message: &str, pos: Option<symbolic_core::error::Pos>) -> Json {
    let mut o = Json::obj();
    o.insert("ok", Json::Bool(false));
    o.insert("kind", Json::str(kind));
    o.insert("message", Json::str(message));
    if let Some(p) = pos {
        let mut pj = Json::obj();
        pj.insert("line", Json::int(p.line as i64));
        pj.insert("col", Json::int(p.col as i64));
        o.insert("pos", pj);
    }
    o
}

fn exit_for(e: &FlickerError) -> u8 {
    match e.kind.as_str() {
        "parse" | "type_error" | "semantic" | "grounding" => exit::PARSE,
        "limit" => exit::LIMIT,
        "validation" => exit::INVALID,
        "io" => exit::IO,
        _ => exit::INVALID,
    }
}

// ---------------------------------------------------------------------------
// Команды
// ---------------------------------------------------------------------------

fn cmd_version(a: &Args) -> ExitCode {
    let mut o = Json::obj();
    o.insert("ok", Json::Bool(true));
    o.insert("flicker_plan", Json::str(VERSION));
    o.insert("fps1", Json::str(FPS1_VERSION));
    o.insert("supported_requirements", Json::arr(
        pddl::SUPPORTED_REQUIREMENTS.iter().map(|r| Json::str(*r)).collect(),
    ));
    emit(a, &format!("flicker-plan {} · {} · requirements: {}",
        VERSION, FPS1_VERSION, pddl::SUPPORTED_REQUIREMENTS.join(", ")), o);
    ExitCode::from(exit::OK)
}

fn load_model(a: &Args, w: &mut Option<ReplayWriter>) -> Result<Model, FlickerError> {
    let dp = require(&a.domain, "--domain").map_err(|e| FlickerError::parse(e, symbolic_core::error::Pos { line: 0, col: 0 }))?;
    let pp = require(&a.problem, "--problem").map_err(|e| FlickerError::parse(e, symbolic_core::error::Pos { line: 0, col: 0 }))?;
    let dsrc = read_file(dp)?;
    let psrc = read_file(pp)?;

    if let Some(w) = w.as_mut() {
        let mut p = Json::obj();
        p.insert("domain", Json::str(dp.display().to_string()));
        p.insert("problem", Json::str(pp.display().to_string()));
        let _ = w.record("request", p, now_ms());
    }

    let m = pddl::load(&dsrc, &psrc)?;

    if let Some(w) = w.as_mut() {
        let mut p = Json::obj();
        p.insert("domain", Json::str(m.domain.name.clone()));
        p.insert("problem", Json::str(m.problem.name.clone()));
        p.insert("objects", Json::int(m.object_types.len() as i64));
        p.insert("init_atoms", Json::int(m.problem.init.len() as i64));
        let _ = w.record("parse_result", p, now_ms());
    }
    Ok(m)
}

fn cmd_check(a: &Args) -> ExitCode {
    let mut w = a.replay.as_ref().map(|_| ReplayWriter::new());
    let m = match load_model(a, &mut w) {
        Ok(m) => m,
        Err(e) => {
            emit(a, &format!("REJECTED [{}] {}", e.kind, e.message), err_json(&e.kind, &e.message, e.pos));
            return ExitCode::from(exit_for(&e));
        }
    };
    let mut o = Json::obj();
    o.insert("ok", Json::Bool(true));
    o.insert("domain", Json::str(m.domain.name.clone()));
    o.insert("problem", Json::str(m.problem.name.clone()));
    o.insert("requirements", Json::arr(m.domain.requirements.iter().map(|r| Json::str(r.clone())).collect()));
    o.insert("actions", Json::int(m.domain.actions.len() as i64));
    o.insert("predicates", Json::int(m.domain.predicates.len() as i64));
    o.insert("objects", Json::int(m.object_types.len() as i64));
    o.insert("init_atoms", Json::int(m.problem.init.len() as i64));

    // Имена объектов, канонические атомы :init и текст цели — нужны Тому 2 для
    // provenance binding (B3, R7.5.1) и для предъявления цели оператору
    // (R7.5.5). Отдаём их из ядра, чтобы воркер НЕ заводил второй парсер PDDL:
    // два источника истины о синтаксисе — это расхождение гарантий B1/B2.
    o.insert("object_names", Json::arr(
        m.object_types.keys().map(|k| Json::str(k.clone())).collect()));
    let mut obj_types = Json::obj();
    for (k, v) in m.object_types.iter() {
        obj_types.insert(k, Json::str(v.clone()));
    }
    o.insert("object_types", obj_types);
    o.insert("init_atom_list", Json::arr(
        m.problem.init.iter().map(|a| Json::str(a.clone())).collect()));
    o.insert("goal", Json::str(symbolic_core::ground::render_formula(&m.problem.goal)));
    o.insert("action_names", Json::arr(
        m.domain.actions.iter().map(|a| Json::str(a.name.clone())).collect()));

    let human = format!(
        "OK · domain '{}' · problem '{}' · {} actions · {} predicates · {} objects · {} init atoms\n     requirements: {}",
        m.domain.name, m.problem.name, m.domain.actions.len(), m.domain.predicates.len(),
        m.object_types.len(), m.problem.init.len(), m.domain.requirements.join(", ")
    );
    if let Some(w) = w.as_mut() {
        let _ = w.record("check", o.clone(), now_ms());
        flush_replay(a, w);
    }
    emit(a, &human, o);
    ExitCode::from(exit::OK)
}

fn cmd_ground(a: &Args) -> ExitCode {
    let mut w = a.replay.as_ref().map(|_| ReplayWriter::new());
    let m = match load_model(a, &mut w) {
        Ok(m) => m,
        Err(e) => {
            emit(a, &format!("REJECTED [{}] {}", e.kind, e.message), err_json(&e.kind, &e.message, e.pos));
            return ExitCode::from(exit_for(&e));
        }
    };
    let g = match ground_actions(&m) {
        Ok(g) => g,
        Err(e) => {
            emit(a, &format!("GROUNDING FAILED [{}] {}", e.kind, e.message), err_json(&e.kind, &e.message, e.pos));
            return ExitCode::from(exit_for(&e));
        }
    };
    let mut o = Json::obj();
    o.insert("ok", Json::Bool(true));
    o.insert("ground_actions", Json::int(g.len() as i64));
    o.insert("cap", Json::int(symbolic_core::ground::DEFAULT_GROUNDING_CAP as i64));
    o.insert("actions", Json::arr(g.iter().map(|x| Json::str(x.key())).collect()));
    if let Some(w) = w.as_mut() {
        let mut p = Json::obj();
        p.insert("size", Json::int(g.len() as i64));
        p.insert("cap", Json::int(symbolic_core::ground::DEFAULT_GROUNDING_CAP as i64));
        let _ = w.record("grounding", p, now_ms());
        flush_replay(a, w);
    }
    emit(a, &format!("grounding space: {} actions (cap {})", g.len(), symbolic_core::ground::DEFAULT_GROUNDING_CAP), o);
    ExitCode::from(exit::OK)
}

fn cmd_plan(a: &Args) -> ExitCode {
    let mut w = a.replay.as_ref().map(|_| ReplayWriter::new());
    let m = match load_model(a, &mut w) {
        Ok(m) => m,
        Err(e) => {
            emit(a, &format!("REJECTED [{}] {}", e.kind, e.message), err_json(&e.kind, &e.message, e.pos));
            return ExitCode::from(exit_for(&e));
        }
    };
    let g = match ground_actions(&m) {
        Ok(g) => g,
        Err(e) => {
            emit(a, &format!("GROUNDING FAILED [{}] {}", e.kind, e.message), err_json(&e.kind, &e.message, e.pos));
            return ExitCode::from(exit_for(&e));
        }
    };
    if let Some(w) = w.as_mut() {
        let mut p = Json::obj();
        p.insert("size", Json::int(g.len() as i64));
        let _ = w.record("grounding", p, now_ms());
    }

    let mode = match PlanMode::parse(&a.mode) {
        Ok(m) => m,
        Err(e) => {
            emit(a, &format!("BAD --mode: {}", e.message), err_json(&e.kind, &e.message, e.pos));
            return ExitCode::from(exit::USAGE);
        }
    };
    let opts = PlanOptions {
        mode,
        seed: a.seed,
        max_nodes: a.max_nodes,
        time_budget_ms: a.budget_ms,
        mcts_iterations: a.iterations,
    };

    let out = match plan(&m, &g, &opts) {
        Ok(out) => out,
        Err(e) => {
            if let Some(w) = w.as_mut() {
                let mut p = Json::obj();
                p.insert("kind", Json::str(e.kind.clone()));
                p.insert("message", Json::str(e.message.clone()));
                let _ = w.record("search_failed", p, now_ms());
                flush_replay(a, w);
            }
            emit(a, &format!("NO PLAN [{}] {}", e.kind, e.message), err_json(&e.kind, &e.message, e.pos));
            return ExitCode::from(exit_for(&e));
        }
    };

    // R7.4.1 — жёсткий шлюз: план выдаётся только при valid && goal_satisfied.
    // `plan()` уже прогоняет валидатор, но проверяем повторно явно: это
    // нормативное требование, а не оптимизация.
    if !(out.validation.valid && out.validation.goal_satisfied) {
        let reason = out.validation.reason.clone().unwrap_or_else(|| "unknown".to_string());
        if let Some(w) = w.as_mut() {
            let mut p = Json::obj();
            p.insert("reason", Json::str(reason.clone()));
            let _ = w.record("validation_rejected", p, now_ms());
            flush_replay(a, w);
        }
        let mut o = err_json("validation", &reason, None);
        o.insert("validated", Json::Bool(false));
        emit(a, &format!("PLAN REJECTED BY VALIDATOR: {}", reason), o);
        return ExitCode::from(exit::INVALID);
    }

    if let Some(w) = w.as_mut() {
        let _ = w.record("search", out.to_json(), now_ms());
        let _ = w.record("validation", out.to_json(), now_ms());
    }

    let steps_txt: Vec<String> = out.steps.iter().map(|s| s.key()).collect();
    let human = format!(
        "PLAN FOUND · mode={} · {} step(s) · expanded={} generated={} elapsed={}ms · seed={}\n     goal_satisfied={} · final_state={}\n     {}",
        out.mode_used, out.steps.len(), out.expanded, out.generated, out.elapsed_ms, out.seed,
        out.validation.goal_satisfied, out.final_state_hash,
        if steps_txt.is_empty() { "(empty plan — goal already holds)".to_string() } else { steps_txt.join("\n     ") }
    );

    let mut o = out.to_json();
    o.insert("ok", Json::Bool(true));
    if let Some(w) = w.as_mut() {
        flush_replay(a, w);
    }
    emit(a, &human, o);
    ExitCode::from(exit::OK)
}

fn cmd_validate(a: &Args) -> ExitCode {
    let mut w = a.replay.as_ref().map(|_| ReplayWriter::new());
    let m = match load_model(a, &mut w) {
        Ok(m) => m,
        Err(e) => {
            emit(a, &format!("REJECTED [{}] {}", e.kind, e.message), err_json(&e.kind, &e.message, e.pos));
            return ExitCode::from(exit_for(&e));
        }
    };
    let g = match ground_actions(&m) {
        Ok(g) => g,
        Err(e) => {
            emit(a, &format!("GROUNDING FAILED [{}] {}", e.kind, e.message), err_json(&e.kind, &e.message, e.pos));
            return ExitCode::from(exit_for(&e));
        }
    };
    let pp = match require(&a.plan_file, "--plan") {
        Ok(p) => p.clone(),
        Err(e) => {
            emit(a, &e, err_json("usage", &e, None));
            return ExitCode::from(exit::USAGE);
        }
    };
    let raw = match read_file(&pp) {
        Ok(s) => s,
        Err(e) => {
            emit(a, &format!("IO ERROR: {}", e.message), err_json(&e.kind, &e.message, None));
            return ExitCode::from(exit::IO);
        }
    };

    let steps = match parse_steps(&raw) {
        Ok(s) => s,
        Err(e) => {
            emit(a, &format!("PLAN JSON ERROR: {}", e), err_json("parse", &e, None));
            return ExitCode::from(exit::PARSE);
        }
    };

    let r = match validate_plan(&m, &g, &steps) {
        Ok(r) => r,
        Err(e) => {
            emit(a, &format!("VALIDATION ERROR [{}] {}", e.kind, e.message), err_json(&e.kind, &e.message, e.pos));
            return ExitCode::from(exit_for(&e));
        }
    };

    let mut o = Json::obj();
    o.insert("ok", Json::Bool(r.valid && r.goal_satisfied));
    o.insert("valid", Json::Bool(r.valid));
    o.insert("goal_satisfied", Json::Bool(r.goal_satisfied));
    o.insert("steps_checked", Json::int(r.steps_checked as i64));
    match r.failed_step {
        Some(i) => { o.insert("failed_step", Json::int(i as i64)); }
        None => { o.insert("failed_step", Json::Null); }
    }
    match &r.reason {
        Some(s) => { o.insert("reason", Json::str(s.clone())); }
        None => { o.insert("reason", Json::Null); }
    }
    o.insert("init_state_hash", Json::str(r.init_state_hash.clone()));
    o.insert("final_state_hash", Json::str(r.final_state_hash.clone()));

    if let Some(w) = w.as_mut() {
        let _ = w.record("validation", o.clone(), now_ms());
        flush_replay(a, w);
    }

    let human = if r.valid && r.goal_satisfied {
        format!(
            "PLAN VALID · {} step(s) checked · goal satisfied\n     init={} \n     final={}",
            r.steps_checked, r.init_state_hash, r.final_state_hash
        )
    } else {
        format!(
            "PLAN INVALID · {} step(s) checked · goal_satisfied={} · failed_step={:?}\n     reason: {}",
            r.steps_checked, r.goal_satisfied, r.failed_step,
            r.reason.as_deref().unwrap_or("(none)")
        )
    };
    emit(a, &human, o);
    if r.valid && r.goal_satisfied {
        ExitCode::from(exit::OK)
    } else {
        ExitCode::from(exit::INVALID)
    }
}

/// Принимает два формата плана:
///   1. массив строк канонической формы:  ["(drive t1 a b)", "(drive t1 b c)"]
///   2. массив объектов:                  [{"action":"drive","args":["t1","a","b"]}, ...]
///   3. объект с полем "steps" любого из двух видов (выход `plan --json`)
fn parse_steps(raw: &str) -> Result<Vec<PlanStep>, String> {
    let v = parse_json(raw).map_err(|e| format!("{}: {}", e.kind, e.message))?;
    let arr = match &v {
        Json::Arr(a) => a.clone(),
        Json::Obj(_) => match v.get("steps") {
            Some(Json::Arr(a)) => a.clone(),
            _ => return Err("object form must contain a 'steps' array".into()),
        },
        _ => return Err("expected a JSON array or an object with 'steps'".into()),
    };

    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        match item {
            Json::Str(s) => {
                let (name, args) = pddl::split_atom(s)
                    .map_err(|e| format!("step {}: {} ({})", i, e.message, s))?;
                out.push(PlanStep { action: name, args });
            }
            Json::Obj(_) => {
                let action = item
                    .get("action")
                    .and_then(|x| x.as_str())
                    .ok_or_else(|| format!("step {}: missing 'action'", i))?
                    .to_string();
                let args_json = item
                    .get("args")
                    .and_then(|x| x.as_arr())
                    .ok_or_else(|| format!("step {}: missing 'args' array", i))?;
                let mut args = Vec::with_capacity(args_json.len());
                for a in args_json {
                    args.push(a.as_str().ok_or_else(|| format!("step {}: arg is not a string", i))?.to_string());
                }
                out.push(PlanStep { action, args });
            }
            _ => return Err(format!("step {}: expected string or object", i)),
        }
    }
    Ok(out)
}

fn cmd_replay_verify(a: &Args) -> ExitCode {
    let cp = match require(&a.chain, "--chain") {
        Ok(p) => p.clone(),
        Err(e) => {
            emit(a, &e, err_json("usage", &e, None));
            return ExitCode::from(exit::USAGE);
        }
    };
    let raw = match fs::read_to_string(&cp) {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("{}: {}", cp.display(), e);
            emit(a, &format!("IO ERROR: {}", msg), err_json("io", &msg, None));
            return ExitCode::from(exit::IO);
        }
    };
    match verify_chain(&raw) {
        Ok(r) => {
            let mut o = Json::obj();
            o.insert("ok", Json::Bool(r.ok));
            o.insert("lines", Json::int(r.lines as i64));
            o.insert("root_hash", Json::str(r.root_hash.clone()));
            match &r.error {
                Some(e) => { o.insert("error", Json::str(e.clone())); }
                None => { o.insert("error", Json::Null); }
            }
            let human = if r.ok {
                format!("CHAIN OK · {} record(s) · root={}", r.lines, r.root_hash)
            } else {
                format!("CHAIN BROKEN · {} record(s) · {}", r.lines, r.error.as_deref().unwrap_or("(no detail)"))
            };
            emit(a, &human, o);
            if r.ok { ExitCode::from(exit::OK) } else { ExitCode::from(exit::CHAIN) }
        }
        Err(e) => {
            emit(a, &format!("CHAIN ERROR [{}] {}", e.kind, e.message), err_json(&e.kind, &e.message, None));
            ExitCode::from(exit::CHAIN)
        }
    }
}

/// Встроенные проверки согласованности ядра — мини-аналог критериев A2/A3/A4,
/// исполняемый без cargo test (нужен для приёмки на стенде заказчика).
fn cmd_selftest(a: &Args) -> ExitCode {
    let mut checks: Vec<(String, bool, String)> = Vec::new();

    // 1. Криптопримитив: вектор FIPS 180-4 для "abc"
    let h = symbolic_core::sha2::sha256_hex(b"abc");
    checks.push((
        "sha256 FIPS180-4 KAT 'abc'".into(),
        h == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        h.clone(),
    ));

    // 2. HMAC RFC 4231 case 1
    let mac = symbolic_core::sha2::hmac_sha256(&[0x0bu8; 20], b"Hi There");
    let mac_hex = symbolic_core::sha2::to_hex(&mac);
    checks.push((
        "hmac-sha256 RFC4231 case1".into(),
        mac_hex == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        mac_hex,
    ));

    // 3. PRNG детерминирован
    let mut r1 = symbolic_core::prng::Xorshift64Star::new(42);
    let mut r2 = symbolic_core::prng::Xorshift64Star::new(42);
    let same = (0..256).all(|_| r1.next_u64() == r2.next_u64());
    checks.push(("prng seeded determinism".into(), same, "256 draws".into()));

    // 4. Json каноничен: порядок вставки ключей не влияет
    let mut j1 = Json::obj();
    j1.insert("b", Json::int(2));
    j1.insert("a", Json::int(1));
    let mut j2 = Json::obj();
    j2.insert("a", Json::int(1));
    j2.insert("b", Json::int(2));
    let c1 = j1.to_canonical().unwrap_or_default();
    let c2 = j2.to_canonical().unwrap_or_default();
    checks.push(("json canonical key order".into(), c1 == c2, c1.clone()));

    // 5. Replay-цепь: подлог обнаруживается
    let mut w = ReplayWriter::new();
    let mut p = Json::obj();
    p.insert("x", Json::int(1));
    let _ = w.record("e1", p, 1);
    let mut p2 = Json::obj();
    p2.insert("y", Json::int(2));
    let _ = w.record("e2", p2, 2);
    let jsonl = w.to_jsonl();
    let clean_ok = verify_chain(&jsonl).map(|r| r.ok).unwrap_or(false);
    let tampered = jsonl.replace("\"x\":1", "\"x\":999");
    let tamper_detected = match verify_chain(&tampered) {
        Ok(r) => !r.ok,
        Err(_) => true,
    };
    checks.push(("replay chain verifies".into(), clean_ok, "".into()));
    checks.push(("replay tampering detected".into(), tamper_detected, "".into()));

    // 6. Канонизация атома стабильна и чувствительна к порядку
    let a1 = pddl::canon_atom("at", &["t1".into(), "a".into()]);
    let a2 = pddl::canon_atom("at", &["a".into(), "t1".into()]);
    checks.push(("canon_atom order-sensitive".into(), a1 != a2, a1.clone()));

    let all_ok = checks.iter().all(|(_, ok, _)| *ok);
    let mut arr = Vec::new();
    for (name, ok, detail) in &checks {
        let mut o = Json::obj();
        o.insert("check", Json::str(name.clone()));
        o.insert("ok", Json::Bool(*ok));
        if !detail.is_empty() {
            o.insert("detail", Json::str(detail.clone()));
        }
        arr.push(o);
    }
    let mut o = Json::obj();
    o.insert("ok", Json::Bool(all_ok));
    o.insert("checks", Json::arr(arr));
    o.insert("version", Json::str(VERSION));
    o.insert("fps1", Json::str(FPS1_VERSION));

    let mut human = String::from("SELFTEST\n");
    for (name, ok, detail) in &checks {
        human.push_str(&format!("  [{}] {}{}\n",
            if *ok { "PASS" } else { "FAIL" }, name,
            if detail.is_empty() { String::new() } else { format!("  ({})", detail) }));
    }
    human.push_str(if all_ok { "RESULT: ALL PASS" } else { "RESULT: FAILURES PRESENT" });
    emit(a, &human, o);
    if all_ok { ExitCode::from(exit::OK) } else { ExitCode::from(exit::INVALID) }
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn flush_replay(a: &Args, w: &mut ReplayWriter) {
    let path = match &a.replay {
        Some(p) => p.clone(),
        None => return,
    };
    let jsonl = w.to_jsonl();
    // Append-only: дописываем, не перезаписываем (R8.2.1).
    let res = fs::OpenOptions::new().create(true).append(true).open(&path)
        .and_then(|mut f| {
            use std::io::Write;
            f.write_all(jsonl.as_bytes())
        });
    if let Err(e) = res {
        eprintln!("WARNING: failed to write replay log {}: {}", path.display(), e);
    }
    // Сбрасываем накопленное, чтобы при повторном вызове не задвоить записи.
    *w = ReplayWriter::new();
}

// ---------------------------------------------------------------------------

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let a = match parse_args(&argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {}\n\n{}", e, USAGE);
            return ExitCode::from(exit::USAGE);
        }
    };

    match a.command.as_str() {
        "" | "help" | "--help" | "-h" => {
            print!("{}", USAGE);
            ExitCode::from(if a.command.is_empty() { exit::USAGE } else { exit::OK })
        }
        "version" => cmd_version(&a),
        "check" => cmd_check(&a),
        "ground" => cmd_ground(&a),
        "plan" => cmd_plan(&a),
        "validate" => cmd_validate(&a),
        "replay-verify" => cmd_replay_verify(&a),
        "selftest" => cmd_selftest(&a),
        other => {
            eprintln!("error: unknown command '{}'\n\n{}", other, USAGE);
            ExitCode::from(exit::USAGE)
        }
    }
}
