//! Критерий **A7** (§12.1, R7.1.3) — контракт «грамматика B1 ⊆ парсер B2».
//!
//! ## Что проверяется
//!
//! Требование R7.1.3: любой документ, принятый грамматикой `fps1_pddl.ebnf`,
//! обязан приниматься `pddl::parse_domain` / `pddl::parse_problem`.
//! Расхождение — блокирующий дефект, а не «погрешность».
//!
//! Это не абстрактное требование. Дефект **D-03** (отчёт о сборке §2.1):
//! `parse_action` принимал только плоскую форму `:parameters (…)`, тогда как
//! EBNF-грамматика порождает вложенную `(:parameters …)`. Следствие: **ни один**
//! constrained emission не прошёл бы парсер, и система не выдала бы ни одного
//! плана. Обнаружилось это случайно, при написании тестов парсера, — то есть
//! контракт A7 не проверялся вовсе. Настоящий файл закрывает этот пробел.
//!
//! ## Метод
//!
//! `xgrammar`-бэкенд здесь недоступен (нет vLLM/GPU), поэтому язык грамматики
//! воспроизводится **детерминированным генератором**: он строит документы,
//! использующие исключительно конструкции, разрешённые `fps1_pddl.ebnf`, во
//! всех 8 `:requirements`, в обеих допустимых формах `:action`, со случайными
//! (но корректными по типам) предикатами, эффектами и кванторами.
//!
//! Генератор сидируется через `prng::Xorshift64Star` — тот же PRNG, что
//! использует MCTS, поэтому корпус воспроизводим побайтово (G3).
//!
//! ## Статус критерия
//!
//! **A7 — ЧАСТИЧНО**: корпус ≥ 10 000 документов сгенерирован и проверен,
//! но сверка идёт с генератором по языку EBNF, а не с самим xgrammar.
//! Полное закрытие A7 требует подъёма vLLM с xgrammar (A1/A7, DEP-HW-01).

use symbolic_core::pddl::{self, SUPPORTED_REQUIREMENTS};
use symbolic_core::prng::Xorshift64Star;

// ---------------------------------------------------------------------------
// Генератор корпуса
// ---------------------------------------------------------------------------

const TARGET_DOCS: usize = 10_000;

struct Rng(Xorshift64Star);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(Xorshift64Star::new(seed))
    }
    /// Равномерно в [0, n). Использует `next_below` (Lemire, без modulo bias).
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        self.0.next_below(n as u64) as usize
    }
    /// С вероятностью p (в процентах).
    fn chance(&mut self, pct: usize) -> bool {
        self.below(100) < pct
    }
}

/// Сгенерированная спецификация — промежуточное представление, из которого
/// затем печатается текст в ОБОИХ допустимых синтаксисах.
struct Spec {
    domain_name: String,
    problem_name: String,
    requirements: Vec<&'static str>,
    /// (имя типа, родитель или None для корневых)
    types: Vec<(String, Option<String>)>,
    /// (имя предиката, типы аргументов)
    preds: Vec<(String, Vec<String>)>,
    /// (имя объекта, тип)
    objects: Vec<(String, String)>,
    actions: Vec<ActionSpec>,
    init: Vec<String>,
    goal_terms: Vec<String>,
}

struct ActionSpec {
    name: String,
    /// (переменная БЕЗ '?', тип)
    params: Vec<(String, String)>,
    precond: String,
    effect: String,
}

/// Все имена — из фиксированных алфавитов, чтобы избежать коллизий и
/// гарантировать лексическую корректность (NAME по EBNF: letter {letter|digit|-|_}).
const TYPE_NAMES: [&str; 6] = ["alpha", "beta", "gamma", "delta", "eps", "zeta"];
const PRED_NAMES: [&str; 6] = ["ready", "linked", "active", "sealed", "moved", "held"];
const OBJ_NAMES: [&str; 16] = [
    "o1", "o2", "o3", "o4", "o5", "o6", "o7", "o8",
    "o9", "o10", "o11", "o12", "o13", "o14", "o15", "o16",
];
const ACT_NAMES: [&str; 5] = ["do-move", "apply", "reset_1", "seal", "transfer"];

fn gen_spec(rng: &mut Rng, idx: usize) -> Spec {
    // --- requirements: подмножество FPS-1, всегда включает :strips ---
    let mut requirements: Vec<&'static str> = vec!["strips"];
    for r in SUPPORTED_REQUIREMENTS.iter().skip(1) {
        if rng.chance(45) {
            requirements.push(*r);
        }
    }
    let has = |r: &str| requirements.contains(&r);

    // --- типы: 1..=4, опциональная иерархия (одно наследование, без циклов) ---
    let ntypes = 1 + rng.below(4);
    let mut types: Vec<(String, Option<String>)> = Vec::new();
    for i in 0..ntypes {
        let name = TYPE_NAMES[i % TYPE_NAMES.len()].to_string();
        // Подтип допускается только от уже объявленного типа — цикл невозможен.
        let parent = if has("typing") && !types.is_empty() && rng.chance(35) {
            Some(types[rng.below(types.len())].0.clone())
        } else {
            None
        };
        types.push((name, parent));
    }

    // Тип объекта: либо объявленный, либо "object" (нетипизированный случай).
    let all_types: Vec<String> = types.iter().map(|(n, _)| n.clone()).collect();

    // --- объекты ---
    //
    // ИНВАРИАНТ: каждый объявленный тип обязан иметь ХОТЯ БЫ ОДИН объект.
    // Без этого `fits()` возвращает пустой список комбинаций для предикатов
    // этого типа, и fallback в :init был вынужден подставлять объект чужого
    // типа — что парсер справедливо отклонял как type error.
    //
    // Поэтому сначала по одному объекту на тип (проход A), затем необязательные
    // дополнительные (проход B).
    let mut objects: Vec<(String, String)> = Vec::new();
    let mut next_name = 0usize;
    // проход A: покрытие всех типов
    for t in &all_types {
        if next_name >= OBJ_NAMES.len() {
            break;
        }
        let name = OBJ_NAMES[next_name].to_string();
        next_name += 1;
        objects.push((name, t.clone()));
    }
    // проход B: 0..=2 дополнительных объекта на тип
    for t in &all_types {
        let extra = rng.below(3);
        for _ in 0..extra {
            if next_name >= OBJ_NAMES.len() {
                break;
            }
            let name = OBJ_NAMES[next_name].to_string();
            next_name += 1;
            objects.push((name, t.clone()));
        }
    }
    assert!(!objects.is_empty(), "корпус обязан содержать хотя бы один объект");

    // --- предикаты: 1..=4, арность 0..=3, типы аргументов из объявленных ---
    let npreds = 1 + rng.below(4);
    let mut preds: Vec<(String, Vec<String>)> = Vec::new();
    for i in 0..npreds {
        let name = PRED_NAMES[i % PRED_NAMES.len()].to_string();
        let arity = rng.below(4);
        let mut args = Vec::with_capacity(arity);
        for _ in 0..arity {
            args.push(all_types[rng.below(all_types.len())].clone());
        }
        preds.push((name, args));
    }

    // --- init: корректные по типам атомы ---
    // Соответствие объекта типу с учётом иерархии: объект типа T подходит
    // для аргумента типа P, если T == P или T — потомок P.
    let is_sub = |child: &str, parent: &str| -> bool {
        if child == parent {
            return true;
        }
        let mut cur = Some(child.to_string());
        for _ in 0..8 {
            let c = match cur {
                Some(x) => x,
                None => return false,
            };
            let par = types.iter().find(|(n, _)| *n == c).and_then(|(_, p)| p.clone());
            match par {
                Some(p) if p == parent => return true,
                Some(p) => cur = Some(p),
                None => return false,
            }
        }
        false
    };

    let fits = |objs: &[String], argtypes: &[String]| -> Vec<Vec<String>> {
        // Все типосовместимые комбинации (полное произведение, обрезанное).
        let mut acc: Vec<Vec<String>> = vec![vec![]];
        for at in argtypes {
            let mut next = Vec::new();
            for prefix in &acc {
                for o in objs {
                    let oty = objects.iter().find(|(n, _)| n == o).map(|(_, t)| t.as_str());
                    if let Some(oty) = oty {
                        if is_sub(oty, at) {
                            let mut v = prefix.clone();
                            v.push(o.clone());
                            next.push(v);
                        }
                    }
                }
            }
            acc = next;
            if acc.len() > 40 {
                acc.truncate(40);
            }
            if acc.is_empty() {
                break;
            }
        }
        acc
    };

    let obj_names: Vec<String> = objects.iter().map(|(n, _)| n.clone()).collect();

    let mut init: Vec<String> = Vec::new();
    for (pname, argtypes) in &preds {
        let combos = fits(&obj_names, argtypes);
        if combos.is_empty() {
            continue;
        }
        // 1..=3 атома на предикат
        let k = 1 + rng.below(3.min(combos.len()));
        for _ in 0..k {
            let c = combos[rng.below(combos.len())].clone();
            let atom = if c.is_empty() {
                format!("({})", pname)
            } else {
                format!("({} {})", pname, c.join(" "))
            };
            if !init.contains(&atom) {
                init.push(atom);
            }
        }
    }
    if init.is_empty() {
        // Гарантируем хотя бы один атом. ВАЖНО: только типосовместимый.
        // Прежняя версия подставляла `objects[0]` при отсутствии объекта
        // нужного типа — это и давало type error в 88 документах корпуса.
        if let Some((pname, _at)) = preds.iter().find(|(_, a)| a.is_empty()) {
            init.push(format!("({})", pname));
        } else {
            'outer: for (pname, argtypes) in &preds {
                let mut args = Vec::with_capacity(argtypes.len());
                for t in argtypes {
                    match objects.iter().find(|(_, ot)| is_sub(ot, t)) {
                        Some((n, _)) => args.push(n.clone()),
                        // нет объекта этого типа — пропускаем ПРЕДИКАТ,
                        // а не подставляем чужой объект
                        None => continue 'outer,
                    }
                }
                init.push(format!("({} {})", pname, args.join(" ")));
                break;
            }
        }
    }
    assert!(!init.is_empty(), "корпус обязан содержать хотя бы один атом :init");

    // --- действия: 1..=3 ---
    let nact = 1 + rng.below(3);
    let mut actions = Vec::new();
    for i in 0..nact {
        let name = ACT_NAMES[i % ACT_NAMES.len()].to_string();
        // параметры: 0..=3, типы из объявленных
        let nparams = rng.below(4);
        let mut params: Vec<(String, String)> = Vec::new();
        for pi in 0..nparams {
            let v = format!("v{}_{}", i, pi);
            let t = all_types[rng.below(all_types.len())].clone();
            params.push((v, t));
        }

        // Область видимости предусловия: параметры + объекты (константы допустимы).
        let scope_vars: Vec<(String, String)> = params.clone();
        let scope_consts: Vec<(String, String)> = objects.clone();

        // Атом в предусловии: предикат + аргументы из области видимости.
        let mk_atom = |rng: &mut Rng,
                           preds: &[(String, Vec<String>)],
                           vars: &[(String, String)],
                           consts: &[(String, String)],
                           emit_var: bool|
         -> Option<String> {
            let (pname, argtypes) = rng_pick_pred(rng, preds);
            let mut args = Vec::with_capacity(argtypes.len());
            for at in argtypes {
                let cands: Vec<String> = vars
                    .iter()
                    .filter(|(_, t)| t == at)
                    .map(|(v, _)| format!("?{}", v))
                    .chain(
                        consts
                            .iter()
                            .filter(|(_, t)| t == at || is_sub_local(t, at, &types))
                            .map(|(c, _)| c.clone()),
                    )
                    .collect();
                if cands.is_empty() {
                    return None;
                }
                let _ = emit_var;
                args.push(cands[rng.below(cands.len())].clone());
            }
            Some(if args.is_empty() {
                format!("({})", pname)
            } else {
                format!("({} {})", pname, args.join(" "))
            })
        };

        // Предусловие
        let mut conj: Vec<String> = Vec::new();
        let nconj = 1 + rng.below(3);
        for _ in 0..nconj {
            if let Some(a) = mk_atom(rng, &preds, &scope_vars, &scope_consts, true) {
                if has("negative-preconditions") && rng.chance(25) {
                    conj.push(format!("(not {})", a));
                } else {
                    conj.push(a);
                }
            }
        }
        if conj.is_empty() {
            conj.push("(and)".to_string());
        }

        let mut precond = if conj.len() == 1 {
            conj[0].clone()
        } else {
            format!("(and {})", conj.join(" "))
        };

        // Дизъюнкция в предусловии (ПОДДЕРЖИВАЕТСЯ, в отличие от эффектов)
        if has("disjunctive-preconditions") && rng.chance(25) && conj.len() >= 2 {
            precond = format!("(or {} {})", conj[0], conj[1]);
        }

        // Кванторы в предусловии
        if has("universal-preconditions") && rng.chance(20) {
            let qt = all_types[rng.below(all_types.len())].clone();
            let qv = format!("q{}_u", i);
            // Внутренний атом: предикат арности 1, принимающий тип qv
            if let Some((pn, _)) = preds.iter().find(|(_, at)| at.len() == 1 && at[0] == qt) {
                let body = format!("(not ({} ?{}))", pn, qv);
                precond = format!("(and {} (forall (?{} - {}) {}))", precond, qv, qt, body);
            }
        }
        if has("existential-preconditions") && rng.chance(20) {
            let qt = all_types[rng.below(all_types.len())].clone();
            let qv = format!("q{}_e", i);
            if let Some((pn, _)) = preds.iter().find(|(_, at)| at.len() == 1 && at[0] == qt) {
                let body = format!("({} ?{})", pn, qv);
                precond = format!("(and {} (exists (?{} - {}) {}))", precond, qv, qt, body);
            }
        }

        // Эффект: add/del атомов, условные и универсальные эффекты
        let mut effs: Vec<String> = Vec::new();
        let neff = 1 + rng.below(3);
        for _ in 0..neff {
            if let Some(a) = mk_atom(rng, &preds, &scope_vars, &scope_consts, true) {
                if rng.chance(40) {
                    effs.push(format!("(not {})", a));
                } else {
                    effs.push(a);
                }
            }
        }
        if effs.is_empty() {
            effs.push("(and)".to_string());
        }
        let mut effect = format!("(and {})", effs.join(" "));

        if has("conditional-effects") && rng.chance(25) {
            if let Some(a) = mk_atom(rng, &preds, &scope_vars, &scope_consts, true) {
                if let Some(b) = mk_atom(rng, &preds, &scope_vars, &scope_consts, true) {
                    effect = format!("(and {} (when {} {}))", effect, a, b);
                }
            }
        }
        if has("universal-effects") && rng.chance(20) {
            let qt = all_types[rng.below(all_types.len())].clone();
            let qv = format!("q{}_f", i);
            if let Some((pn, _)) = preds.iter().find(|(_, at)| at.len() == 1 && at[0] == qt) {
                effect = format!(
                    "(and {} (forall (?{} - {}) (not ({} ?{}))))",
                    effect, qv, qt, pn, qv
                );
            }
        }

        actions.push(ActionSpec { name, params, precond, effect });
    }

    // --- цель: 1..=2 атома из init (гарантированно достижима тривиально или нет —
    //     для A7 важна корректность разбора, а не разрешимость) ---
    let mut goal_terms = Vec::new();
    let ng = 1 + rng.below(2);
    for _ in 0..ng {
        let a = init[rng.below(init.len())].clone();
        if !goal_terms.contains(&a) {
            goal_terms.push(a);
        }
    }

    Spec {
        domain_name: format!("gen_domain_{}", idx),
        problem_name: format!("gen_problem_{}", idx),
        requirements,
        types,
        preds,
        objects,
        actions,
        init,
        goal_terms,
    }
}

fn rng_pick_pred<'a>(rng: &mut Rng, preds: &'a [(String, Vec<String>)]) -> (&'a String, &'a [String]) {
    let (n, a) = &preds[rng.below(preds.len())];
    (n, a.as_slice())
}

fn is_sub_local(child: &str, parent: &str, types: &[(String, Option<String>)]) -> bool {
    if child == parent {
        return true;
    }
    let mut cur = child.to_string();
    for _ in 0..8 {
        match types.iter().find(|(n, _)| *n == cur).and_then(|(_, p)| p.clone()) {
            Some(p) if p == parent => return true,
            Some(p) => cur = p,
            None => return false,
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Печать в обе допустимые формы
// ---------------------------------------------------------------------------

fn render(spec: &Spec, nested: bool, comments: bool) -> (String, String) {
    let mut d = String::new();
    if comments {
        d.push_str(";; A7 corpus document — generated deterministically from seed\n");
    }
    d.push_str(&format!("(define (domain {})\n", spec.domain_name));
    d.push_str(&format!(
        "  (:requirements {})\n",
        spec.requirements.iter().map(|r| format!(":{}", r)).collect::<Vec<_>>().join(" ")
    ));

    if !spec.types.is_empty() {
        // ВАЖНО: родитель указывается ЯВНО для каждого типа, включая корневые.
        //
        // В типизированном списке PDDL подряд идущие имена группируются с
        // последующим `- тип`: запись `(:types alpha beta - alpha)` означает,
        // что И `alpha`, И `beta` имеют родителем `alpha` — то есть `alpha`
        // становится собственным предком, и build_model справедливо сообщает
        // "type hierarchy has a cycle". Пропуск `- object` для корневых типов
        // поэтому недопустим: он неявно присоединяет их к следующей группе.
        d.push_str("  (:types");
        for (name, parent) in &spec.types {
            match parent {
                Some(p) => d.push_str(&format!(" {} - {}", name, p)),
                None => d.push_str(&format!(" {} - object", name)),
            }
        }
        d.push_str(")\n");
    }

    d.push_str("  (:predicates");
    for (pname, argtypes) in &spec.preds {
        if argtypes.is_empty() {
            d.push_str(&format!(" ({})", pname));
        } else {
            d.push_str(&format!(" ({} ", pname));
            let parts: Vec<String> = argtypes
                .iter()
                .enumerate()
                .map(|(i, t)| format!("?p{} - {}", i, t))
                .collect();
            d.push_str(&parts.join(" "));
            d.push(')');
        }
    }
    d.push_str(")\n");

    for a in &spec.actions {
        if nested {
            d.push_str(&format!("  (:action {}\n", a.name));
            d.push_str("    (:parameters (");
            d.push_str(
                &a.params
                    .iter()
                    .map(|(v, t)| format!("?{} - {}", v, t))
                    .collect::<Vec<_>>()
                    .join(" "),
            );
            d.push_str("))\n");
            d.push_str(&format!("    (:precondition {})\n", a.precond));
            // `))` = закрыть :effect и закрыть :action. `define` закрывается
            // отдельно в конце функции — ровно один раз.
            d.push_str(&format!("    (:effect {}))\n", a.effect));
        } else {
            d.push_str(&format!("  (:action {}\n", a.name));
            d.push_str("    :parameters (");
            d.push_str(
                &a.params
                    .iter()
                    .map(|(v, t)| format!("?{} - {}", v, t))
                    .collect::<Vec<_>>()
                    .join(" "),
            );
            d.push_str(")\n");
            d.push_str(&format!("    :precondition {}\n", a.precond));
            // `)` = закрыть :action (тело :effect само сбалансировано).
            d.push_str(&format!("    :effect {})\n", a.effect));
        }
    }
    d.push_str(")\n");

    let mut p = String::new();
    p.push_str(&format!("(define (problem {})\n", spec.problem_name));
    p.push_str(&format!("  (:domain {})\n", spec.domain_name));
    if !spec.objects.is_empty() {
        p.push_str("  (:objects");
        for (oname, otype) in &spec.objects {
            p.push_str(&format!(" {} - {}", oname, otype));
        }
        p.push_str(")\n");
    }
    p.push_str(&format!("  (:init {})\n", spec.init.join(" ")));
    p.push_str(&format!("  (:goal (and {})))\n", spec.goal_terms.join(" ")));

    (d, p)
}

// ---------------------------------------------------------------------------
// ТЕСТ A7
// ---------------------------------------------------------------------------

#[test]
fn a7_grammar_subset_of_parser_on_10k_corpus() {
    let mut rng = Rng::new(0xA7A7_A7A7);

    let mut total = 0usize;
    let mut nested_ok = 0usize;
    let mut flat_ok = 0usize;
    let mut model_ok = 0usize;
    let mut req_coverage: std::collections::BTreeMap<&str, usize> =
        SUPPORTED_REQUIREMENTS.iter().map(|r| (*r, 0)).collect();
    let mut arity_hist: std::collections::BTreeMap<usize, usize> = Default::default();
    let mut failures: Vec<(usize, String, String, String)> = Vec::new();

    for idx in 0..TARGET_DOCS {
        let spec = gen_spec(&mut rng, idx);
        for r in &spec.requirements {
            if let Some(c) = req_coverage.get_mut(r) {
                *c += 1;
            }
        }
        for a in &spec.actions {
            *arity_hist.entry(a.params.len()).or_insert(0) += 1;
        }

        // Обе формы печатаются из ОДНОЙ спецификации — это и есть проверка
        // того, что грамматика (вложенная форма) и парсер согласованы.
        for &nested in &[true, false] {
            let comments = idx % 3 == 0; // часть документов — с комментариями
            let (dsrc, psrc) = render(&spec, nested, comments);
            total += 1;

            let parsed = pddl::parse_domain(&dsrc).and_then(|d| {
                pddl::parse_problem(&psrc).and_then(|p| pddl::build_model(d, p))
            });

            match parsed {
                Ok(_m) => {
                    if nested {
                        nested_ok += 1;
                    } else {
                        flat_ok += 1;
                    }
                    model_ok += 1;
                }
                Err(e) => {
                    if failures.len() < 10 {
                        failures.push((
                            idx,
                            if nested { "nested" } else { "flat" }.to_string(),
                            format!("[{}] {}", e.kind, e.message),
                            dsrc.chars().take(600).collect(),
                        ));
                    }
                }
            }
        }
    }

    // --- Отчёт ---
    println!("── A7 · grammar ⊆ parser ────────────────────────────────");
    println!("  спецификаций:        {}", TARGET_DOCS);
    println!("  документов проверено: {} (обе формы × {})", total, TARGET_DOCS);
    println!("  вложенная форма:      {}/{} принята", nested_ok, TARGET_DOCS);
    println!("  плоская форма:        {}/{} принята", flat_ok, TARGET_DOCS);
    println!("  build_model успешен:  {}/{}", model_ok, total);
    println!("  покрытие requirements:");
    for r in SUPPORTED_REQUIREMENTS {
        println!("    :{:<28} {}", r, req_coverage.get(r).copied().unwrap_or(0));
    }
    println!("  арность параметров действий:");
    for (k, v) in &arity_hist {
        println!("    {} параметр(ов): {} действий", k, v);
    }

    if !failures.is_empty() {
        println!("\n  ПЕРВЫЕ ОТКАЗЫ (≤10):");
        for (i, form, err, src) in &failures {
            println!("    #{} [{}] {}", i, form, err);
            println!("    ---- домен ----");
            for line in src.lines().take(18) {
                println!("    | {}", line);
            }
            println!();
        }
    }

    // --- Утверждения ---
    assert_eq!(total, 2 * TARGET_DOCS, "корпус обязан быть ≥ 10 000 документов");
    assert!(total >= 10_000, "R7.1.3 требует корпус ≥ 10 000, получено {}", total);

    // Каждое требование FPS-1 должно быть покрыто корпусом, иначе тест
    // не доказывает согласие грамматики и парсера для него.
    for r in SUPPORTED_REQUIREMENTS {
        let c = req_coverage.get(r).copied().unwrap_or(0);
        assert!(c > 0, "requirement ':{}' не покрыт корпусом", r);
    }

    assert!(
        failures.is_empty(),
        "A7 НАРУШЕН: {} из {} документов, соответствующих грамматике, отклонены парсером. \
         Первый отказ: #{} [{}] {}",
        total - model_ok,
        total,
        failures[0].0,
        failures[0].1,
        failures[0].2
    );
    assert_eq!(nested_ok, TARGET_DOCS, "вложенная форма (порождаемая EBNF) обязана приниматься целиком");
    assert_eq!(flat_ok, TARGET_DOCS, "плоская форма обязана приниматься целиком");
}

/// Отрицательная половина A7: конструкции вне FPS-1, которые грамматика
/// НЕ порождает, обязаны отклоняться парсером. Векторы — из Приложения Б.2.
#[test]
fn a7_out_of_subset_vectors_are_rejected() {
    let negatives: Vec<(&str, &str)> = vec![
        (
            "numeric fluents",
            r#"(define (domain n) (:requirements :strips :fluents)
               (:predicates (p)) (:functions (cost))
               (:action a (:parameters ()) (:precondition (p)) (:effect (and))))"#,
        ),
        (
            "disjunctive effects",
            r#"(define (domain n) (:requirements :strips :disjunctive-effects)
               (:predicates (p) (q))
               (:action a (:parameters ()) (:precondition (p)) (:effect (or (q) (p)))))"#,
        ),
        (
            "equality",
            r#"(define (domain n) (:requirements :strips :equality)
               (:predicates (p)) (:action a (:parameters (?x))
               (:precondition (= ?x ?x)) (:effect (and (p)))))"#,
        ),
        (
            "durative action",
            r#"(define (domain n) (:requirements :strips :durative-actions)
               (:predicates (p))
               (:durative-action a (:parameters ()) (:duration (= ?d 5))
                 (:condition (at start (p))) (:effect (and (at end (p))))))"#,
        ),
        (
            "probabilistic effect",
            r#"(define (domain n) (:requirements :strips :probabilistic-effects)
               (:predicates (p) (q))
               (:action a (:parameters ()) (:precondition (p))
                 (:effect (probabilistic 0.8 (q) 0.2 (p)))))"#,
        ),
        (
            "unsupported requirement :adl",
            r#"(define (domain n) (:requirements :strips :adl)
               (:predicates (p))
               (:action a (:parameters ()) (:precondition (p)) (:effect (and))))"#,
        ),
        (
            ":constants section",
            r#"(define (domain n) (:requirements :strips :typing)
               (:types t) (:constants c - t) (:predicates (p ?x - t))
               (:action a (:parameters (?x - t)) (:precondition (p ?x)) (:effect (and))))"#,
        ),
        (
            ":derived predicate",
            r#"(define (domain n) (:requirements :strips)
               (:predicates (p) (q)) (:derived (q) (p))
               (:action a (:parameters ()) (:precondition (p)) (:effect (and))))"#,
        ),
    ];

    let mut rejected = 0usize;
    for (label, src) in &negatives {
        match pddl::parse_domain(src) {
            Ok(_) => panic!(
                "A7 НАРУШЕН (отрицательный вектор): '{}' принят парсером, хотя вне FPS-1",
                label
            ),
            Err(e) => {
                rejected += 1;
                assert!(
                    e.kind == "semantic" || e.kind == "parse",
                    "'{}': ожидался kind semantic|parse, получен '{}' ({})",
                    label,
                    e.kind,
                    e.message
                );
                assert!(!e.message.is_empty(), "'{}': диагностика пуста", label);
                println!("  ✓ {:<32} → [{}] {}", label, e.kind, e.message.chars().take(70).collect::<String>());
            }
        }
    }
    assert_eq!(rejected, negatives.len());
}

/// Детерминизм самого генератора: тот же seed ⇒ тот же корпус.
/// Без этого A7 невоспроизводим, а значит не может быть критерием приёмки.
#[test]
fn a7_corpus_generator_is_deterministic() {
    let fingerprint = |seed: u64, n: usize| -> String {
        let mut rng = Rng::new(seed);
        let mut acc = String::new();
        for i in 0..n {
            let spec = gen_spec(&mut rng, i);
            let (d, p) = render(&spec, i % 2 == 0, false);
            acc.push_str(&d);
            acc.push_str(&p);
        }
        symbolic_core::sha2::sha256_hex(acc.as_bytes())
    };

    let a = fingerprint(0xA7A7_A7A7, 200);
    let b = fingerprint(0xA7A7_A7A7, 200);
    let c = fingerprint(0xDEAD_BEEF, 200);
    assert_eq!(a, b, "один seed обязан давать идентичный корпус (G3)");
    assert_ne!(a, c, "разные seed'ы обязаны давать разные корпусы");
    println!("  corpus fingerprint (seed 0xA7A7A7A7, 200 docs) = {}", a);
}
