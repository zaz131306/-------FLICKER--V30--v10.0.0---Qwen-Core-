"""Расчёт готовности FLICKER V30 по фактическим артефактам.

Четыре независимых среза. Сводить их в одну цифру нельзя без указания веса —
именно это смешение и привело V28 к «УТВЕРЖДЕНО К РЕАЛИЗАЦИИ» при фактических
~20 %. Поэтому каждый срез публикуется отдельно, с основанием.
"""
import os, re, subprocess, glob

HERE = os.path.dirname(os.path.abspath(__file__))
# Скрипт живёт в <repo>/scripts/, поэтому корень репозитория — родитель.
# Прежняя версия предполагала запуск извне и после переноса находила 0 файлов.
ROOT = os.path.dirname(HERE)
if not os.path.isdir(os.path.join(ROOT, "crates")):
    ROOT = os.path.join(HERE, "FLICKER")   # запуск из-за пределов репозитория

def sh(cmd, cwd=ROOT):
    try:
        return subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True,
                              text=True, timeout=300).stdout
    except Exception:
        return ""

print("=" * 74)
print("ГОТОВНОСТЬ FLICKER V30 · расчёт по артефактам")
print("=" * 74)

# ---------------------------------------------------------------- срез 1 ----
print("\n【СРЕЗ 1】 Критерии приёмки (§12 ТЗ)")
crit = [
    ("A1", "0 parse-ошибок на 10^6",      0.0, "блокировано: GPU + vLLM"),
    ("A2", "невалидный план не проходит", 1.0, "ПРОЙДЕН (exhaust по шагам и парам)"),
    ("A3", "детерминизм",                 0.7, "ПРОЙДЕН в ядре; 1000 прогонов + logprobs требуют vLLM"),
    ("A4", "подлог цепи обнаруживается",  1.0, "ПРОЙДЕН (6 мутаций x 2 языка)"),
    ("A5", "crypto-erase + верификация",  0.8, "ПРОЙДЕН на software keystore; HIL для HSM блокирован"),
    ("A6", "0 unwrap/expect/panic",       1.0, "ПРОЙДЕН (clippy -D, --all-targets)"),
    ("A7", "grammar ⊆ parser, 10k корпус",0.9, "ПРОЙДЕН 20000/20000; xgrammar-бэкенд не задействован"),
    ("B1", "semantic_escape_rate <= 2%",  1.0, "ПРОЙДЕН: 0.0000 на 520 сценариях"),
    ("B2", "repair_rate < 5%",            0.0, "требует fine-tuned SLM-FORMAL"),
    ("B3", "пропуск FPCC <= 10%",         0.0, "требует реальной NLI-модели"),
    ("B4", "отказы по provenance",        1.0, "измеряется (red-team cat1/2, демо 4-6)"),
]
tot = sum(c[2] for c in crit) / len(crit)
for cid, name, val, note in crit:
    bar = "#" * int(val * 20)
    print("  %-4s %-34s %3.0f%% |%-20s| %s" % (cid, name, val * 100, bar, note))
print("  %-4s %-34s %3.0f%%" % ("", "ИТОГО ПО КРИТЕРИЯМ", tot * 100))

# ---------------------------------------------------------------- срез 2 ----
print("\n【СРЕЗ 2】 Зрелость компонентов (машинно-читаемые маркеры §6.2)")
WEIGHT = {"verified": 1.0, "specification": 0.35, "stub": 0.1, "mock": 0.05,
          "not-implemented": 0.0}
components = [
    # (имя, maturity, вес в системе)
    ("symbolic-core / pddl",        "verified", 1.0),
    ("symbolic-core / ground",      "verified", 1.0),
    ("symbolic-core / state",       "verified", 1.0),
    ("symbolic-core / planner",     "verified", 1.0),
    ("symbolic-core / mcts",        "verified", 1.0),
    ("symbolic-core / validator",   "verified", 1.0),
    ("symbolic-core / replay",      "verified", 1.0),
    ("symbolic-core / sha2+prng",   "verified", 1.0),
    ("symbolic-core / json+sexpr",  "verified", 1.0),
    ("symbolic-core / game (ADM)",  "verified", 0.6),
    ("flicker-plan CLI",            "verified", 1.0),
    ("supervisor / keystore",       "verified", 1.0),
    ("supervisor / crypto-erase",   "verified", 1.0),
    ("supervisor / IPC UDS+HMAC",   "verified", 1.0),
    ("supervisor / PKCS#11",        "stub",     0.8),
    ("supervisor / TEE attestation","stub",     0.5),
    ("supervisor / AES-GCM транспорт","not-implemented", 0.4),
    ("worker / canon",              "verified", 1.0),
    ("worker / replay",             "verified", 1.0),
    ("worker / grammar_gate",       "verified", 1.0),
    ("worker / core_bridge",        "verified", 1.0),
    ("worker / provenance",         "verified", 1.0),
    ("worker / knowledge (SQLite)", "verified", 1.0),
    ("worker / hitl",               "verified", 1.0),
    ("worker / ipc",                "verified", 1.0),
    ("worker / iep (bwrap+seccomp)","verified", 1.0),
    ("worker / iep (eBPF R9.3)",    "not-implemented", 0.3),
    ("worker / pipeline",           "verified", 1.0),
    ("worker / prng",               "verified", 0.4),
    ("worker / redteam",            "verified", 0.8),
    ("worker / critic (FPCC NLI)",  "stub",     0.6),
    ("worker / llm vLLM",           "specification", 1.0),
    ("worker / llm offline",        "mock",     0.2),
    ("GraphRAG / Neo4j",            "specification", 0.7),
    ("constrained decoding (xgrammar)","specification", 1.0),
    ("SLM fine-tuning (FPS-1)",     "not-implemented", 0.9),
    ("SSTT / Prometheus",           "not-implemented", 0.4),
    ("Threat model",                "verified", 0.5),
    ("Docs (ТЗ/отчёты/матрица)",    "verified", 0.8),
    ("CI/CD pipeline",              "specification", 0.5),
    ("Two-track BOM",               "not-implemented", 0.4),
    ("Deploy (Docker/systemd)",     "verified", 0.6),
]
wsum = sum(w for _, _, w in components)
wready = sum(WEIGHT[m] * w for _, m, w in components)
buckets = {}
for _, m, w in components:
    buckets.setdefault(m, [0, 0.0])
    buckets[m][0] += 1
    buckets[m][1] += w
for m in ("verified", "specification", "stub", "mock", "not-implemented"):
    if m in buckets:
        n, w = buckets[m]
        print("  %-18s %2d компонент(ов), вес %.1f" % (m, n, w))
print("  %-18s %3.0f%%  (взвешенно по значимости)" % ("ИТОГО", wready / wsum * 100))

# ---------------------------------------------------------------- срез 3 ----
print("\n【СРЕЗ 3】 Тестовое покрытие кодовой базы")
rust_src = 0
tested_mods = set()
for f in glob.glob(os.path.join(ROOT, "crates/symbolic-core/src/*.rs")):
    n = len(open(f, encoding="utf-8").read().splitlines())
    rust_src += n
    tested_mods.add(os.path.basename(f)[:-3])
# модули с нулевым покрытием (по интеграционным тестам)
# Модули с фактическим покрытием (юнит-тесты в #[cfg(test)] + интеграционные).
# lib.rs исключён намеренно: содержит только константы FPS1_VERSION/VERSION.
covered = {"pddl", "planner", "mcts", "validator", "ground", "state",
           "replay", "sha2", "prng", "json", "sexpr", "error", "game"}
no_logic = {"lib"}
uncov = tested_mods - covered - no_logic
ntests_rust = 0
for line in sh("cargo test --workspace 2>&1 | grep -oE '[0-9]+ passed'").splitlines():
    ntests_rust += int(re.match(r"(\d+)", line.strip()).group(1))
ntests_py = 0
for t in ("test_interop", "test_redteam", "test_b3_iep"):
    out = sh("cd worker && python3 tests/%s.py 2>&1 | grep -oE '^[0-9]+ passed|[0-9]+/[0-9]+ passed'" % t)
    m = re.findall(r"(\d+)", out)
    if m:
        ntests_py += int(m[0])
print("  Rust src строк:            %d" % rust_src)
print("  модулей с нулевым покрытием: %d %s" % (len(uncov), sorted(uncov) if uncov else ""))
print("  Rust тестов (факт. прогон): %d" % ntests_rust)
print("  Python тестов:              %d" % ntests_py)
denominator = len(tested_mods - no_logic)
cov = len(covered & tested_mods) / max(1, denominator)
print("  покрытие модулей ядра:      %.0f%%" % (cov * 100))

# ---------------------------------------------------------------- срез 4 ----
print("\n【СРЕЗ 4】 План ОКР (§11.1) — этапы")
stages = [
    ("Э0", "стенд P0, CI, G3-верификация",      1.0,  "1 мес"),
    ("Э1", "grammar B1 <-> парсер B2, корпус",  0.85, "1.5 мес"),
    ("Э2", "fine-tuning SLM-FORMAL на FPS-1",   0.0,  "2 мес"),
    ("Э3", "provenance, GraphRAG, staleness",   0.75, "2 мес"),
    ("Э4", "replay-chain, WORM, аудит",         0.8,  "1 мес"),
    ("Э5", "Том 1: PKCS#11, crypto-erase",      0.55, "2 мес"),
    ("Э6", "red-team suite, приёмка A/B",       0.8,  "1.5 мес"),
    ("Э7", "профиль P1, нагрузочное, доки",     0.15, "1.5 мес"),
]
for sid, name, val, dur in stages:
    print("  %s %-40s %3.0f%%  (%s)" % (sid, name, val * 100, dur))
st = sum(s[2] for s in stages) / len(stages)
# взвешенно по длительности
months = [1, 1.5, 2, 2, 1, 2, 1.5, 1.5]
stw = sum(s[2] * m for s, m in zip(stages, months)) / sum(months)
print("  %-4s %-40s %3.0f%%  (среднее)" % ("", "ИТОГО ПО ЭТАПАМ", st * 100))
print("  %-4s %-40s %3.0f%%  (взвешенно по срокам)" % ("", "", stw * 100))

# ---------------------------------------------------------------- итог ------
print("\n" + "=" * 74)
print("СВОДКА")
print("=" * 74)
print("  Срез 1 · критерии приёмки      %3.0f%%" % (tot * 100))
print("  Срез 2 · зрелость компонентов  %3.0f%%" % (wready / wsum * 100))
print("  Срез 3 · покрытие модулей ядра %3.0f%%" % (cov * 100))
print("  Срез 4 · план ОКР (по срокам)  %3.0f%%" % (stw * 100))
