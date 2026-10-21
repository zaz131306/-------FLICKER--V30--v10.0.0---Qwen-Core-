# FLICKER V30 · Qwen Core
![CI](https://github.com/zaz131306/-------FLICKER--V30--v10.0.0---Qwen-Core-/actions/workflows/ci.yml/badge.svg)
**Система когнитивной поддержки принятия решений с нейро-символическим ядром.**

LLM может ошибаться сколь угодно часто. Ни одна её ошибка не способна
превратиться в исполненное действие, не прошедшее формальную валидацию, —
и каждая попытка записана в неизменяемую аудиторскую цепочку.

| | |
|---|---|
| Версия | **10.0.0 (V30)** |
| Нормативная спецификация | **FPS-1/1.0** |
| Ядро | Rust, **0 внешних зависимостей**, std-only |
| Модель | **Qwen3.5** (Apache-2.0) |
| Тесты | **159 Rust + 49 Python** (18 interop + 8 red-team + 23 B3/IEP) |
| Лицензия | Apache-2.0 |
| Статус | reference implementation — см. [Готовность](#готовность) |

---

## Быстрый старт

```bash
# 1. Ядро (Rust >= 1.75)
cargo build --workspace
cargo test  --workspace            # 159 тестов

# 2. Том 2 (Python >= 3.10, зависимостей НЕТ)
cd worker && python3 -m flicker_worker selftest

# 3. Демонстрация: 6 сценариев, 5 из них — ошибки модели
python3 -m flicker_worker demo --replay /tmp/demo.jsonl

# 4. Один запрос сквозняком
python3 -m flicker_worker run "Перевезти груз t1 из a в c" \
        --backend offline --offline-mode logistics \
        --interactive --auto-approve --operator op-7 --json
```

Или всё сразу:

```bash
make all        # сборка + seccomp + все тесты + lint + selftest + демо
make seccomp    # собрать seccomp-BPF whitelist и прогнать его selftest
make iep        # эмпирическая проверка изоляции (§9)
make demo       # только демонстрация
make redteam    # критерий B1: 520 сценариев
make verify     # полный прогон критериев приёмки
```

---

## Что это решает

Нейросеть выдаёт правдоподобный текст. В ответственных применениях правдоподобие
не является приемлемым основанием для действия: нужен план, корректность которого
**доказуема**, и решение, которое **воспроизводимо и аудируемо**.

FLICKER ставит LLM внутрь конвейера, где выход модели переводится в формальную
модель (PDDL), проверяется символьным валидатором и только затем предъявляется
человеку. Ошибка модели на любом этапе приводит к **отказу**, а не к degrade.

### Четыре класса ошибок — и что с ними делает система

| | Ошибка | Устраняется? |
|---|---|---|
| **E1** | emission не является валидным PDDL | **да, конструктивно** — непредставим |
| **E2** | план нарушает предусловия или не достигает цели | **да, конструктивно** |
| **E3** | формальная модель не соответствует реальности | **нет** — снижается B3/B7, остаток предъявляется оператору |
| **E4** | в доменной модели нет сущности, которая есть в мире | **нет, в принципе** |

### Лестница гарантий

| ID | Гарантия | Уровень | Механизм |
|---|---|---|---|
| **G1** | emission синтаксически валиден | **100 % конструктивно** | constrained decoding по EBNF (`grammar/fps1_pddl.ebnf`) |
| **G2** | невалидный план не достигает исполнения | **100 % конструктивно** | `symbolic-core::validator`, жёсткий шлюз R7.4.1 |
| **G3** | идентичный вход ⇒ идентичный выход | **100 % конструктивно** | seed + канонический порядок + `temperature=0` |
| **G4** | план воспроизводим и аудируем | **100 % конструктивно** | SHA-256 hash-chain, `verify_chain` |
| **G5** | модель соответствует реальности | **НЕ ГАРАНТИРУЕТСЯ** | измеряется как `semantic_escape_rate` |

**Система не заявляет «0 % галлюцинаций».** Это утверждение ложно: валидатор
закрывает E1–E2 *внутри* формальной модели, а E3/E4 формальной проверкой не
устраняются в принципе — для этого нужно обратиться к реальности, а не к модели.
Подробно — `docs/01_ТЗ_FLICKER_V30_Qwen3.md` §3.

---

## Архитектура

### Конвейер B1 → B9

```
 запрос оператора (ЕЯ)
   │
   ├─ B1  constrained decoding   SLM-FORMAL + xgrammar/EBNF        → G1
   ├─ B1g structural gate        детектор дрейфа конфигурации
   │      repair loop ≤ 3        R7.2.1, temperature=0 на ремонте
   ├─ B2  parse + type check     symbolic-core::pddl               → G1
   ├─ B3  provenance binding     объекты и :init ⇒ база знаний     → G5 (снижает)
   ├─ B4  grounding              symbolic-core::ground             → G2
   ├─ B5  search                 best-first / MCTS (seeded)        → G3
   ├─ B6  validation             ЖЁСТКИЙ шлюз R7.4.1               → G2
   ├─ B7  FPCC critic            вероятностный, НЕ гарантия
   ├─ B8  replay hash-chain      каждое событие                    → G4
   └─ B9  HITL gate              обязательное подтверждение
   │
 план + provenance + confidence + перечень непроверенного
```

### Микроkernel: Том 1 / Том 2

| | Том 1 · `flicker-supervisor` | Том 2 · `flicker-worker` |
|---|---|---|
| Язык | Rust, привилегированный | Python, непривилегированный |
| Обязанности | keystore, crypto-erase, IPC-шлюз | инференс, provenance, критик, HITL |
| Доступ к ключам | да | **нет** — только через IPC |
| Бизнес-логика | **нет** | да |
| Связь | gRPC-over-UDS, HMAC-SHA256, AAD{session_id, sequence} | то же |

Гарантии G1–G4 обеспечивает **Rust-ядро**, а не Python-воркер. Компрометация
воркера не может привести к исполнению невалидного плана: B6 выполняется в ядре
независимо.

### Модельный слой (§5)

| Роль | Модель | Активных | Роль в конвейере |
|---|---|---|---|
| **LLM-MAIN** | Qwen3.5-122B-A10B | 10B | анализ запроса, отчёт, объяснение плана. **PDDL не порождает никогда** |
| **SLM-FORMAL** | Qwen3.5-27B | 27B | **единственная** роль, порождающая PDDL — под constrained decoding |
| **CRITIC-NLI** | Qwen3.5-9B | 9B | FPCC (вероятностный барьер) |

Все три — **Apache 2.0**, без field-of-use ограничений.

> **Почему не Llama.** Llama Community License + Acceptable Use Policy прямо
> запрещают военное применение. Для системы, заявленной для оборонного
> заказчика, это нарушение лицензии **на уровне архитектуры**, неустранимое
> конфигурацией. Переход на Qwen3.5 устраняет дефект и заодно снижает
> потребность в железе с 4× DGX H100 (32 GPU) до 1 узла 8× GPU, поскольку
> MoE активирует 10B параметров из 122B.

> **Лицензия в семействе Qwen неоднородна.** Qwen3/3.5 — Apache 2.0, но
> `Qwen3.8-Flash-Next` — Qwen Community License, а `Qwen3.5-Flash` — hosted API
> без весов. License-gate (`llm.py: DENIED_MODEL_PATTERNS`) проверяет конкретный
> checkpoint, а не семейство; веса пинятся по SHA-256 (`configs/model_pin.yaml`).

---

## Структура репозитория

```
FLICKER/
├── Cargo.toml                     workspace v10.0.0
├── rust-toolchain.toml            пиннинг 1.99.0 (часть контракта G3)
├── Makefile                       all / test / demo / verify / lint / clean
├── crates/
│   ├── symbolic-core/             НОРМАТИВНОЕ ЯДРО · 3 959+ строк · 0 зависимостей
│   │   ├── src/                   pddl, ground, state, planner, mcts, validator,
│   │   │                          replay, sha2, prng, json, sexpr, error, game
│   │   └── tests/                 97 интеграционных тестов
│   │       ├── common/mod.rs      общие домены и фикстуры
│   │       ├── pddl_parser.rs     41 тест парсера (A7, G1)
│   │       ├── planner_search.rs  25 тестов поиска (G3)
│   │       └── guarantees_a2_a3_a4.rs  31 тест критериев приёмки
│   ├── flicker-plan/              CLI: check · ground · plan · validate ·
│   │                                     replay-verify · selftest
│   └── supervisor/                Том 1: keystore, crypto-erase+верификация,
│                                  IPC/UDS, anti-replay, maturity-отчёт
├── worker/
│   ├── flicker_worker/            Том 2 · Python, 0 зависимостей
│   │   ├── canon.py               канонический JSON + SHA-256 (байт-совместимо с Rust)
│   │   ├── replay.py              B8 hash-chain (G4)
│   │   ├── grammar.py             B1g структурный шлюз FPS-1
│   │   ├── llm.py                 Qwen3.5: vLLM-клиент + offline-бэкенд
│   │   ├── provenance.py          B3 привязка к источникам (G5)
│   ├── knowledge.py           B3 персистентная БЗ (SQLite, row_hash, аудит)
│   ├── iep.py                 IEP: bwrap + rlimits, адаптивное зондирование
│   ├── prng.py                зеркало Xorshift64Star (детерминизм генераторов)
│   ├── redteam.py             red-team suite: 520 сценариев, критерий B1
│   │   ├── critic.py              B7 FPCC (вероятностный)
│   │   ├── hitl.py                B9 шлюз подтверждения
│   │   ├── ipc.py                 клиент Тома 1 (HMAC + AAD)
│   │   ├── pipeline.py            конвейер B1→B9
│   │   └── cli.py                 run · demo · selftest · maturity · supervisor
│   └── tests/                     49 тестов: 18 interop · 8 red-team · 23 B3/IEP
├── grammar/fps1_pddl.ebnf         B1: грамматика для xgrammar + векторы
├── domains/                       примеры PDDL (logistics, blocks, негативный)
├── configs/
│   ├── vllm_qwen35.yaml           3 роли, каждый параметр обоснован R5.3.x
│   └── model_pin.yaml             пиннинг G3, denied_models, DEP-HW-01
├── deploy/                        Dockerfile × 2, docker-compose, systemd,
│   └── seccomp/flicker_seccomp.c  raw-BPF whitelist (193 syscall, без libseccomp)
├── scripts/                       run_demo.sh, verify_g3.sh, build.sh
└── docs/                          ТЗ V30, отчёт аудита, changelog, матрица
```

---

## CLI

### `flicker-plan` — нормативное ядро

```bash
flicker-plan check    --domain d.pddl --problem p.pddl
flicker-plan ground   --domain d.pddl --problem p.pddl
flicker-plan plan     --domain d.pddl --problem p.pddl --mode auto --seed 42 --json
flicker-plan plan     --domain d.pddl --problem p.pddl --replay trace.jsonl
flicker-plan validate --domain d.pddl --problem p.pddl --plan plan.json
flicker-plan replay-verify --chain trace.jsonl
flicker-plan selftest
```

Коды выхода — стабильный контракт:

| Код | Значение |
|---|---|
| 0 | ok |
| 1 | план невалиден или цель не достигнута (**G2**) |
| 2 | ошибка использования |
| 3 | io |
| 4 | parse/semantic — вход вне FPS-1 (**G1**) |
| 5 | исчерпан бюджет поиска |
| 6 | replay-цепь повреждена (**G4**) |

Пример отказа по G1:

```
$ flicker-plan check --domain domains/reject_fluents.pddl --problem domains/logistics_p1.pddl
REJECTED [semantic] requirement ':fluents' is not in the FPS-1 subset
         (supported: strips, typing, negative-preconditions, disjunctive-preconditions,
          universal-preconditions, existential-preconditions, conditional-effects,
          universal-effects)
$ echo $?
4
```

### `flicker-supervisor` — Том 1

```bash
flicker-supervisor selftest        # A5 crypto-erase, anti-replay, AAD, stub-честность
flicker-supervisor maturity        # отчёт о зрелости (§6.2)
flicker-supervisor serve --socket /run/flicker/supervisor.sock
flicker-supervisor zeroize --socket … --session-id … --session-key …
```

### `flicker-worker` — Том 2

```bash
python3 -m flicker_worker run "…" --backend offline|vllm --replay trace.jsonl --json
python3 -m flicker_worker demo --replay /tmp/demo.jsonl
python3 -m flicker_worker selftest
python3 -m flicker_worker maturity
python3 -m flicker_worker supervisor status --socket …
```

---

## Демонстрация

`make demo` прогоняет шесть сценариев. Модель намеренно ошибается в пяти:

| # | Сценарий | Барьер | Исход |
|---|---|---|---|
| 1 | корректный запрос | все | **план принят**, 2 шага |
| 2 | галлюцинация: числовой флюент (вне FPS-1) | B1g/B2 | **отказ** |
| 3 | синтаксически разрушенный выход | B1g | **отказ** |
| 4 | объект отсутствует в базе знаний | B3 (R7.5.2) | **отказ вместо догадки** |
| 5 | данные устарели (`as_of` > bound) | B3 (R7.5.3) | **отказ** |
| 6 | GraphRAG недоступен | B3 (§15.4) | **остановка системы** |

Каждый прогон пишет собственную replay-цепь; все шесть верифицируются.

> Сценарий 6 — асимметрия намеренная: FPCC-критик (B7) вероятностен, поэтому при
> его отказе система продолжает работу с пометкой `critic_unavailable`. Провенанс
> (B3) — единственный барьер против E3, поэтому его отсутствие останавливает
> систему полностью.

---

## Что видит оператор (B9)

```
========================================================================
ПЛАН НА ПОДТВЕРЖДЕНИЕ
========================================================================
Запрос: Перевезти груз t1 из пункта a в пункт c
Формальная цель: (at t1 c)
Уверенность: 0.85
Отпечаток плана: 6b8d9df498e06d3868da422d9a1606fb7a6834d6b5fbe9b2ce9b4ef9b0aadb2b

Шаги (2):
  1. drive(t1, a, b)
  2. drive(t1, b, c)

Обоснование (provenance):
  · (at t1 a)  ← tms-fleet (as_of=1791557311, age=60s, conf=0.98)
  · (road a b) ← tms-fleet (as_of=1791557311, age=60s, conf=0.98)
  · (road b c) ← tms-fleet (as_of=1791557311, age=60s, conf=0.98)

ЧТО НЕ ПРОВЕРЕНО (остаток G5):
  ✗ G5 · Соответствие формальной модели реальному положению дел формально
        НЕ гарантируется. Валидатор проверяет план внутри модели, а не
        модель против мира.
  ✗ E4 · Полнота доменной модели: если в мире есть ограничение, которого
        нет в PDDL, система выдаст формально валидный план, его нарушающий.
  ✗ E3 · Корректность трансляции запроса в формальную цель: цель предъявлена
        выше — сверьте её с намерением.
  ✗ FPCC-критик вероятностен и не несёт гарантии.
  ✗ Данные provenance актуальны на момент as_of.
========================================================================
```

Перечень непроверенного **обязателен** (R7.7.2) и не может быть пустым:
остаток G5 существует всегда. Скрытие E4 в отчётности запрещено (§12.6 ТЗ).

R7.7.4: режима автоматического исполнения не существует — конфигурационного
флага для него нет. `--auto-approve` имитирует **ввод оператора** для сквозных
тестов, шлюз при этом остаётся активным и пишется в replay.

---

## Запуск с настоящей моделью Qwen3.5

```bash
# 1. Поднять vLLM с constrained decoding (профиль P0, 1× GPU 80 ГБ)
vllm serve Qwen/Qwen3.5-27B \
  --quantization awq \
  --max-model-len 16384 \
  --temperature 0.0 --top-p 0.0 --top-k 1 --seed 42 \
  --guided-decoding-backend xgrammar \
  --no-enable-speculative-decoding

# 2. Зафиксировать хэши весов в configs/model_pin.yaml (R5.2.3)
find ./models -name '*.safetensors' -print0 | sort -z \
  | xargs -0 sha256sum | sha256sum

# 3. Указать воркеру на эндпоинт
export FLICKER_VLLM_URL=http://127.0.0.1:8000
python3 -m flicker_worker run "…" --backend vllm --replay trace.jsonl
```

**Запрещено** (§5.3): `temperature > 0`, `top_p > 0`, speculative decoding,
`trust_remote_code: true`. Каждое из них ломает G3 или открывает RCE.

**R5.3.3:** смена `tensor_parallel_size` меняет порядок редукций и требует
полной переверификации replay-цепочек.

Профили железа — `configs/model_pin.yaml`:

| Профиль | LLM-MAIN | GPU | Статус |
|---|---|---|---|
| **P0 · PoC** | Qwen3.5-27B AWQ | 1× 80 ГБ | работает сейчас |
| **P1 · Baseline** | Qwen3.5-122B-A10B FP8 | 1 узел 8× 80 ГБ | **блокирован DEP-HW-01** |
| **P2 · Target** | Qwen3.5-397B-A17B FP8 | 2 узла 16× 80 ГБ | опционально |
| **fallback** | Qwen3.5-35B-A3B | существенно меньше | рекомендован при DEP-HW-01 |

> **DEP-HW-01** — ускорители класса 80 ГБ HBM не поставляются легально в
> юрисдикцию РФ (экспортный контроль США/ЕС). Это **внешняя блокирующая
> зависимость с владельцем «заказчик»**, а не инженерная задача. Репозиторий не
> содержит и не должен содержать рекомендаций по обходу экспортного контроля.
> Все работы до её разрешения ведутся на профиле P0 либо на арендованных
> мощностях без данных с грифом.

---

## Готовность

Честная оценка по результатам аудита (`docs/02_ОТЧЁТ_аудит_FlickER_V28.md`):

| Компонент | Статус |
|---|---|
| `symbolic-core` (парсер, grounding, поиск, валидатор, replay, sha2) | **verified** — собирается, 141 тест |
| `flicker-plan` CLI | **verified** — 7 команд, стабильные коды выхода |
| `flicker-supervisor` (software keystore, crypto-erase+верификация, IPC) | **verified** — 15 тестов, сквозной UDS |
| `flicker-worker` (конвейер B1→B9, provenance, HITL, replay) | **verified** — 18 тестов, 6 сценариев демо |
| Кросс-языковая replay-цепь (Python ↔ Rust) | **verified** — root_hash совпадает |
| Constrained decoding B1 (xgrammar) | **specification** — грамматика готова, интеграция с vLLM не прогнана |
| LLM-слой Qwen3.5 | **specification** — конфиги и license-gate готовы, веса не загружены |
| PKCS#11 / HSM | **stub** — DEP-HW-01 |
| TEE attestation | **stub** — DEP-HW-01 |
| Конфиденциальность транспорта (AES-256-GCM) | **not implemented** — DEP-CRYPTO-01 |
| FPCC-критик (реальная NLI) | **stub** — офлайн возвращает `neutral` |
| Threat model (STRIDE) | **verified** — Приложение Г, 47 угроз |
| B3 персистентная БЗ (`knowledge.py`) | **verified** — SQLite, `row_hash`, аудит-цепь, 15 тестов |
| GraphRAG / Neo4j | **specification** — интерфейс совпадает, замена не затрагивает конвейер |
| IEP: bwrap + seccomp + rlimits | **verified** — проверено эмпирически; в части окружений SKIP (см. §5.1 Прил. Г) |
| seccomp-BPF whitelist (193 syscall) | **verified** — `--selftest`: `socket()`→EPERM, `ptrace`→EPERM |

Маркировка зрелости машинно-читаема: `flicker-supervisor maturity`,
`python3 -m flicker_worker maturity`. Заявлять компонент реализованным, имея
`stub`/`mock`, запрещено (R6.2).

---

## Критерии приёмки

**Class-A** (жёсткие, waiver запрещён — R13.5):

| ID | Критерий | Статус |
|---|---|---|
| A1 | 0 parse-ошибок на 10⁶ запросов при constrained decoding | требует vLLM |
| A2 | невалидный план никогда не проходит `validate_plan` | **пройден** — exhaust-тесты одиночных шагов и всех пар |
| A3 | побайтовое совпадение на 1000 прогонов | **пройден** (25 прогонов best-first, 15 MCTS) в пределах ядра |
| A4 | подлог replay-цепи обнаруживается всегда | **пройден** — 6 видов мутаций, оба языка |
| A5 | crypto-erase < 2 с **с верификацией нечитаемости** | **пройден** |
| A6 | 0 `unwrap`/`expect`/`panic!` в Томах 1 и CLI | **пройден** для `flicker-plan` и `supervisor` |
| A7 | grammar ⊆ parser на корпусе ≥ 10 000 | **пройден** — 20 000 документов (10 000 спецификаций × 2 формы) |

**Class-B** (измеряемые):

| ID | Критерий | Статус |
|---|---|---|
| **B1** | `semantic_escape_rate` ≤ 2 % | **ПРОЙДЕН: 0.0000** на 520 сценариях (300 в знаменателе) |
| **B1·E4** | неполнота модели, публикуется отдельно | **1.0000** — 100 %, ожидаемо и неизмеримо иначе |
| **B1·inj** | сопротивление prompt injection | **1.0000** — 120 сценариев, 0 проникновений |
| B2 | `repair_rate` < 5 % | требует fine-tuned SLM-FORMAL (Э2) |
| B3 | пропуск FPCC ≤ 10 % | требует реальной NLI-модели |
| B4 | отказы по provenance | измеряется в демо и red-team |

Цифра **E4 = 1.0000** — самая важная в отчёте. Она означает: когда в мире есть
ограничение, которого нет в PDDL-модели, система **всегда** выдаст формально
валидный план, его нарушающий. Это не дефект реализации, а измеренная граница
принципа. Именно поэтому она публикуется отдельной строкой, а не прячется
в общей метрике (§12.6).

`make verify` прогоняет всё, что выполнимо без GPU и без vLLM.

---

## Документы

| Файл | Содержание |
|---|---|
| `docs/01_ТЗ_FLICKER_V30_Qwen3.md` | полное ТЗ, 18 разделов + 6 приложений |
| `docs/02_ОТЧЁТ_аудит_FlickER_V28.md` | отчёт аудита: 34 дефекта, эррата, готовность |
| `docs/05_CHANGELOG_V28_to_V30.md` | трассировка каждого изменения V28 → V30 |
| `docs/06_Матрица_трассировки.md` | требование → код → тест → критерий |
| `docs/04_Приложение_А_Быстрый_старт.md` | команды, smoke-тесты, запреты |
| `docs/08_THREAT_MODEL_STRIDE.md` | **Приложение Г**: 47 угроз STRIDE, 7 остаточных рисков |
| `docs/07_ОТЧЁТ_О_СБОРКЕ.md` | отчёт о сборке: 9 дефектов, критерии приёмки, инварианты |

---

## Чего делать нельзя

| Запрет | Основание |
|---|---|
| Писать «0 % галлюцинаций», «ИИ не ошибается» | §3.3 ТЗ |
| Указывать «УТВЕРЖДЕНО К РЕАЛИЗАЦИИ / СЕРИЙНОМУ ПРОИЗВОДСТВУ» | §0.3 ТЗ |
| Ссылаться на сертификаты ФСТЭК/ФСБ и аудиты | они не получены и не проводились |
| Маркировать «КС3» без сертификата | R6.3.2 |
| Менять модель или стек без прогона A1/A3/A7 | R5.3.4, R11.4.1 |
| Брать waiver на Class-A | R13.5 |
| Скрывать категорию E4 в red-team отчётности | §12.6 ТЗ |
| Искать способы обхода DEP-HW-01 | R5.5.1 |
| Передавать материалы через публичные файлообменники | R17.3 |
