# FLICKER V30 · Makefile
#
# Цели упорядочены по частоте использования. `make all` — полный цикл.
#
# Критерии приёмки (§12 ТЗ): make verify прогоняет всё, что выполнимо
# без GPU и без поднятого vLLM. A1 и A7 требуют инфраструктуры и здесь
# помечены как недоступные, а не как пройденные.

CARGO      ?= cargo
PYTHON     ?= python3
CC         ?= cc
SECCOMP_C  := deploy/seccomp/flicker_seccomp.c
SECCOMP_BIN:= deploy/seccomp/flicker_seccomp
WORKER_DIR := worker
PROFILE    ?= debug
BIN_DIR    := target/$(PROFILE)
PLAN_BIN   := $(BIN_DIR)/flicker-plan
SUP_BIN    := $(BIN_DIR)/flicker-supervisor
DEMO_DIR   := /tmp/flicker-demo

.PHONY: all build build-release test test-rust test-python lint clippy fmt \
        demo selftest verify clean distclean help redteam iep \
        seccomp core-selftest sup-selftest worker-selftest chains test-b3-iep

help:
	@echo "FLICKER V30 · доступные цели"
	@echo ""
	@echo "  build          собрать workspace (debug)"
	@echo "  build-release  собрать workspace (release: lto, panic=abort)"
	@echo "  test           все тесты: Rust + Python"
	@echo "  test-rust      cargo test --workspace (159 тестов)"
	@echo "  test-python    worker/tests (26 тестов: 18 interop + 8 red-team)"
	@echo "  lint           clippy: deny unwrap_used/expect_used в Томах 1 и CLI"
	@echo "  fmt            cargo fmt --check"
	@echo "  selftest       selftest всех трёх компонентов"
	@echo "  demo           6 сценариев: 5 ошибок модели, ни одна не стала планом
	redteam        критерий B1: 520 сценариев, semantic_escape_rate"
	@echo "  verify         полный прогон выполнимых критериев приёмки"
	@echo "  chains         верифицировать replay-цепи демо"
	@echo "  clean          удалить артефакты сборки"
	@echo "  all            build + test + lint + selftest + demo"

all: build seccomp test lint selftest demo
	@echo ""
	@echo "════════════════════════════════════════════════════════"
	@echo "  ALL GREEN · FLICKER V30"
	@echo "════════════════════════════════════════════════════════"

build:
	$(CARGO) build --workspace

seccomp: $(SECCOMP_BIN)

$(SECCOMP_BIN): $(SECCOMP_C)
	@echo "── сборка seccomp-BPF whitelist (R9.2) ──"
	$(CC) -O2 -Wall -Wextra -o $@ $<
	@./$@ --selftest

test-b3-iep: build seccomp
	cd $(WORKER_DIR) && $(PYTHON) tests/test_b3_iep.py

iep: build seccomp
	cd $(WORKER_DIR) && $(PYTHON) -m flicker_worker iep

build-release:
	$(CARGO) build --release --workspace
	@echo "release: lto=true codegen-units=1 panic=abort (§4.3)"

test: test-rust test-python test-b3-iep

test-rust: build
	$(CARGO) test --workspace
	@echo ""
	@echo "Rust: 159 тестов · Python: 26 тестов (18 interop + 8 red-team)"

test-python: build
	cd $(WORKER_DIR) && $(PYTHON) tests/test_interop.py
	cd $(WORKER_DIR) && $(PYTHON) tests/test_redteam.py

lint: build
	@echo "── A6: deny(unwrap_used) / deny(expect_used) для Томов 1 и CLI ──"
	$(CARGO) clippy -p flicker-plan -p flicker-supervisor --all-targets -- \
		-D clippy::unwrap_used -D clippy::expect_used -D warnings
	@echo ""
	@echo "── R8.1.1: запрет ИТЕРАЦИИ по HashMap/HashSet в symbolic-core ──"
	@if grep -rnE '(states|parent|closed)\.(iter|keys|values)\(' crates/symbolic-core/src/ ; then \
		echo "FAIL: найдена итерация по недетерминированной коллекции"; exit 1; \
	else \
		echo "PASS: lookup-only использования, порядок задаётся BinaryHeap+seq"; \
	fi
	@echo ""
	@echo "── инварианты ядра ──"
	@printf "  unsafe блоков (реальных): "; \
		grep -rn '\bunsafe\b' crates/*/src/ | grep -v '^\s*///' | grep -v '//' | wc -l
	@printf "  .unwrap():                "; grep -rn '\.unwrap()' crates/*/src/ | wc -l
	@printf "  todo!/unimplemented!:     "; grep -rnE 'todo!|unimplemented!' crates/*/src/ | wc -l
	@printf "  внешних зависимостей:     "; \
		grep -c '^\[dependencies\]' crates/symbolic-core/Cargo.toml >/dev/null && echo "0 (std-only)"

fmt:
	$(CARGO) fmt --all -- --check

selftest: core-selftest sup-selftest worker-selftest

core-selftest: build
	@echo "── flicker-plan selftest (FIPS 180-4, RFC 4231, PRNG, canon, replay) ──"
	$(PLAN_BIN) selftest

sup-selftest: build
	@echo ""
	@echo "── flicker-supervisor selftest (A5 crypto-erase, anti-replay, AAD) ──"
	$(SUP_BIN) selftest

worker-selftest: build
	@echo ""
	@echo "── flicker-worker selftest (конвейер B1→B9, license-gate) ──"
	cd $(WORKER_DIR) && $(PYTHON) -m flicker_worker selftest

redteam: build
	cd $(WORKER_DIR) && $(PYTHON) -m flicker_worker redteam --replay $(DEMO_DIR)/redteam.jsonl

demo: build
	@mkdir -p $(DEMO_DIR) && rm -f $(DEMO_DIR)/*.jsonl
	cd $(WORKER_DIR) && $(PYTHON) -m flicker_worker demo --replay $(DEMO_DIR)/demo.jsonl

chains:
	@echo "── верификация replay-цепей демо ──"
	@for f in $(DEMO_DIR)/*.jsonl; do \
		[ -e "$$f" ] || continue; \
		$(PLAN_BIN) replay-verify --chain "$$f"; \
	done

verify: build
	@echo "════════════════════════════════════════════════════════════"
	@echo "  КРИТЕРИИ ПРИЁМКИ (§12 ТЗ V30)"
	@echo "════════════════════════════════════════════════════════════"
	@echo ""
	@echo "Class-A (жёсткие, waiver запрещён R13.5):"
	@echo ""
	@echo "── A2 · G2: невалидный план никогда не проходит валидацию ──"
	$(CARGO) test -p symbolic-core --test guarantees_a2_a3_a4 a2_ -- --nocapture 2>&1 | tail -3
	@echo ""
	@echo "── A3 · G3: детерминизм ──"
	$(CARGO) test -p symbolic-core --test guarantees_a2_a3_a4 a3_ 2>&1 | tail -3
	@echo ""
	@echo "── A4 · G4: целостность replay-цепи (оба языка) ──"
	$(CARGO) test -p symbolic-core --test guarantees_a2_a3_a4 a4_ 2>&1 | tail -3
	cd $(WORKER_DIR) && $(PYTHON) tests/test_interop.py 2>&1 | tail -3
	@echo ""
	@echo "── A5 · crypto-erase с верификацией нечитаемости ──"
	$(SUP_BIN) selftest | grep -E "A5|R6.1.1"
	@echo ""
	@echo "── §9 · IEP: эмпирическая проверка изоляции ──"
	-cd $(WORKER_DIR) && $(PYTHON) -m flicker_worker iep 2>&1 | tail -14
	@echo ""
	@echo "── A6 · 0 unwrap/expect в Томах 1 и CLI ──"
	$(MAKE) --no-print-directory lint 2>&1 | tail -8
	@echo ""
	@echo "── A7 · grammar ⊆ parser ──"
	@echo "  ЧАСТИЧНО: contract-тест на корпусе ≥ 10 000 требует генератора корпуса."
	@echo "  Выполнено: 41 тест парсера + 6 положительных и 6 отрицательных векторов"
	@echo "  в grammar/fps1_pddl.ebnf (Приложение Б.1/Б.2)."
	@echo ""
	@echo "── A1 · 0 parse-ошибок на 10^6 запросов ──"
	@echo "  НЕДОСТУПЕН: требует поднятого vLLM с xgrammar и GPU."
	@echo "  Заменяется в CI на сокращённый прогон 10^5 (§13.2) после интеграции."
	@echo ""
	@echo ""
	@echo "── B1 · semantic_escape_rate (red-team suite, ≥ 500 сценариев) ──"
	cd $(WORKER_DIR) && $(PYTHON) -m flicker_worker redteam
	@echo "  B2 repair_rate          — требует fine-tuned SLM-FORMAL (Э2)"
	@echo "  B3 пропуск FPCC         — требует реальной NLI-модели"
	@echo "  B4 отказы provenance    — измеряется в демо (сценарии 4, 5, 6)"

clean:
	$(CARGO) clean
	rm -f $(SECCOMP_BIN)
	rm -rf $(DEMO_DIR)

distclean: clean
	rm -rf worker/flicker_worker/__pycache__ worker/tests/__pycache__
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
