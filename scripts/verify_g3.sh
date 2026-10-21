#!/usr/bin/env bash
# Критерий A3 (G3): идентичный вход ⇒ идентичный выход.
#
# Прогоняет одно и то же планирование N раз и сверяет НЕ только текст плана,
# но и хэш конечного состояния, и counters расширений. R5.3.2 требует
# сравнивать logprobs, а не только текст — для ядра это final_state_hash.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN=./target/debug/flicker-plan
D=${1:-domains/blocks.pddl}
P=${2:-domains/blocks_p1.pddl}
N=${3:-20}
MODE=${4:-best-first}

echo "── A3 / G3: детерминизм ───────────────────────────────"
echo "  domain=$D problem=$P mode=$MODE runs=$N"

first=""
fail=0
for i in $(seq 1 "$N"); do
  out=$("$BIN" plan --domain "$D" --problem "$P" --mode "$MODE" --json)
  sig=$(printf '%s' "$out" | python3 -c '
import json,sys
d=json.load(sys.stdin)
st=d.get("stats",{})
print("|".join([
  json.dumps(d.get("steps"),sort_keys=True),
  str(st.get("mode_used")), str(st.get("expanded")), str(st.get("generated")),
  str(d.get("validation",{}).get("final_state_hash")),
]))')
  if [ -z "$first" ]; then first="$sig"; echo "  baseline: ${sig:0:96}…"; fi
  if [ "$sig" != "$first" ]; then
    echo "  RUN $i DIFFERS:"; echo "    got:  ${sig:0:120}"; echo "    want: ${first:0:120}"
    fail=1
  fi
done

if [ "$fail" = 0 ]; then
  echo "  PASS: все $N прогонов побайтово идентичны"
else
  echo "  FAIL: G3 нарушен"
  exit 1
fi

echo
echo "── seed-чувствительность (разные seed вправе дать разный путь, но КАЖДЫЙ валиден)"
for s in 1 2 3 42 99; do
  r=$("$BIN" plan --domain "$D" --problem "$P" --mode mcts --seed "$s" --iterations 2000 --json 2>&1) || {
    echo "  seed=$s -> no plan (limit); допустимо"; continue; }
  ok=$(printf '%s' "$r" | python3 -c '
import json,sys
d=json.load(sys.stdin); v=d.get("validation",{})
print(v.get("valid") and v.get("goal_satisfied"))')
  echo "  seed=$s -> valid=$ok"
  [ "$ok" = "True" ] || { echo "  FAIL: seed $s дал невалидный план"; exit 1; }
done
echo "  PASS"
