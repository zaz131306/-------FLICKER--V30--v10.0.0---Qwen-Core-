#!/usr/bin/env bash
# Демонстрация: 6 сценариев, модель ошибается в 5 — и ни одна ошибка
# не превращается в план, готовый к исполнению.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:-/tmp/flicker-demo}"
mkdir -p "$OUT"; rm -f "$OUT"/*.jsonl
cd worker
python3 -m flicker_worker demo --replay "$OUT/demo.jsonl"
echo
echo "── верификация replay-цепей ядром (Rust) ───────────────"
cd ..
for f in "$OUT"/*.jsonl; do
  [ -e "$f" ] || continue
  ./target/debug/flicker-plan replay-verify --chain "$f"
done
