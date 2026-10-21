#!/usr/bin/env bash
# Сборка FLICKER V30. Пиннинг тулчейна — часть контракта G3 (R5.3.4):
# смена версии rustc меняет результат и требует полного прогона A1/A3/A7.
set -euo pipefail
cd "$(dirname "$0")/.."

PROFILE="${1:-debug}"
echo "── toolchain ──────────────────────────────────────────"
rustc --version
cargo --version
cc --version 2>/dev/null | head -1 || echo "cc: NOT FOUND (нужен линковщик)"
echo "── declared pin ───────────────────────────────────────"
grep -E '^(channel|components)' rust-toolchain.toml

echo "── build ($PROFILE) ───────────────────────────────────"
cargo build --workspace ${PROFILE/debug/} $([ "$PROFILE" = release ] && echo --release || true)

echo "── binaries ───────────────────────────────────────────"
for b in flicker-plan flicker-supervisor; do
  p="target/$PROFILE/$b"
  [ -x "$p" ] && printf "  %-22s %s bytes\n" "$b" "$(stat -c%s "$p")" || echo "  $b MISSING"
done
