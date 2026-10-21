"""Мост к нормативному ядру `symbolic-core` через бинарник `flicker-plan`.

Архитектурный принцип (§4.1 ТЗ): гарантии G1–G4 обеспечиваются РУСТОВЫМ ядром,
а не этим пакетом. Воркер лишь подготавливает вход и вызывает ядро. Следствие:
компрометация или сбой Python-воркера НЕ может привести к исполнению
невалидного плана — ядро отклонит его независимо.

Вызываемые барьеры:
    B2  check       — parse + type check, machine-readable диагностика
    B4  ground      — размер пространства grounding
    B5+B6 plan      — поиск + жёсткий шлюз валидации (R7.4.1)
    B6  validate    — независимая валидация готового плана (R7.4.4)
    B8  replay-verify
"""
from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from typing import Any, Optional

__all__ = [
    "CoreError", "CoreResult", "FlickerCore", "find_binary",
]


class CoreError(RuntimeError):
    """Ядро недоступно или вернуло неклассифицируемую ошибку."""


@dataclass
class CoreResult:
    ok: bool
    kind: str = ""
    message: str = ""
    pos: Optional[dict] = None
    data: dict = field(default_factory=dict)
    exit_code: int = 0
    raw_stdout: str = ""
    raw_stderr: str = ""

    @property
    def diagnostic_for_llm(self) -> str:
        """Диагностика в форме, пригодной для repair loop (§7.2, B2).

        R7.2.2: каждая итерация ремонта пишется в replay-лог, поэтому строка
        обязана быть стабильной и машиночитаемой.
        """
        loc = ""
        if self.pos:
            loc = " at line %s col %s" % (self.pos.get("line"), self.pos.get("col"))
        return "[%s]%s %s" % (self.kind or "error", loc, self.message)


def find_binary(explicit: Optional[str] = None) -> str:
    """Найти `flicker-plan`. Порядок: явный путь → $FLICKER_PLAN_BIN → target/."""
    candidates = []
    if explicit:
        candidates.append(explicit)
    env = os.environ.get("FLICKER_PLAN_BIN")
    if env:
        candidates.append(env)
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(os.path.dirname(here))
    for prof in ("release", "debug"):
        candidates.append(os.path.join(repo, "target", prof, "flicker-plan"))
    for c in candidates:
        if c and os.path.exists(c) and os.access(c, os.X_OK):
            return c
    raise CoreError(
        "flicker-plan binary not found. Build it with: cargo build -p flicker-plan\n"
        "searched: %s" % ", ".join(x for x in candidates if x)
    )


class FlickerCore:
    """Тонкая обёртка над CLI ядра. Без состояния, без кэширования."""

    def __init__(self, binary: Optional[str] = None, timeout: float = 120.0):
        self.binary = find_binary(binary)
        self.timeout = timeout

    # ------------------------------------------------------------------ low
    def _run(self, args: list[str]) -> CoreResult:
        try:
            p = subprocess.run(
                [self.binary] + args,
                capture_output=True, text=True, timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            return CoreResult(False, "limit", "flicker-plan timed out after %.0fs" % self.timeout,
                              exit_code=5)
        except OSError as e:
            raise CoreError("failed to execute %s: %s" % (self.binary, e))

        data: dict[str, Any] = {}
        if p.stdout.strip():
            try:
                data = json.loads(p.stdout)
            except json.JSONDecodeError:
                data = {"_unparsed": p.stdout}

        ok = p.returncode == 0 and data.get("ok", False)
        pos = data.get("pos") if isinstance(data.get("pos"), dict) else None
        return CoreResult(
            ok=ok,
            kind=data.get("kind", ""),
            message=data.get("message", "") or data.get("reason", "") or p.stderr.strip(),
            pos=pos,
            data=data,
            exit_code=p.returncode,
            raw_stdout=p.stdout,
            raw_stderr=p.stderr,
        )

    # ------------------------------------------------------------- barriers
    def check(self, domain_path: str, problem_path: str) -> CoreResult:
        """B2 · parse + type check against FPS-1."""
        return self._run(["check", "--domain", domain_path, "--problem", problem_path, "--json"])

    def ground(self, domain_path: str, problem_path: str) -> CoreResult:
        """B4 · grounding space size."""
        return self._run(["ground", "--domain", domain_path, "--problem", problem_path, "--json"])

    def plan(self, domain_path: str, problem_path: str, mode: str = "auto",
             seed: int = 42, max_nodes: int = 200_000, budget_ms: int = 5_000,
             iterations: int = 20_000, replay: Optional[str] = None) -> CoreResult:
        """B5+B6 · search with the hard validation gate (R7.4.1)."""
        args = ["plan", "--domain", domain_path, "--problem", problem_path, "--json",
                "--mode", mode, "--seed", str(seed),
                "--max-nodes", str(max_nodes), "--budget-ms", str(budget_ms),
                "--iterations", str(iterations)]
        if replay:
            args += ["--replay", replay]
        return self._run(args)

    def validate(self, domain_path: str, problem_path: str, plan_path: str) -> CoreResult:
        """B6 · independent re-validation of an already-issued plan (R7.4.4)."""
        return self._run(["validate", "--domain", domain_path, "--problem", problem_path,
                          "--plan", plan_path, "--json"])

    def validate_steps(self, domain_path: str, problem_path: str,
                       steps: list[dict[str, Any]]) -> CoreResult:
        """То же, но план передаётся списком, а не файлом."""
        import tempfile
        payload = {"steps": [
            {"action": s["action"], "args": list(s.get("args", []))} for s in steps
        ]}
        fd, path = tempfile.mkstemp(prefix="flicker-plan-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f)
            return self.validate(domain_path, problem_path, path)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def replay_verify(self, chain_path: str) -> CoreResult:
        """B8 · verify hash-chain integrity."""
        return self._run(["replay-verify", "--chain", chain_path, "--json"])

    def selftest(self) -> CoreResult:
        return self._run(["selftest", "--json"])

    # -------------------------------------------------------------- helpers
    @staticmethod
    def steps_from_result(res: CoreResult) -> list[dict[str, Any]]:
        """Извлечь шаги плана из результата `plan`."""
        out = []
        for s in res.data.get("steps", []) or []:
            if isinstance(s, dict):
                out.append({"action": s.get("action", ""), "args": list(s.get("args", []))})
            elif isinstance(s, str):
                out.append({"canonical": s})
        return out

    @staticmethod
    def canonical_keys(res: CoreResult) -> list[str]:
        """Канонические ключи шагов, если ядро их вернуло."""
        return [s.get("canonical") for s in res.data.get("steps", []) or []
                if isinstance(s, dict) and s.get("canonical")]
