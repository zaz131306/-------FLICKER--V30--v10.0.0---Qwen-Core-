"""Барьер IEP · Isolated Execution Pool (§9 ТЗ, R9.1–R9.6).

Изолированное исполнение **недоверенного** кода. Недоверенным считается весь
код, порождённый моделью, включая синтаксически валидный PDDL и любые
вспомогательные скрипты (R9.5).

## Четыре слоя

| Слой | Механизм | Требование |
|---|---|---|
| Namespaces | `bwrap --unshare-all` (user/pid/net/mount/ipc/uts/cgroup) | R9.1 |
| Filesystem | `--ro-bind / /`, `--tmpfs /tmp`, `--dev /dev` | R9.1 |
| Syscalls | seccomp-BPF whitelist (`deploy/seccomp/flicker_seccomp.c`) | R9.2 |
| Ресурсы | `setrlimit`: CPU, AS, NPROC, FSIZE, NOFILE | R9.6 |

Слои избыточны намеренно: netns уже блокирует сеть, но seccomp запрещает
`socket()` независимо. Полагаться на один барьер там, где цена ошибки
неограничена, неверно.

## Адаптивное зондирование возможностей

Набор доступных флагов bwrap **зависит от окружения**. В частности, `--proc`
требует права монтирования procfs, а `--setenv` в ряде контейнеров завершается
ошибкой. Предполагать их наличие нельзя: молчаливый отказ bwrap выглядел бы как
«изоляция работает», хотя команда просто не запустилась.

Поэтому `probe_environment()` эмпирически проверяет каждый необязательный флаг
и возвращает фактический набор. То, что применить не удалось, **фиксируется в
`IepResult.policy_notes`** — аудит видит реальные условия, а не заявленные.

`--setenv` не используется вовсе: вместо него `--clearenv` плюс **абсолютные
пути** к интерпретаторам. Это сильнее по двум причинам: окружение не наследуется
(секреты вроде `FLICKER_SESSION_KEY` не утекают в песочницу) и нет зависимости
от флага, который может не работать.

## Время жизни процесса

R9.4: пул инициализируется заранее (cold-start вне критического пути), время
жизни процесса — **одна задача**, после чего он уничтожается, а не
переиспользуется. Переиспользование означало бы, что состояние предыдущей
задачи влияет на следующую — это и канал утечки, и источник недетерминизма.

## Честное ограничение

Если изоляция недоступна, пул **отказывается исполнять код**, а не переходит в
«неизолированный режим». Деградация изоляции — это снятие барьера, а не снижение
качества. Флаг `allow_unisolated` существует только для диагностики, по
умолчанию `False`, и его использование отмечается в результате как
`isolated=False` с явной пометкой в `policy_notes`.
"""

from __future__ import annotations

import os
import resource
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Optional

__all__ = [
    "IepError", "IepResult", "Rlimits", "IepPolicy", "IsolatedExecutionPool",
    "probe_environment", "SECCOMP_HELPER_CANDIDATES",
]


class IepError(RuntimeError):
    """Изоляция недоступна или нарушена."""


#: Кандидаты на роль seccomp-хелпера (R9.2). Собирается через `make seccomp`.
SECCOMP_HELPER_CANDIDATES = (
    "deploy/seccomp/flicker_seccomp",
    "/opt/flicker/deploy/seccomp/flicker_seccomp",
    "/usr/local/bin/flicker_seccomp",
)


@dataclass(frozen=True)
class Rlimits:
    """Ресурсные лимиты (R9.6). Превышение даёт отказ, а не OOM-kill соседей."""
    cpu_seconds: int = 10
    address_space_bytes: int = 512 * 1024 * 1024     # 512 МБ
    max_processes: int = 32
    max_file_bytes: int = 16 * 1024 * 1024           # 16 МБ
    max_open_files: int = 64

    def as_pairs(self) -> list[tuple[int, int]]:
        return [
            (resource.RLIMIT_CPU, self.cpu_seconds),
            (resource.RLIMIT_AS, self.address_space_bytes),
            (resource.RLIMIT_NPROC, self.max_processes),
            (resource.RLIMIT_FSIZE, self.max_file_bytes),
            (resource.RLIMIT_NOFILE, self.max_open_files),
        ]


@dataclass(frozen=True)
class IepPolicy:
    """Политика изоляции. Значения по умолчанию — из R9.1/R9.2/R9.6.

    Поля `proc` и `dev` — ЗАПРОС, а не гарантия: применяются только если
    зондирование подтвердило доступность (см. docstring модуля).
    """
    unshare_all: bool = True
    ro_bind_root: bool = True
    tmpfs_tmp: bool = True
    die_with_parent: bool = True
    dev: bool = True
    proc: bool = True                 # применяется только если доступно
    clearenv: bool = True             # секреты не наследуются в песочницу
    extra_ro_binds: tuple[str, ...] = ()
    rlimits: Rlimits = field(default_factory=Rlimits)
    timeout_seconds: float = 15.0
    #: Путь к seccomp-хелперу; None -> автопоиск по SECCOMP_HELPER_CANDIDATES.
    seccomp_helper: Optional[str] = None
    #: Использовать seccomp, если хелпер найден (R9.2).
    use_seccomp: bool = True
    #: Отклонять исполнение, если изоляция недоступна. Только для диагностики.
    allow_unisolated: bool = False


@dataclass
class IepResult:
    ok: bool
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    elapsed_ms: int = 0
    isolated: bool = False
    timed_out: bool = False
    resource_exceeded: bool = False
    policy_notes: list[str] = field(default_factory=list)
    applied_flags: list[str] = field(default_factory=list)
    seccomp_applied: bool = False
    marker: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "exit_code": self.exit_code,
            "stdout_len": len(self.stdout),
            "stderr_head": self.stderr[:300],
            "elapsed_ms": self.elapsed_ms,
            "isolated": self.isolated,
            "timed_out": self.timed_out,
            "resource_exceeded": self.resource_exceeded,
            "policy_notes": list(self.policy_notes),
            "applied_flags": list(self.applied_flags),
            "seccomp_applied": self.seccomp_applied,
            "marker": self.marker,
        }


def _find_seccomp_helper(explicit: Optional[str] = None) -> Optional[str]:
    cands: list[str] = []
    if explicit:
        cands.append(explicit)
    env = os.environ.get("FLICKER_SECCOMP_HELPER")
    if env:
        cands.append(env)
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(os.path.dirname(here))
    for c in SECCOMP_HELPER_CANDIDATES:
        cands.append(c if os.path.isabs(c) else os.path.join(repo, c))
    for c in cands:
        if c and os.path.exists(c) and os.access(c, os.X_OK):
            return c
    return None


def probe_environment(bwrap: Optional[str] = None,
                      policy: Optional[IepPolicy] = None) -> dict[str, Any]:
    """Эмпирически определить, какие механизмы изоляции доступны.

    Возвращает словарь с фактическим состоянием. Он пишется в replay-лог,
    чтобы аудит видел условия исполнения, а не заявленные.
    """
    p = policy or IepPolicy()
    exe = bwrap or shutil.which("bwrap")
    helper = _find_seccomp_helper(p.seccomp_helper)

    info: dict[str, Any] = {
        "bwrap_path": exe,
        "bwrap_available": bool(exe),
        "seccomp_helper": helper,
        "seccomp_available": bool(helper),
        "user_namespaces": False,
        "flags_available": {},
        "effective_flags": [],
        "isolation_verified": False,
        "notes": [],
    }
    if not exe:
        info["notes"].append("bwrap not found in PATH")
        return info

    try:
        with open("/proc/sys/user/max_user_namespaces", "r", encoding="utf-8") as f:
            info["max_user_namespaces"] = int(f.read().strip())
            info["user_namespaces"] = info["max_user_namespaces"] > 0
    except (OSError, ValueError):
        info["notes"].append("cannot read max_user_namespaces")

    base = ["--unshare-all", "--ro-bind", "/", "/", "--tmpfs", "/tmp"]

    def works(extra: list[str]) -> bool:
        try:
            r = subprocess.run([exe] + base + extra + ["/bin/true"],
                               capture_output=True, timeout=20)
            return r.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    # Проверяем каждый необязательный флаг отдельно: их доступность
    # независима, и отказ одного не должен снимать остальные.
    optional = {
        "--dev /dev": ["--dev", "/dev"],
        "--proc /proc": ["--proc", "/proc"],
        "--die-with-parent": ["--die-with-parent"],
        "--clearenv": ["--clearenv"],
    }
    for name, flags in optional.items():
        ok = works(flags)
        info["flags_available"][name] = ok
        if not ok:
            info["notes"].append("flag unavailable in this environment: %s" % name)

    eff = list(base)
    for name, flags in optional.items():
        if info["flags_available"].get(name):
            eff += flags
    info["effective_flags"] = eff

    # Итоговая проверка: запускаем реальную команду и убеждаемся, что она
    # исполнилась ВНУТРИ песочницы.
    try:
        r = subprocess.run([exe] + eff + ["/bin/sh", "-c", "echo FLICKER_IEP_PROBE_OK"],
                           capture_output=True, text=True, timeout=25)
        info["isolation_verified"] = (r.returncode == 0
                                      and "FLICKER_IEP_PROBE_OK" in r.stdout)
        if not info["isolation_verified"]:
            info["notes"].append("probe command did not execute in the sandbox: %s"
                                 % (r.stderr.strip()[:200] or "empty stderr"))
    except (subprocess.TimeoutExpired, OSError) as e:
        info["notes"].append("probe error: %s" % e)

    if not info["flags_available"].get("--proc /proc"):
        info["notes"].append(
            "--proc недоступен: /proc внутри песочницы остаётся procfs хоста "
            "(через --ro-bind). PID namespace изолирован, но перечень процессов "
            "хоста виден. Для production требуется полноценный контейнер/VM, "
            "где монтирование procfs разрешено.")
    return info


class IsolatedExecutionPool:
    """Пул изолированного исполнения. Одна задача = один процесс (R9.4)."""

    def __init__(self, policy: Optional[IepPolicy] = None, bwrap: Optional[str] = None):
        self.policy = policy or IepPolicy()
        self._bwrap = bwrap or shutil.which("bwrap")
        self._env: Optional[dict[str, Any]] = None
        self._tasks = 0

    # ------------------------------------------------------------ lifecycle
    def warm(self) -> dict[str, Any]:
        """R9.4: cold-start и зондирование — вне критического пути."""
        if self._env is None:
            self._env = probe_environment(self._bwrap, self.policy)
        return dict(self._env)

    @property
    def usable(self) -> bool:
        env = self._env or self.warm()
        return bool(env.get("isolation_verified")) or self.policy.allow_unisolated

    @property
    def seccomp_helper(self) -> Optional[str]:
        env = self._env or self.warm()
        return env.get("seccomp_helper") if self.policy.use_seccomp else None

    def close(self) -> None:
        self._tasks = 0

    def __enter__(self) -> "IsolatedExecutionPool":
        self.warm()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---------------------------------------------------------------- build
    def _bwrap_argv(self, inner: list[str], workdir: Optional[str] = None,
                    seccomp: bool = True) -> tuple[list[str], list[str], bool]:
        env = self._env or self.warm()
        flags = list(env.get("effective_flags") or ["--unshare-all", "--ro-bind", "/", "/"])
        if not self._bwrap:
            raise IepError("bwrap binary not available")

        argv = [self._bwrap] + flags
        for b in self.policy.extra_ro_binds:
            argv += ["--ro-bind", b, b]

        helper = env.get("seccomp_helper") if (self.policy.use_seccomp and seccomp) else None
        sc_applied = False
        if helper and os.path.exists(helper):
            # КРИТИЧНО: `--tmpfs /tmp` маскирует всё содержимое /tmp. Если
            # хелпер лежит под /tmp (а рабочая область часто именно там),
            # он исчезает из песочницы и bwrap падает с `execvp ... No such
            # file`. Явный ro-bind ПОСЛЕ tmpfs возвращает его обратно:
            # в bwrap порядок аргументов определяет порядок монтирования.
            argv += ["--ro-bind", helper, helper]
            # Интерпретатор, если он тоже вне стандартных путей.
            for extra in self.policy.extra_ro_binds:
                pass  # уже добавлены выше
        if workdir:
            argv += ["--chdir", workdir]

        if helper and os.path.exists(helper):
            # seccomp-хелпер устанавливает фильтр и exec'ит цель.
            # Фильтр наследуется через execve и не может быть снят процессом.
            argv += [helper, "--"]
            sc_applied = True

        # Команды вызываются АБСОЛЮТНЫМИ путями: при --clearenv PATH пуст,
        # и поиск по имени не сработает. Это же устраняет зависимость от
        # --setenv, который в ряде окружений завершается ошибкой.
        argv += [_abspath(inner[0])] + list(inner[1:])
        return argv, flags, sc_applied

    def _preexec(self):
        """rlimits в дочернем процессе до exec (R9.6)."""
        pairs = self.policy.rlimits.as_pairs()

        def _apply() -> None:
            for which, value in pairs:
                try:
                    resource.setrlimit(which, (value, value))
                except (ValueError, OSError):
                    try:
                        os.write(2, ("[iep] setrlimit(%s,%d) unavailable\n"
                                     % (which, value)).encode())
                    except OSError:
                        pass
        return _apply

    # ----------------------------------------------------------------- run
    def run(self, argv: list[str], *, stdin_data: str = "", marker: str = "",
            workdir: Optional[str] = None, seccomp: bool = True) -> IepResult:
        """Исполнить одну задачу в изоляции. Процесс не переиспользуется."""
        env = self._env or self.warm()
        notes = list(env.get("notes") or [])
        isolated = bool(env.get("isolation_verified"))
        applied: list[str] = []
        sc_applied = False

        if not isolated:
            if not self.policy.allow_unisolated:
                raise IepError(
                    "изоляция недоступна (%s); исполнение ОТКЛОНЕНО. Деградация "
                    "изоляции запрещена: это снятие барьера, а не снижение "
                    "качества. Для диагностики используйте allow_unisolated=True."
                    % ("; ".join(env.get("notes") or []) or "probe failed"))
            notes.append("UNISOLATED: allow_unisolated=True, барьер IEP снят")

        if isolated:
            cmd, applied, sc_applied = self._bwrap_argv(argv, workdir, seccomp=seccomp)
        else:
            cmd = [_abspath(argv[0])] + list(argv[1:])

        t0 = time.time()
        timed_out = False
        try:
            p = subprocess.run(
                cmd,
                input=stdin_data.encode("utf-8") if stdin_data else b"",
                capture_output=True,
                timeout=self.policy.timeout_seconds,
                # rlimits ставим в родителе для неизолированного пути;
                # внутри bwrap preexec_fn неприменим к внутренней команде,
                # поэтому лимиты применяются к самому bwrap-процессу и
                # наследуются sandbox'ом.
                preexec_fn=self._preexec(),
            )
            rc: Optional[int] = p.returncode
            out = p.stdout.decode("utf-8", "replace")
            err = p.stderr.decode("utf-8", "replace")
        except subprocess.TimeoutExpired as e:
            timed_out = True
            rc = None
            raw_out = e.stdout if isinstance(e.stdout, bytes) else (e.stdout or "").encode()
            out = raw_out.decode("utf-8", "replace")
            err = "timed out after %.1fs" % self.policy.timeout_seconds
            if isinstance(e.stderr, bytes) and e.stderr:
                err += "; " + e.stderr.decode("utf-8", "replace")[:200]
        except OSError as e:
            return IepResult(ok=False, exit_code=None, stderr=str(e),
                             elapsed_ms=int((time.time() - t0) * 1000),
                             isolated=isolated, policy_notes=notes,
                             applied_flags=applied, seccomp_applied=sc_applied,
                             marker=marker)

        resource_exceeded = False
        if rc is not None and rc < 0:
            resource_exceeded = True
            notes.append("killed by signal %d" % (-rc))
        low = (err + out).lower()
        if "resource temporarily unavailable" in low or "memoryerror" in low:
            resource_exceeded = True
            notes.append("resource limit hit")

        self._tasks += 1
        return IepResult(
            ok=(rc == 0), exit_code=rc, stdout=out, stderr=err,
            elapsed_ms=int((time.time() - t0) * 1000),
            isolated=isolated, timed_out=timed_out,
            resource_exceeded=resource_exceeded,
            policy_notes=notes, applied_flags=applied,
            seccomp_applied=sc_applied, marker=marker,
        )

    def run_python(self, source: str, *, marker: str = "",
                   seccomp: bool = True) -> IepResult:
        """Исполнить порождённый моделью Python-код в изоляции.

        `-I` — isolated mode Python: игнорирует переменные окружения и не
        добавляет текущий каталог в sys.path. `-S` — не импортирует site,
        что сужает поверхность и ускоряет старт.
        """
        return self.run(["/usr/bin/python3", "-I", "-S", "-c", source],
                        marker=marker, seccomp=seccomp)

    def run_shell(self, script: str, *, marker: str = "",
                  seccomp: bool = True) -> IepResult:
        return self.run(["/bin/sh", "-c", script], marker=marker, seccomp=seccomp)

    # ------------------------------------------------------- self-проверки
    def verify_isolation(self) -> dict[str, Any]:
        """Эмпирические проверки, что барьеры действительно работают.

        Проверяется НАБЛЮДАЕМОЕ поведение внутри песочницы, а не факт передачи
        правильных флагов. Это принципиально: флаг может быть проигнорирован.
        """
        checks: dict[str, Any] = {}
        env = self._env or self.warm()
        checks["bwrap_available"] = bool(env.get("bwrap_available"))
        checks["seccomp_available"] = bool(env.get("seccomp_available"))
        checks["isolation_verified"] = bool(env.get("isolation_verified"))
        checks["effective_flags"] = list(env.get("effective_flags") or [])
        checks["notes"] = list(env.get("notes") or [])

        if not env.get("isolation_verified"):
            checks["skipped"] = True
            return checks

        # 1. Сеть недоступна (R9.1)
        net = self.run(["/usr/bin/python3", "-c",
                        "import socket\n"
                        "try:\n"
                        "    s=socket.socket(); s.settimeout(2); s.connect(('1.1.1.1',53))\n"
                        "    print('NET_REACHABLE')\n"
                        "except OSError as e:\n"
                        "    print('NET_BLOCKED', type(e).__name__, e.errno)\n"],
                       marker="net")
        checks["network_blocked"] = ("NET_BLOCKED" in net.stdout
                                     and "NET_REACHABLE" not in net.stdout)
        checks["network_detail"] = net.stdout.strip()[:120]

        # 2. Корневая ФС только для чтения (R9.1)
        ro = self.run(["/bin/sh", "-c",
                       "touch /etc/flicker_ro_probe 2>/dev/null && echo WRITABLE || echo READONLY"],
                      marker="ro-root")
        checks["root_readonly"] = ("READONLY" in ro.stdout and "WRITABLE" not in ro.stdout)

        # 3. /tmp доступен для записи (tmpfs)
        tw = self.run(["/bin/sh", "-c",
                       "echo x > /tmp/flicker_tmp_probe && echo TMP_WRITABLE || echo TMP_BLOCKED"],
                      marker="tmpfs")
        checks["tmp_writable"] = "TMP_WRITABLE" in tw.stdout

        # 4. Окружение не наследуется (секреты не утекают)
        os.environ["FLICKER_IEP_LEAK_PROBE"] = "secret-value"
        leak = self.run(["/bin/sh", "-c",
                         "env | grep -c FLICKER_IEP_LEAK_PROBE || true"],
                        marker="clearenv")
        del os.environ["FLICKER_IEP_LEAK_PROBE"]
        checks["env_not_leaked"] = leak.stdout.strip().startswith("0")
        checks["env_detail"] = leak.stdout.strip()[:60]

        # 5. Таймаут прерывает зависшую задачу
        hang = IsolatedExecutionPool(IepPolicy(timeout_seconds=2.0))
        hang.warm()
        hr = hang.run(["/bin/sh", "-c", "sleep 30"], marker="timeout")
        checks["timeout_enforced"] = hr.timed_out and hr.elapsed_ms < 10_000
        checks["timeout_elapsed_ms"] = hr.elapsed_ms

        # 6. seccomp: socket() запрещён СИСТЕМНЫМ ВЫЗОВОМ, а не только netns
        helper = env.get("seccomp_helper")
        if helper:
            sc = self.run(["/usr/bin/python3", "-c",
                           "import socket\n"
                           "try:\n"
                           "    socket.socket(); print('SOCKET_ALLOWED')\n"
                           "except OSError as e:\n"
                           "    print('SOCKET_EPERM', e.errno)\n"],
                          marker="seccomp")
            checks["seccomp_blocks_socket"] = ("SOCKET_EPERM 1" in sc.stdout
                                               and "SOCKET_ALLOWED" not in sc.stdout)
            checks["seccomp_detail"] = sc.stdout.strip()[:120]

            sc2 = self.run(["/usr/bin/python3", "-c",
                            "import ctypes\n"
                            "libc = ctypes.CDLL(None, use_errno=True)\n"
                            "r = libc.ptrace(0, 0, 0, 0)\n"
                            "print('PTRACE', r, ctypes.get_errno())\n"],
                           marker="seccomp-ptrace")
            checks["seccomp_blocks_ptrace"] = "PTRACE -1 1" in sc2.stdout
            checks["ptrace_detail"] = sc2.stdout.strip()[:120]
        else:
            checks["seccomp_blocks_socket"] = None
            checks["notes"].append("seccomp helper не найден: слой R9.2 не активен "
                                   "(соберите: make seccomp)")

        # 7. Ресурсный лимит по адресному пространству
        tight = IsolatedExecutionPool(IepPolicy(
            rlimits=Rlimits(address_space_bytes=192 * 1024 * 1024, cpu_seconds=5)))
        tight.warm()
        if tight.usable:
            mem = tight.run(["/usr/bin/python3", "-c",
                             "try:\n"
                             "    b = bytearray(1500*1024*1024); b[0]=1\n"
                             "    print('ALLOC_OK')\n"
                             "except MemoryError:\n"
                             "    print('ALLOC_BLOCKED')\n"],
                            marker="rlimit-as")
            checks["address_space_limited"] = ("ALLOC_BLOCKED" in mem.stdout
                                               or mem.exit_code != 0)
            checks["alloc_detail"] = (mem.stdout + mem.stderr).strip()[:150]

        required = ["network_blocked", "root_readonly", "tmp_writable",
                    "env_not_leaked", "timeout_enforced", "isolation_verified"]
        checks["required_pass"] = all(checks.get(k) for k in required)
        if checks.get("seccomp_blocks_socket") is not None:
            checks["required_pass"] = (checks["required_pass"]
                                       and checks["seccomp_blocks_socket"]
                                       and checks.get("seccomp_blocks_ptrace"))
        return checks


def _abspath(cmd: str) -> str:
    """Абсолютный путь к исполняемому файлу.

    При `--clearenv` PATH пуст, поэтому поиск по имени не сработает.
    Если путь уже абсолютный — возвращаем как есть.
    """
    if cmd.startswith("/"):
        return cmd
    found = shutil.which(cmd)
    return found or cmd
