"""IPC-клиент Тома 1 (`flicker-supervisor`) по Unix domain socket.

Протокол — ТОЧНО как в `crates/supervisor/src/main.rs`:

    envelope = {"session_id":…, "sequence":<int>, "mac":<hex>, "body":{…}}
    mac      = HMAC-SHA256(session_key, "{session_id}|{sequence}\\n" + canonical(body))

AAD = {session_id, sequence} (§4.4, R4.4): привязка MAC к контексту сессии и
строго возрастающему порядковому номеру исключает и подмену контекста, и
повторное воспроизведение.

Том 2 НЕ имеет прямого доступа к ключам: единственный путь — этот клиент.
При недоступности супервизора конвейер обязан отказать, а не продолжить
«без криптоконтура» (§4.3).
"""
from __future__ import annotations

import json
import os
import socket
from dataclasses import dataclass
from typing import Any, Optional

from .canon import canonical_json, constant_time_eq, hmac_sha256_hex

__all__ = ["SupervisorError", "SupervisorReply", "SupervisorClient", "DEFAULT_SOCKET"]

DEFAULT_SOCKET = os.environ.get("FLICKER_SUPERVISOR_SOCK", "/run/flicker/supervisor.sock")


class SupervisorError(RuntimeError):
    """Супервизор недоступен или отказал."""


@dataclass
class SupervisorReply:
    ok: bool
    data: dict = None  # type: ignore[assignment]
    error: str = ""
    raw: str = ""

    def __post_init__(self):
        if self.data is None:
            self.data = {}


class SupervisorClient:
    def __init__(self, socket_path: Optional[str] = None,
                 session_id: str = "worker-session",
                 session_key: str = "dev-session-key",
                 timeout: float = 30.0):
        self.socket_path = socket_path or DEFAULT_SOCKET
        self.session_id = session_id
        self.session_key = session_key
        self.timeout = timeout
        # sequence строго возрастает в пределах процесса: повтор невозможен.
        self._sequence = 0

    def _next_seq(self) -> int:
        self._sequence += 1
        return self._sequence

    def _mac(self, sequence: int, body_canon: str) -> str:
        aad = "%s|%d" % (self.session_id, sequence)
        msg = (aad + "\n" + body_canon).encode("utf-8")
        return hmac_sha256_hex(self.session_key.encode("utf-8"), msg)

    def call(self, method: str, **args: Any) -> SupervisorReply:
        body = {"method": method}
        body.update(args)
        body_canon = canonical_json(body)
        seq = self._next_seq()
        envelope = {
            "session_id": self.session_id,
            "sequence": seq,
            "mac": self._mac(seq, body_canon),
            "body": body,
        }
        payload = (canonical_json(envelope) + "\n").encode("utf-8")

        if not os.path.exists(self.socket_path):
            raise SupervisorError(
                "supervisor socket %s does not exist — Том 1 не запущен. "
                "Конвейер обязан отказать: работа без криптоконтура запрещена (§4.3). "
                "Запустите: flicker-supervisor serve --socket %s"
                % (self.socket_path, self.socket_path))

        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect(self.socket_path)
                s.sendall(payload)
                s.shutdown(socket.SHUT_WR)
                chunks = []
                while True:
                    buf = s.recv(65536)
                    if not buf:
                        break
                    chunks.append(buf)
        except OSError as e:
            raise SupervisorError("IPC to %s failed: %s" % (self.socket_path, e))

        raw = b"".join(chunks).decode("utf-8", "replace").strip()
        if not raw:
            raise SupervisorError("supervisor returned an empty response")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise SupervisorError("supervisor response is not JSON: %s (%r)" % (e, raw[:200]))
        if not isinstance(data, dict):
            raise SupervisorError("supervisor response is not an object")
        ok = bool(data.get("ok", False))
        return SupervisorReply(ok=ok, data=data, error=str(data.get("error", "")), raw=raw)

    # ------------------------------------------------------------- методы
    def ping(self) -> SupervisorReply:
        return self.call("ping")

    def status(self) -> SupervisorReply:
        return self.call("status")

    def list_keys(self) -> SupervisorReply:
        return self.call("keys.list")

    def key_fingerprint(self, key_id: str) -> SupervisorReply:
        """Отпечаток ключа. Материал ключа Том 2 не получает НИКОГДА."""
        return self.call("keys.read_fingerprint", id=key_id)

    def zeroize(self) -> SupervisorReply:
        """Crypto-erase с верификацией (R6.1.1, критерий A5)."""
        return self.call("zeroize")

    def attest(self) -> SupervisorReply:
        """TEE attestation — в текущей сборке stub (DEP-HW-01)."""
        return self.call("attest")


def verify_mac_locally(session_id: str, session_key: str, sequence: int,
                       body_canon: str, mac: str) -> bool:
    """Проверка MAC на стороне клиента — для тестов и диагностики."""
    aad = "%s|%d" % (session_id, sequence)
    expected = hmac_sha256_hex(session_key.encode("utf-8"),
                               (aad + "\n" + body_canon).encode("utf-8"))
    return constant_time_eq(expected, mac)
