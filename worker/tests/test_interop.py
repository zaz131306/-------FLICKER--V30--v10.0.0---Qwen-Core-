"""Интероперабельность Python ↔ Rust для канонического JSON и replay-цепи.

Это нормативный тест G4: replay-цепь пишут ОБА языка, поэтому `verify_chain`
с каждой стороны обязан принимать цепь другой стороны, а каноническая
сериализация обязана совпадать БАЙТ в БАЙТ.

Запуск:  python3 -m pytest worker/tests/test_interop.py -v
или:     python3 worker/tests/test_interop.py     (без pytest)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WORKER = os.path.dirname(HERE)
REPO = os.path.dirname(WORKER)
sys.path.insert(0, WORKER)

from flicker_worker.canon import canonical_json, sha256_hex, hmac_sha256_hex  # noqa: E402
from flicker_worker.replay import (  # noqa: E402
    GENESIS_PREV_HASH, ReplayWriter, verify_chain, verify_file,
)

PLAN_BIN = os.path.join(REPO, "target", "debug", "flicker-plan")
SUP_BIN = os.path.join(REPO, "target", "debug", "flicker-supervisor")
DOMAIN = os.path.join(REPO, "domains", "logistics.pddl")
PROBLEM = os.path.join(REPO, "domains", "logistics_p1.pddl")


def _have(binpath: str) -> bool:
    return os.path.exists(binpath)


# ---------------------------------------------------------------------------
# 1. Канонический JSON: Python против известных значений Rust
# ---------------------------------------------------------------------------

def test_canonical_matches_rust_vectors():
    """Векторы получены из `symbolic_core::json` (см. тесты json.rs)."""
    # json.rs::parse_roundtrip: каноническая форма сортирует ключи
    assert canonical_json({"x": [1, -2, {"y": "z"}], "n": None, "t": True, "f": False}) == \
        '{"f":false,"n":null,"t":true,"x":[1,-2,{"y":"z"}]}'
    # json.rs::escapes: управляющие символы и non-ASCII
    assert canonical_json('a"b\\c\nd\te\u0001ж') == '"a\\"b\\\\c\\nd\\te\\u0001ж"'
    # пустые контейнеры
    assert canonical_json({}) == "{}"
    assert canonical_json([]) == "[]"
    # порядок вставки ключей не влияет (свойство BTreeMap)
    a = canonical_json({"b": 2, "a": 1})
    b = canonical_json({"a": 1, "b": 2})
    assert a == b == '{"a":1,"b":2}'
    # вложенная сортировка
    assert canonical_json({"z": {"b": 1, "a": 2}, "a": 0}) == '{"a":0,"z":{"a":2,"b":1}}'


def test_canonical_rejects_floats():
    """`symbolic_core::json` отвергает float (тест `rejects_floats`). Python обязан тоже."""
    for bad in (1.5, 0.0, [1.0], {"a": 2.5}):
        try:
            canonical_json(bad)
        except Exception:
            continue
        raise AssertionError("float must be rejected: %r" % (bad,))


def test_bool_is_not_confused_with_int():
    # В Python bool является подклассом int — классический источник расхождений.
    assert canonical_json(True) == "true"
    assert canonical_json(False) == "false"
    assert canonical_json(1) == "1"
    assert canonical_json(0) == "0"
    assert canonical_json({"a": True, "b": 1}) == '{"a":true,"b":1}'


# ---------------------------------------------------------------------------
# 2. Криптопримитивы против векторов FIPS 180-4 / RFC 4231
# ---------------------------------------------------------------------------

def test_sha256_fips_vectors():
    assert sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256_hex(b"a" * 1_000_000) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    assert sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") == \
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"


def test_hmac_rfc4231_case1():
    assert hmac_sha256_hex(b"\x0b" * 20, b"Hi There") == \
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"


# ---------------------------------------------------------------------------
# 3. Replay-цепь: собственная верификация и обнаружение подлога
# ---------------------------------------------------------------------------

def _sample_chain() -> tuple[ReplayWriter, str]:
    w = ReplayWriter()
    w.record("model_pin", {"sha256": "abc123", "kind": "model_pin"}, ts_ms=1000)
    w.record("validation", {"steps": ["(drive t1 a b)", "(drive t1 b c)"]}, ts_ms=1001)
    w.record("operator_confirm", {"operator": "op-7"}, ts_ms=1002)
    return w, w.to_jsonl()


def test_chain_verifies_and_starts_at_genesis():
    w, jsonl = _sample_chain()
    r = verify_chain(jsonl)
    assert r.ok, r.error
    assert r.lines == 3
    assert r.root_hash == w.root_hash
    first = json.loads(jsonl.splitlines()[0])
    assert first["prev_hash"] == GENESIS_PREV_HASH
    assert first["seq"] == 0


def test_chain_detects_payload_tampering():
    _, jsonl = _sample_chain()
    assert not verify_chain(jsonl.replace("abc123", "abc999")).ok


def test_chain_detects_reordering():
    _, jsonl = _sample_chain()
    lines = jsonl.splitlines()
    assert not verify_chain("\n".join([lines[1], lines[0], lines[2]]) + "\n").ok


def test_chain_detects_middle_deletion():
    _, jsonl = _sample_chain()
    lines = jsonl.splitlines()
    assert not verify_chain("\n".join([lines[0], lines[2]]) + "\n").ok


def test_chain_detects_seq_tampering():
    _, jsonl = _sample_chain()
    lines = jsonl.splitlines()
    obj = json.loads(lines[1])
    obj["seq"] = 99
    tampered = "\n".join([lines[0], canonical_json(obj), lines[2]]) + "\n"
    assert not verify_chain(tampered).ok


def test_chain_detects_line_hash_tampering():
    _, jsonl = _sample_chain()
    lines = jsonl.splitlines()
    obj = json.loads(lines[1])
    obj["line_hash"] = "0" * 64
    tampered = "\n".join([lines[0], canonical_json(obj), lines[2]]) + "\n"
    assert not verify_chain(tampered).ok


def test_chain_detects_prev_hash_break():
    _, jsonl = _sample_chain()
    lines = jsonl.splitlines()
    obj = json.loads(lines[2])
    obj["prev_hash"] = "f" * 64
    # line_hash теперь не соответствует prev+event -> два независимых срабатывания
    tampered = "\n".join([lines[0], lines[1], canonical_json(obj)]) + "\n"
    assert not verify_chain(tampered).ok


def test_truncation_changes_root_hash():
    w, jsonl = _sample_chain()
    lines = jsonl.splitlines()
    truncated = "\n".join(lines[:2]) + "\n"
    r = verify_chain(truncated)
    assert r.ok, "валидный префикс верифицируется сам по себе"
    assert r.lines == 2
    assert r.root_hash != w.root_hash, "усечение ОБЯЗАНО менять root_hash"


def test_malformed_json_handled_not_crash():
    r = verify_chain("{ not json }\n")
    assert not r.ok
    assert r.error


def test_key_insertion_order_does_not_change_hash():
    w1 = ReplayWriter()
    w1.record("e", {"b": 2, "a": 1}, ts_ms=1)
    w2 = ReplayWriter()
    w2.record("e", {"a": 1, "b": 2}, ts_ms=1)
    assert w1.root_hash == w2.root_hash


# ---------------------------------------------------------------------------
# 4. КРОСС-ЯЗЫКОВАЯ совместимость с Rust (требует собранных бинарников)
# ---------------------------------------------------------------------------

def test_python_verifies_rust_written_chain():
    """G4 interop: цепь, записанная Rust-CLI, верифицируется Python."""
    if not _have(PLAN_BIN):
        print("SKIP: %s not built (cargo build -p flicker-plan)" % PLAN_BIN)
        return
    with tempfile.TemporaryDirectory() as d:
        trace = os.path.join(d, "rust.jsonl")
        rc = subprocess.call(
            [PLAN_BIN, "plan", "--domain", DOMAIN, "--problem", PROBLEM, "--replay", trace],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert rc == 0, "flicker-plan exited %d" % rc
        assert os.path.exists(trace), "Rust did not write a replay log"
        r = verify_file(trace)
        assert r.ok, "Python rejected a Rust-written chain: %s" % r.error
        assert r.lines >= 3, "expected several records, got %d" % r.lines


def test_rust_verifies_python_written_chain():
    """G4 interop в обратную сторону: Rust `replay-verify` принимает Python-цепь."""
    if not _have(PLAN_BIN):
        print("SKIP: %s not built" % PLAN_BIN)
        return
    w = ReplayWriter()
    w.record("model_pin", {"name": "Qwen3.5-27B", "sha256": "deadbeef"}, ts_ms=1000)
    w.record("slm_emission", {"pddl": "(define (domain d) ...)"}, ts_ms=1001)
    w.record("validation", {"valid": True, "goal_satisfied": True}, ts_ms=1002)
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "py.jsonl")
        with open(p, "w", encoding="utf-8") as f:
            f.write(w.to_jsonl())
        out = subprocess.run([PLAN_BIN, "replay-verify", "--chain", p, "--json"],
                             capture_output=True, text=True)
        assert out.returncode == 0, "Rust rejected a Python-written chain: %s%s" % (out.stdout, out.stderr)
        data = json.loads(out.stdout)
        assert data["ok"] is True
        assert data["lines"] == 3
        assert data["root_hash"] == w.root_hash, (
            "root hash mismatch: rust=%s python=%s" % (data["root_hash"], w.root_hash))


def test_rust_and_python_agree_on_canonical_hash():
    """Хэш одного и того же события обязан совпадать в обоих языках.

    Криптографические векторы FIPS 180-4 / RFC 4231 проверяет `flicker-plan
    selftest`; `flicker-supervisor selftest` проверяет keystore/crypto-erase/
    anti-replay. Здесь сверяются ОБА бинарника, а Python независимо
    пересчитывает те же векторы.
    """
    if not _have(PLAN_BIN) or not _have(SUP_BIN):
        print("SKIP: binaries not built")
        return

    # --- flicker-plan selftest: криптопримитивы, PRNG, canonical JSON, replay
    out = subprocess.run([PLAN_BIN, "selftest", "--json"], capture_output=True, text=True)
    assert out.returncode == 0, "flicker-plan selftest failed: %s" % out.stderr
    plan_data = json.loads(out.stdout)
    assert plan_data["ok"] is True, "flicker-plan selftest reported failures"
    plan_checks = {c["check"]: c["ok"] for c in plan_data["checks"]}
    for name in (
        "sha256 FIPS180-4 KAT 'abc'",
        "hmac-sha256 RFC4231 case1",
        "prng seeded determinism",
        "json canonical key order",
        "replay chain verifies",
        "replay tampering detected",
        "canon_atom order-sensitive",
    ):
        assert plan_checks.get(name) is True, "missing/failed check: %r (have %s)" % (name, sorted(plan_checks))

    # --- flicker-supervisor selftest: A5 crypto-erase, anti-replay, AAD, stub
    out2 = subprocess.run([SUP_BIN, "selftest", "--json"], capture_output=True, text=True)
    assert out2.returncode == 0, "flicker-supervisor selftest failed: %s" % out2.stderr
    sup_data = json.loads(out2.stdout)
    assert sup_data["ok"] is True, "supervisor selftest reported failures"
    sup_checks = {c["check"]: c["ok"] for c in sup_data["checks"]}
    for name in (
        "R6.1.1 verification: master unreadable after erase",
        "A5 crypto-erase < 2000 ms",
        "replayed sequence rejected",
        "MAC binds session_id (AAD)",
        "pkcs11 stub reports itself as stub",
    ):
        assert sup_checks.get(name) is True, "missing/failed check: %r (have %s)" % (name, sorted(sup_checks))

    # --- Python независимо пересчитывает те же векторы
    assert sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert hmac_sha256_hex(b"\x0b" * 20, b"Hi There") == \
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    # и канонический JSON совпадает с тем, что Rust считает каноническим
    assert canonical_json({"b": 2, "a": 1}) == '{"a":1,"b":2}'


# ---------------------------------------------------------------------------

def _run_all() -> int:
    fns = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in fns:
        try:
            fn()
            print("  PASS  %s" % name)
        except AssertionError as e:
            failed += 1
            print("  FAIL  %s: %s" % (name, e))
        except Exception as e:
            failed += 1
            print("  ERROR %s: %s: %s" % (name, type(e).__name__, e))
    print("\n%d/%d passed" % (len(fns) - failed, len(fns)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
