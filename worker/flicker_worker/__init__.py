"""FLICKER Том 2 — алгоритмический контур (Python worker).

Непривилегированные сервисы: инференс Qwen3.5, constrained decoding,
provenance binding, FPCC-критик, HITL-шлюз, replay. Прямого доступа к
аппаратным ключам НЕ имеет — только через IPC к Тому 1 (§4.3 ТЗ).

Гарантии G1–G4 обеспечиваются РУСТОВЫМ ядром `symbolic-core`, а не этим
пакетом: воркер лишь подготавливает вход и вызывает ядро. Поэтому сбой или
подмена воркера не может привести к исполнению невалидного плана (G2).
"""

__version__ = "10.0.0"
FPS1_VERSION = "FPS-1/1.0"

MATURITY = {
    "canon": "verified",
    "replay": "verified",
    "core_bridge": "verified",
    "grammar_gate": "verified",
    "pipeline": "verified",
    "provenance": "verified",
    "critic": "stub",
    "hitl": "verified",
    "ipc_supervisor": "verified",
    "llm_vllm": "specification",
    "llm_offline": "mock",
    "prng": "verified",
    "redteam": "verified",
    "knowledge": "verified",
    "iep": "verified",
}
