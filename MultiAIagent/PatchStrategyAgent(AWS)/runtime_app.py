from __future__ import annotations

def invoke(payload: dict | None) -> dict:
    from patch_runtime.patch_actions import invoke as patch_strategy_invoke

    return patch_strategy_invoke(payload or {})
