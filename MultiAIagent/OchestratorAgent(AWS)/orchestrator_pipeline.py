from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pipeline_stages import (
    PATCH_ASSET_FACT_TRACE_PATH,
    PATCH_CONTEXT_PATH,
    PATCH_RESULT_PATH,
    PIPELINE_RESULT_PATH,
    PATCH_EXEC_RESULT_PATH,
    run_asset_stage,
    run_patch_stage,
    run_risk_stage,
    run_vuln_stage,
    run_patch_execution_stage,
)


MODULE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = MODULE_ROOT.parent.parent
DEFAULT_STACK_NAME = os.environ.get("CF_STACK_NAME", "megathon")
DEFAULT_INFRA_MATCHING_RUNTIME_ARN = (
    os.environ.get("INFRA_MATCHING_AGENTCORE_ARN")
    or os.environ.get("ASSET_MATCHING_AGENTCORE_ARN")
    or os.environ.get("ASSET_MATCHING_ARN")
)
VALID_MODES = {"full", "vuln_only", "asset_only", "risk_only", "patch_only", "test", "patch_exec_only"}
STAGE_ORDER = {
    "vuln": 1,
    "asset": 2,
    "risk": 3,
    "patch": 4,
    "patch_execution": 5,
}

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_json(path: Path, data: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _resolve_mode(payload: dict[str, Any]) -> str:
    raw_mode = str(payload.get("mode") or "full").strip().lower()
    aliases = {
        "default": "full",
        "pipeline": "full",
        "full_pipeline": "full",
        "vuln": "vuln_only",
        "vulnerability": "vuln_only",
        "asset": "asset_only",
        "risk": "risk_only",
        "patch": "patch_only",
        "stage_test": "test",
        "inject": "test",
    }
    mode = aliases.get(raw_mode, raw_mode)
    if mode not in VALID_MODES:
        raise ValueError("mode 는 full | vuln_only | asset_only | risk_only | patch_only | test | patch_exec_only 중 하나여야 합니다.")
    return mode


def _build_config(payload: dict[str, Any]) -> dict[str, Any]:
    raw_stop_stage = str(payload.get("stop_stage") or "").strip().lower() or None
    return {
        "mode": _resolve_mode(payload),
        "orchestration_style": "direct_pipeline",
        "stack_name": str(payload.get("stack_name") or "").strip() or DEFAULT_STACK_NAME,
        "region": str(payload.get("region") or "ap-northeast-2"),
        "infra_matching_runtime_arn": (
            str(payload.get("infra_matching_runtime_arn") or "").strip() or DEFAULT_INFRA_MATCHING_RUNTIME_ARN or None
        ),
        "patch_impact_runtime_arn": str(
            payload.get("patch_impact_runtime_arn") or payload.get("patch_runtime_arn") or ""
        ).strip()
        or None,
        "allow_followup": bool(payload.get("allow_followup", True)),
        "stop_stage": raw_stop_stage,
    }


def _pick_payload_value(payload: dict[str, Any], key: str) -> Any:
    if key in payload and payload.get(key) is not None:
        return payload.get(key)
    test_inputs = payload.get("test_inputs")
    if isinstance(test_inputs, dict) and key in test_inputs and test_inputs.get(key) is not None:
        return test_inputs.get(key)
    return None


def _resolve_requested_cve_ids(payload: dict[str, Any]) -> list[str] | None:
    value = _pick_payload_value(payload, "cve_ids") or _pick_payload_value(payload, "CVE_IDS") or _pick_payload_value(payload, "cve_id")
    if isinstance(value, str):
        items = [part.strip().upper() for part in value.split(",")]
        normalized = [item for item in items if item]
        return normalized or None
    if isinstance(value, list):
        normalized = [str(item).strip().upper() for item in value if str(item).strip()]
        return normalized or None
    return None


def _seed_state(payload: dict[str, Any]) -> dict[str, Any]:
    state: dict[str, Any] = {}

    vuln_stage = _pick_payload_value(payload, "vuln_stage")
    if isinstance(vuln_stage, dict):
        state["vuln_stage"] = vuln_stage.get("vuln_stage") if isinstance(vuln_stage.get("vuln_stage"), dict) else vuln_stage
    else:
        raw_result = _pick_payload_value(payload, "raw_result") or _pick_payload_value(payload, "raw_dataset")
        risk_assessment_payload = _pick_payload_value(payload, "risk_assessment_payload")
        operational_payload = _pick_payload_value(payload, "operational_payload") or _pick_payload_value(payload, "operational_impact_payload")
        asset_matching_payload = _pick_payload_value(payload, "asset_matching_payload")
        if any(isinstance(item, dict) for item in (raw_result, risk_assessment_payload, operational_payload, asset_matching_payload)):
            state["vuln_stage"] = {
                "agent": "vuln_collector_agent",
                "status": "injected",
                "raw_result": raw_result if isinstance(raw_result, dict) else {},
                "risk_assessment_payload": risk_assessment_payload if isinstance(risk_assessment_payload, dict) else {},
                "operational_impact_payload": operational_payload if isinstance(operational_payload, dict) else {},
                "asset_matching_payload": asset_matching_payload if isinstance(asset_matching_payload, dict) else {},
            }

    asset_stage = _pick_payload_value(payload, "asset_stage")
    if isinstance(asset_stage, dict):
        if isinstance(asset_stage.get("asset_stage"), dict):
            state["asset_stage"] = asset_stage["asset_stage"]
        elif isinstance(asset_stage.get("result"), dict):
            state["asset_stage"] = asset_stage
    else:
        infra_context = _pick_payload_value(payload, "infra_context")
        if isinstance(infra_context, dict):
            state["asset_stage"] = {
                "agent": "infra_matching_agent",
                "status": "injected",
                "result": infra_context,
            }

    risk_stage = _pick_payload_value(payload, "risk_stage")
    if isinstance(risk_stage, dict):
        if isinstance(risk_stage.get("risk_stage"), dict):
            state["risk_stage"] = risk_stage["risk_stage"]
        elif "result" in risk_stage:
            state["risk_stage"] = risk_stage
    else:
        risk_result = _pick_payload_value(payload, "risk_result")
        if isinstance(risk_result, (dict, list)):
            state["risk_stage"] = {
                "agent": "risk_evaluation_agent",
                "status": "injected",
                "result": risk_result,
            }

    patch_stage = _pick_payload_value(payload, "patch_stage")
    if isinstance(patch_stage, dict):
        if isinstance(patch_stage.get("patch_stage"), dict):
            state["patch_stage"] = patch_stage["patch_stage"]
        elif "result" in patch_stage:
            state["patch_stage"] = patch_stage
    else:
        patch_result = _pick_payload_value(payload, "patch_result") or _pick_payload_value(payload, "patch_strategy_result")
        if isinstance(patch_result, dict):
            state["patch_stage"] = {
                "agent": "patch_impact_agent",
                "status": "injected",
                "result": patch_result,
            }

    patch_execution_stage = _pick_payload_value(payload, "patch_execution_stage") or _pick_payload_value(payload, "patch_execution_result")
    if isinstance(patch_execution_stage, dict):
        if isinstance(patch_execution_stage.get("patch_execution_stage"), dict):
            state["patch_execution_stage"] = patch_execution_stage["patch_execution_stage"]
        elif "result" in patch_execution_stage:
            state["patch_execution_stage"] = patch_execution_stage
        else:
            state["patch_execution_stage"] = {
                "agent": "patch_execution_agent",
                "status": "injected",
                "result": patch_execution_stage,
            }

    return state


def _record_count(payload: Any) -> int:
    if isinstance(payload, dict) and isinstance(payload.get("records"), list):
        return len(payload["records"])
    if isinstance(payload, list):
        return len(payload)
    return 0


def _build_pipeline_result(state: dict[str, Any], config: dict[str, Any], agent_message: str) -> dict[str, Any]:
    patch_present = bool(state.get("patch_stage"))
    pipeline = [
        "vuln_collector_agent" if state.get("vuln_stage") else None,
        "infra_matching_agent" if state.get("asset_stage") else None,
        "risk_evaluation_agent" if state.get("risk_stage") else None,
        "patch_impact_agent" if patch_present else None,
        "patch_execution_agent" if state.get("patch_execution_stage") else None,
    ]
    result = {
        "agent": "orchestrator_agent",
        "mode": config["mode"],
        "orchestration_style": config.get("orchestration_style", "direct_pipeline"),
        "generated_at": _utc_now(),
        "stack_name": config["stack_name"],
        "region": config["region"],
        "pipeline": [step for step in pipeline if step],
        "handoff_summary": {
            "vuln_to_asset": ["asset_matching_payload"],
            "asset_to_risk": ["infra_context"],
            "vuln_to_risk": ["risk_assessment_payload"],
            "asset_to_patch": ["infra_context"],
            "vuln_to_patch": ["operational_impact_payload"],
            "risk_to_patch": ["risk_evaluation_result"],
            "patch_to_execution": ["patch_stage.result"],
        },
        "agent_message": agent_message,
        "vuln_stage": state.get("vuln_stage"),
        "asset_stage": state.get("asset_stage"),
        "risk_stage": state.get("risk_stage"),
        "patch_stage": state.get("patch_stage"),
        "patch_execution_stage": state.get("patch_execution_stage"),
        "artifacts": {
            "patch_context_path": str(PATCH_CONTEXT_PATH),
            "patch_asset_fact_trace_path": str(PATCH_ASSET_FACT_TRACE_PATH),
            "patch_result_path": str(PATCH_RESULT_PATH),
            "patch_execution_path": str(PATCH_EXEC_RESULT_PATH),
            "pipeline_result_path": str(PIPELINE_RESULT_PATH),
        },
        "test_interface": {
            "stop_stage": config.get("stop_stage"),
            "injected_state": config.get("injected_state", []),
        },
    }
    _write_json(PIPELINE_RESULT_PATH, result)
    return result


def _resolve_asset_matching_payload(state: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    vuln_stage = state.get("vuln_stage")
    if isinstance(vuln_stage, dict) and isinstance(vuln_stage.get("asset_matching_payload"), dict):
        return vuln_stage["asset_matching_payload"]
    value = _pick_payload_value(payload, "asset_matching_payload")
    if isinstance(value, dict):
        return value
    raise ValueError("asset_only 모드는 asset_matching_payload 가 필요합니다.")


def _resolve_infra_context(state: dict[str, Any], payload: dict[str, Any], *, field_name: str) -> dict[str, Any]:
    asset_stage = state.get("asset_stage")
    if isinstance(asset_stage, dict) and isinstance(asset_stage.get("result"), dict):
        return asset_stage["result"]
    value = _pick_payload_value(payload, field_name)
    if isinstance(value, dict):
        return value
    raise ValueError(f"{field_name} 가 필요합니다.")


def _resolve_risk_assessment_payload(state: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    vuln_stage = state.get("vuln_stage")
    if isinstance(vuln_stage, dict) and isinstance(vuln_stage.get("risk_assessment_payload"), dict):
        return vuln_stage["risk_assessment_payload"]
    value = _pick_payload_value(payload, "risk_assessment_payload")
    if isinstance(value, dict):
        return value
    raise ValueError("risk_only 모드는 risk_assessment_payload 가 필요합니다.")


def _resolve_risk_result(state: dict[str, Any], payload: dict[str, Any]) -> Any:
    risk_stage = state.get("risk_stage")
    if isinstance(risk_stage, dict):
        risk_result = risk_stage.get("result")
        if isinstance(risk_result, (dict, list)):
            return risk_result
    value = _pick_payload_value(payload, "risk_result")
    if isinstance(value, (dict, list)):
        return value
    raise ValueError("patch_only 모드는 risk_result 가 필요합니다.")


def _resolve_operational_payload(state: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    vuln_stage = state.get("vuln_stage")
    if isinstance(vuln_stage, dict) and isinstance(vuln_stage.get("operational_impact_payload"), dict):
        return vuln_stage["operational_impact_payload"]
    value = _pick_payload_value(payload, "operational_payload") or _pick_payload_value(payload, "operational_impact_payload")
    if isinstance(value, dict):
        return value
    raise ValueError("patch_only 모드는 operational_payload 가 필요합니다.")


def _should_execute(stop_stage: str | None, stage_name: str) -> bool:
    if not stop_stage:
        return True
    return STAGE_ORDER[stage_name] <= STAGE_ORDER[stop_stage]


def run_asset_only(payload: dict[str, Any]) -> dict[str, Any]:
    config = _build_config(payload)
    state = _seed_state(payload)
    config["injected_state"] = list(state.keys())
    state["asset_stage"] = run_asset_stage(
        stack_name=config["stack_name"],
        region=config["region"],
        asset_matching_payload=_resolve_asset_matching_payload(state, payload),
        infra_matching_runtime_arn=config["infra_matching_runtime_arn"],
    )["asset_stage"]
    return _build_pipeline_result(state, config, "asset_only 모드 실행 완료")


def run_vuln_only(payload: dict[str, Any]) -> dict[str, Any]:
    config = _build_config(payload)
    state = _seed_state(payload)
    config["injected_state"] = list(state.keys())
    if "vuln_stage" not in state:
        state["vuln_stage"] = run_vuln_stage(cve_ids=_resolve_requested_cve_ids(payload))["vuln_stage"]
    return _build_pipeline_result(state, config, "vuln_only 모드 실행 완료")


def run_risk_only(payload: dict[str, Any]) -> dict[str, Any]:
    config = _build_config(payload)
    state = _seed_state(payload)
    config["injected_state"] = list(state.keys())
    state["risk_stage"] = run_risk_stage(
        region=config["region"],
        infra_context=_resolve_infra_context(state, payload, field_name="infra_context"),
        risk_assessment_payload=_resolve_risk_assessment_payload(state, payload),
        infra_matching_runtime_arn=config["infra_matching_runtime_arn"],
    )["risk_stage"]
    return _build_pipeline_result(state, config, "risk_only 모드 실행 완료")


def run_patch_only(payload: dict[str, Any]) -> dict[str, Any]:
    config = _build_config(payload)
    state = _seed_state(payload)
    config["injected_state"] = list(state.keys())
    if "patch_stage" not in state:
        patch_stage = run_patch_stage(
            region=config["region"],
            infra_context=_resolve_infra_context(state, payload, field_name="infra_context"),
            risk_result=_resolve_risk_result(state, payload),
            operational_payload=_resolve_operational_payload(state, payload),
            infra_matching_runtime_arn=config["infra_matching_runtime_arn"],
            patch_impact_runtime_arn=config["patch_impact_runtime_arn"],
            allow_followup=config["allow_followup"],
        )
        state["patch_stage"] = patch_stage["patch_stage"]
    return _build_pipeline_result(state, config, "patch_only 모드 실행 완료")


def run_patch_exec_only(payload: dict[str, Any]) -> dict[str, Any]:
    config = _build_config(payload)
    state = _seed_state(payload)
    config["injected_state"] = list(state.keys())

    # 클라이언트가 보낸 최종 영향도 데이터 추출
    impact_data = _pick_payload_value(payload, "patch_final_result")
    if not impact_data:
        raise ValueError("patch_exec_only 모드에서는 patch_final_result 가 필요합니다.")

    # 패치 실행 에이전트 단독 호출
    state["patch_execution_stage"] = run_patch_execution_stage(
        region=config["region"],
        prompt=payload.get("prompt", "보안 패치 분석 및 자동 실행"),
        impact_data=impact_data,
    )["patch_execution_stage"]

    return _build_pipeline_result(state, config, "patch_exec_only 모드 실행 완료")


def run_orchestrator(payload: dict[str, Any]) -> dict[str, Any]:
    config = _build_config(payload)
    state = _seed_state(payload)
    config["injected_state"] = list(state.keys())

    stop_stage = config["stop_stage"]

    if _should_execute(stop_stage, "vuln") and "vuln_stage" not in state:
        state["vuln_stage"] = run_vuln_stage(cve_ids=_resolve_requested_cve_ids(payload))["vuln_stage"]
    if stop_stage == "vuln":
        return _build_pipeline_result(state, config, "vuln 단계까지 실행 완료")

    if _should_execute(stop_stage, "asset") and "asset_stage" not in state:
        state["asset_stage"] = run_asset_stage(
            stack_name=config["stack_name"],
            region=config["region"],
            asset_matching_payload=_resolve_asset_matching_payload(state, payload),
            infra_matching_runtime_arn=config["infra_matching_runtime_arn"],
        )["asset_stage"]
    if stop_stage == "asset":
        return _build_pipeline_result(state, config, "asset 단계까지 실행 완료")

    if _should_execute(stop_stage, "risk") and "risk_stage" not in state:
        state["risk_stage"] = run_risk_stage(
            region=config["region"],
            infra_context=_resolve_infra_context(state, payload, field_name="infra_context"),
            risk_assessment_payload=_resolve_risk_assessment_payload(state, payload),
            infra_matching_runtime_arn=config["infra_matching_runtime_arn"],
        )["risk_stage"]
    if stop_stage == "risk":
        return _build_pipeline_result(state, config, "risk 단계까지 실행 완료")

    if _should_execute(stop_stage, "patch") and "patch_stage" not in state:
        patch_stage = run_patch_stage(
            region=config["region"],
            infra_context=_resolve_infra_context(state, payload, field_name="infra_context"),
            risk_result=_resolve_risk_result(state, payload),
            operational_payload=_resolve_operational_payload(state, payload),
            infra_matching_runtime_arn=config["infra_matching_runtime_arn"],
            patch_impact_runtime_arn=config["patch_impact_runtime_arn"],
            allow_followup=config["allow_followup"],
        )
        state["patch_stage"] = patch_stage["patch_stage"]
    if stop_stage == "patch":
        return _build_pipeline_result(state, config, "patch 단계까지 실행 완료")

    return _build_pipeline_result(state, config, "full/test 모드 실행 완료")


def invoke(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("payload는 JSON object 형태여야 합니다.")
    mode = _resolve_mode(payload)
    if mode == "asset_only":
        return run_asset_only(payload)
    if mode == "vuln_only":
        return run_vuln_only(payload)
    if mode == "risk_only":
        return run_risk_only(payload)
    if mode == "patch_only":
        return run_patch_only(payload)
    if mode == "patch_exec_only":
        return run_patch_exec_only(payload)
    return run_orchestrator(payload)
