from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from runtime_agents import run_agent


RUNTIME_ROOT = Path(os.environ.get("MULTIAI_RUNTIME_ROOT") or "/tmp/multiai")
ASSET_OUTPUT_DIR = RUNTIME_ROOT / "OutputResult" / "AssetAgent"
VULN_OUTPUT_DIR = RUNTIME_ROOT / "OutputResult" / "VulAgent"
RISK_OUTPUT_DIR = RUNTIME_ROOT / "OutputResult" / "RiskevalAgent"
PATCH_OUTPUT_DIR = RUNTIME_ROOT / "OutputResult" / "PatchImAgent"
PATCH_EXEC_OUTPUT_DIR = RUNTIME_ROOT / "OutputResult" / "PatchExecAgent"
SWARM_OUTPUT_DIR = RUNTIME_ROOT / "OutputResult" / "SwarmAgent"

PIPELINE_RESULT_PATH = SWARM_OUTPUT_DIR / "pipeline_result.json"
PATCH_CONTEXT_PATH = PATCH_OUTPUT_DIR / "patch_strategy_context.json"
PATCH_ASSET_FACT_TRACE_PATH = PATCH_OUTPUT_DIR / "asset_fact_trace.json"
PATCH_RESULT_PATH = PATCH_OUTPUT_DIR / "patch_strategy_result.json"
ASSET_INFRA_CONTEXT_PATH = ASSET_OUTPUT_DIR / "infra_context.json"
VULN_RAW_OUTPUT_PATH = VULN_OUTPUT_DIR / "focused_selected_raw_cves.json"
VULN_RISK_PAYLOAD_PATH = VULN_OUTPUT_DIR / "risk_assessment_payloads.json"
VULN_OPERATIONAL_PAYLOAD_PATH = VULN_OUTPUT_DIR / "operational_impact_payloads.json"
VULN_ASSET_MATCHING_PAYLOAD_PATH = VULN_OUTPUT_DIR / "asset_matching_payload.json"
RISK_RESULT_PATH = RISK_OUTPUT_DIR / "risk_evaluation_result.json"
PATCH_EXEC_RESULT_PATH = PATCH_EXEC_OUTPUT_DIR / "patch_execution_result.json"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def run_vuln_stage(*, cve_ids: list[str] | None = None) -> dict[str, Any]:
    request_payload: dict[str, Any] = {
        "action": "collect_vulnerabilities",
        "raw_output_path": str(VULN_RAW_OUTPUT_PATH),
        "risk_output_path": str(VULN_RISK_PAYLOAD_PATH),
        "operational_output_path": str(VULN_OPERATIONAL_PAYLOAD_PATH),
        "asset_matching_output_path": str(VULN_ASSET_MATCHING_PAYLOAD_PATH),
    }
    if cve_ids:
        request_payload["cve_ids"] = cve_ids
    vuln_stage = run_agent("vuln_collector_agent", request_payload)
    return {
        "agent": "orchestrator_pipeline",
        "stage": "vuln",
        "generated_at": _utc_now(),
        "vuln_stage": vuln_stage,
    }


def run_asset_stage(
    *,
    stack_name: str,
    region: str,
    asset_matching_payload: dict[str, Any],
    infra_matching_runtime_arn: str | None = None,
) -> dict[str, Any]:
    asset_stage = run_agent("infra_matching_agent", {
        "action": "bootstrap_asset_context",
        "stack_name": stack_name,
        "region": region,
        "asset_matching_payload": asset_matching_payload,
        "infra_matching_runtime_arn": infra_matching_runtime_arn,
        "save_path": str(ASSET_INFRA_CONTEXT_PATH),
    })
    return {
        "agent": "orchestrator_pipeline",
        "stage": "asset",
        "generated_at": _utc_now(),
        "asset_stage": asset_stage,
    }


def run_risk_stage(
    *,
    region: str,
    infra_context: dict[str, Any] | None = None,
    risk_assessment_payload: dict[str, Any] | None = None,
    infra_matching_runtime_arn: str | None = None,
) -> dict[str, Any]:
    risk_stage = run_agent("risk_evaluation_agent", {
        "action": "evaluate_risk",
        "region": region,
        "infra_context": infra_context if isinstance(infra_context, dict) else _load_json(ASSET_INFRA_CONTEXT_PATH, {}),
        "risk_assessment_payload": risk_assessment_payload if isinstance(risk_assessment_payload, dict) else _load_json(VULN_RISK_PAYLOAD_PATH, {}),
        "infra_matching_runtime_arn": infra_matching_runtime_arn,
        "save_path": str(RISK_RESULT_PATH),
    })
    return {
        "agent": "orchestrator_pipeline",
        "stage": "risk",
        "generated_at": _utc_now(),
        "risk_stage": risk_stage,
    }


def run_patch_stage(
    *,
    region: str,
    infra_context: dict[str, Any] | None = None,
    risk_result: dict[str, Any] | list[Any] | None = None,
    operational_payload: dict[str, Any] | None = None,
    infra_matching_runtime_arn: str | None = None,
    patch_impact_runtime_arn: str | None = None,
    allow_followup: bool = True,
) -> dict[str, Any]:
    resolved_infra_context = infra_context if isinstance(infra_context, dict) else _load_json(ASSET_INFRA_CONTEXT_PATH, {})
    resolved_risk_result = risk_result if isinstance(risk_result, (dict, list)) else _load_json(RISK_RESULT_PATH, {})
    resolved_operational_payload = operational_payload if isinstance(operational_payload, dict) else _load_json(VULN_OPERATIONAL_PAYLOAD_PATH, {})

    patch_stage = run_agent("patch_impact_agent", {
        "action": "run_patch_strategy",
        "region": region,
        "patch_impact_runtime_arn": patch_impact_runtime_arn,
        "infra_matching_runtime_arn": infra_matching_runtime_arn,
        "allow_followup": allow_followup,
        "infra_context": resolved_infra_context,
        "risk_result": resolved_risk_result,
        "operational_payload": resolved_operational_payload,
        "context_save_path": str(PATCH_CONTEXT_PATH),
        "asset_fact_trace_path": str(PATCH_ASSET_FACT_TRACE_PATH),
        "save_path": str(PATCH_RESULT_PATH),
    })
    return {
        "agent": "orchestrator_pipeline",
        "stage": "patch",
        "generated_at": _utc_now(),
        "patch_stage": patch_stage,
    }


def run_patch_execution_stage(
    *,
    region: str,
    prompt: str | None = None,
    impact_data: dict[str, Any] | None = None,
    patch_execution_runtime_arn: str | None = None,
) -> dict[str, Any]:

    resolved_impact_data = impact_data if isinstance(impact_data, dict) else _load_json(PATCH_RESULT_PATH, {})

    patch_execution_stage = run_agent("patch_execution_agent", {
        "action": "execute_patch",
        "region": region,
        "prompt": prompt or "보안 패치 분석 및 자동 실행",
        "impact_data": resolved_impact_data,
        "patch_execution_runtime_arn": patch_execution_runtime_arn,
        "save_path": str(PATCH_EXEC_RESULT_PATH),
    })

    return {
        "agent": "orchestrator_pipeline",
        "stage": "patch_execution",
        "generated_at": _utc_now(),
        "patch_execution_stage": patch_execution_stage,
    }
