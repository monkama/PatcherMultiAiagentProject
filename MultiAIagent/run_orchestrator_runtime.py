#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config
from dotenv import load_dotenv


def _first_env_value(*keys: str) -> str:
    for key in keys:
        value = str(os.environ.get(key) or "").strip()
        if value:
            return value
    return ""


PROJECT_ROOT = Path(__file__).resolve().parent
REPO_ROOT = PROJECT_ROOT.parent
ENV_PATH_CANDIDATES = (
    PROJECT_ROOT / ".env",
    REPO_ROOT / ".env",
)
RESULT_ROOT = PROJECT_ROOT / "OchestraResult"
CONVERSATION_LOG_ROOT = PROJECT_ROOT / "Conversationlog"
PATCH_TO_ASSET_LOG_ROOT = CONVERSATION_LOG_ROOT / "PatchToAsset"
RISK_TO_ASSET_LOG_ROOT = CONVERSATION_LOG_ROOT / "RiskToAsset"
DEFAULT_REGION = "ap-northeast-2"
DEFAULT_STACK_NAME = "megathon"
ORCHESTRATOR_RUNTIME_ARN_ENV_KEYS = (
    "ORCHESTRATOR_AGENTCORE_ARN",
    "ORCHESTRATOR_ARN",
    "ORCHESTRATOR_RUNTIME_ARN",
)
PATCH_IMPACT_RUNTIME_ARN_ENV_KEYS = (
    "PATCH_IMPACT_AGENTCORE_ARN",
    "PATCH_IMPACT_ARN",
)
INFRA_MATCHING_RUNTIME_ARN_ENV_KEYS = (
    "INFRA_MATCHING_AGENTCORE_ARN",
    "ASSET_MATCHING_AGENTCORE_ARN",
    "ASSET_MATCHING_ARN",
)
PATCH_EXECUTION_RUNTIME_ARN_ENV_KEYS = (
    "PATCH_EXECUTION_AGENTCORE_ARN",
    "PATCH_EXECUTION_ARN",
)
DEFAULT_ORCHESTRATOR_ARN = ""
DEFAULT_PATCH_IMPACT_ARN = ""
DEFAULT_INFRA_MATCHING_ARN = ""
DEFAULT_PATCH_EXECUTION_ARN = ""
DEFAULT_READ_TIMEOUT = 900
DEFAULT_CONNECT_TIMEOUT = 10

MODE_OPTIONS = {
    "1": ("full", "전체 실행"),
    "2": ("vuln_only", "취약점 수집만"),
    "3": ("asset_only", "자산 수집만"),
    "4": ("risk_only", "위험 평가만"),
    "5": ("patch_only", "패치 영향도만"),
    "6": ("patch_exec_only", "패치 실행만"),
    "7": ("test", "중간 단계 주입 테스트"),
}

STOP_STAGE_OPTIONS = {
    "1": "vuln",
    "2": "asset",
    "3": "risk",
    "4": "patch",
    "5": "patch_execution",
}

VULN_RESULT_FILENAMES = {
    "raw_result": "focused_selected_raw_cves.json",
    "risk_assessment_payload": "risk_assessment_payloads.json",
    "operational_impact_payload": "operational_impact_payloads.json",
    "asset_matching_payload": "asset_matching_payload.json",
}


def _load_env() -> None:
    for env_path in ENV_PATH_CANDIDATES:
        if env_path.exists():
            load_dotenv(env_path)
            break


def _refresh_runtime_defaults() -> None:
    global DEFAULT_ORCHESTRATOR_ARN
    global DEFAULT_PATCH_IMPACT_ARN
    global DEFAULT_INFRA_MATCHING_ARN
    global DEFAULT_PATCH_EXECUTION_ARN

    DEFAULT_ORCHESTRATOR_ARN = _first_env_value(*ORCHESTRATOR_RUNTIME_ARN_ENV_KEYS)
    DEFAULT_PATCH_IMPACT_ARN = _first_env_value(*PATCH_IMPACT_RUNTIME_ARN_ENV_KEYS)
    DEFAULT_INFRA_MATCHING_ARN = _first_env_value(*INFRA_MATCHING_RUNTIME_ARN_ENV_KEYS)
    DEFAULT_PATCH_EXECUTION_ARN = _first_env_value(*PATCH_EXECUTION_RUNTIME_ARN_ENV_KEYS)


def _print_usage_guide() -> None:
    print(
        "\n[사용 방법]\n"
        "- 대괄호 [ ] 안에 보이는 값은 기본값입니다.\n"
        "- 기본값 그대로 쓰고 싶으면 그냥 엔터를 누르면 됩니다.\n"
        "- JSON 파일 경로를 물어볼 때는 기본 경로가 보이면 엔터만 눌러도 됩니다.\n"
        "- 결과는 OchestraResult 아래에 에이전트별 폴더로 저장됩니다.\n"
    )
    print(
        "[모드 설명]\n"
        "1. full\n"
        "   vuln -> asset -> risk -> patch -> patch_execution 전체 실행\n"
        "2. vuln_only\n"
        "   취약점 수집 에이전트만 실행\n"
        "3. asset_only\n"
        "   자산 수집 에이전트만 실행\n"
        "   필요 입력: asset_matching_payload.json\n"
        "4. risk_only\n"
        "   위험 평가 에이전트만 실행\n"
        "   필요 입력: infra_context.json, risk_assessment_payloads.json\n"
        "5. patch_only\n"
        "   패치 영향도 에이전트만 실행\n"
        "   필요 입력: infra_context.json, risk_evaluation_result.json, operational_impact_payloads.json\n"
        "   runtime ARN은 .env 에 설정하거나 실행 시 직접 입력하면 됩니다.\n"
        "   patch는 현재 OpenAI API 기반이며, 관련 runtime에는 OPENAI_API_KEY가 배포 환경에 설정돼 있어야 합니다.\n"
        "   위험도 기반 전략 판단, 필요한 경우 asset fact 조회, 최종 판단을 한 번의 patch 호출 안에서 처리합니다.\n"
        "6. patch_exec_only\n"
        "   패치 실행 에이전트만 단독으로 실행\n"
        "   필요 입력: patch_strategy_result.json\n"
        "7. test\n"
        "   중간 단계 주입 테스트\n"
        "   stop_stage 를 고르고, 그 단계에 필요한 JSON만 넣으면 됩니다.\n"
    )
    print(
        "[빠른 예시]\n"
        "- 취약점 수집만 빠르게 보고 싶다:\n"
        "  엔터 -> 2 -> 엔터 -> 엔터 -> 엔터\n"
        "- 자산 수집만 돌리고 싶다:\n"
        "  엔터 -> 3 -> 엔터 -> 엔터 -> asset_matching_payload 경로 입력(또는 기본값 엔터) -> 엔터\n"
    )


def _utc_tag() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _safe_slug(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in value.strip().lower())
    return cleaned or "run"


def _has_meaningful_json(data: Any) -> bool:
    if data is None:
        return False
    if isinstance(data, dict):
        return bool(data)
    if isinstance(data, list):
        return bool(data)
    if isinstance(data, str):
        return bool(data.strip())
    return True


def _input(prompt: str) -> str:
    return input(prompt).strip()


def _prompt_with_default(label: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    value = _input(f"{label}{suffix}: ")
    return value or (default or "")


def _prompt_yes_no(label: str, default: bool = True) -> bool:
    default_text = "Y/n" if default else "y/N"
    value = _input(f"{label} [{default_text}]: ").lower()
    if not value:
        return default
    return value in {"y", "yes", "1", "true"}


def _prompt_optional_runtime_arn(label: str, default: str | None = None) -> str:
    value = _prompt_with_default(label, default)
    return value.strip()


def _require_runtime_arn(value: str, label: str, env_keys: tuple[str, ...]) -> str:
    resolved = value.strip()
    if resolved:
        return resolved
    raise ValueError(
        f"{label}이 필요합니다. 직접 입력하거나 .env 에 {', '.join(env_keys)} 중 하나를 설정하세요."
    )


def _redact_secrets(data: Any) -> Any:
    secret_keys = {"api_key", "openai_api_key"}
    if isinstance(data, dict):
        redacted: dict[str, Any] = {}
        for key, value in data.items():
            if key in secret_keys and value:
                redacted[key] = "***REDACTED***"
            else:
                redacted[key] = _redact_secrets(value)
        return redacted
    if isinstance(data, list):
        return [_redact_secrets(item) for item in data]
    return data


def _choose_mode() -> tuple[str, str]:
    print("\n실행 모드 선택")
    for number, (_, label) in MODE_OPTIONS.items():
        print(f"{number}. {label}")
    selected = _input("번호 입력 [1]: ") or "1"
    if selected not in MODE_OPTIONS:
        raise ValueError("지원하지 않는 모드 번호입니다.")
    return MODE_OPTIONS[selected]


def _choose_stop_stage() -> str:
    print("\n중간 테스트 종료 stage 선택")
    for number, stage_name in STOP_STAGE_OPTIONS.items():
        print(f"{number}. {stage_name}")
    selected = _input("번호 입력 [4]: ") or "4"
    if selected not in STOP_STAGE_OPTIONS:
        raise ValueError("지원하지 않는 stop_stage 번호입니다.")
    return STOP_STAGE_OPTIONS[selected]


def _prompt_cve_ids(default: str | None = None) -> list[str] | None:
    raw = _prompt_with_default("CVE 목록 (쉼표 구분, 비우면 에이전트 기본값 사용)", default)
    items = [part.strip().upper() for part in raw.split(",")] if raw else []
    normalized = [item for item in items if item]
    return normalized or None


def _latest_from_dir(path: Path, filename: str) -> Path | None:
    if not path.exists():
        return None
    candidates = sorted(
        (candidate for candidate in path.rglob(filename) if candidate.is_file()),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    for candidate in candidates:
        try:
            if _has_meaningful_json(_read_json(candidate)):
                return candidate
        except Exception:
            continue
    return candidates[0] if candidates else None


def _first_existing(paths: list[Path | None]) -> Path | None:
    for path in paths:
        if path and path.exists():
            try:
                if _has_meaningful_json(_read_json(path)):
                    return path
            except Exception:
                return path
    for path in paths:
        if path and path.exists():
            return path
    return None


def _default_input_path(key: str) -> Path | None:
    latest_root = RESULT_ROOT
    if key == "asset_matching_payload":
        return _first_existing([
            latest_root / "vuln_collector_agent" / "latest" / "asset_matching_payload.json",
            latest_root / "vuln_collector_agent" / "latest" / "asset_matching_payloads.json",
            _latest_from_dir(latest_root / "vuln_collector_agent", "asset_matching_payload.json"),
            REPO_ROOT / "vuln_runtime_result" / "asset_matching_payload.json",
            PROJECT_ROOT / "OutputResult" / "VulAgent" / "asset_matching_payload.json",
        ])
    if key == "risk_assessment_payload":
        return _first_existing([
            latest_root / "vuln_collector_agent" / "latest" / "risk_assessment_payload.json",
            latest_root / "vuln_collector_agent" / "latest" / "risk_assessment_payloads.json",
            _latest_from_dir(latest_root / "vuln_collector_agent", "risk_assessment_payloads.json"),
            REPO_ROOT / "vuln_runtime_result" / "risk_assessment_payloads.json",
            PROJECT_ROOT / "OutputResult" / "VulAgent" / "risk_assessment_payloads.json",
        ])
    if key in {"operational_payload", "operational_impact_payload"}:
        return _first_existing([
            latest_root / "vuln_collector_agent" / "latest" / "operational_impact_payload.json",
            latest_root / "vuln_collector_agent" / "latest" / "operational_impact_payloads.json",
            _latest_from_dir(latest_root / "vuln_collector_agent", "operational_impact_payloads.json"),
            REPO_ROOT / "vuln_runtime_result" / "operational_impact_payloads.json",
            PROJECT_ROOT / "OutputResult" / "VulAgent" / "operational_impact_payloads.json",
        ])
    if key == "infra_context":
        return _first_existing([
            latest_root / "asset_matching_agent" / "latest" / "infra_context.json",
            _latest_from_dir(latest_root / "asset_matching_agent", "infra_context.json"),
            PROJECT_ROOT / "OutputResult" / "AssetAgent" / "infra_context.json",
        ])
    if key == "risk_result":
        return _first_existing([
            latest_root / "risk_evaluation_agent" / "latest" / "risk_evaluation_result.json",
            latest_root / "risk_evaluation_agent" / "latest" / "risk_result.json",
            _latest_from_dir(latest_root / "risk_evaluation_agent", "risk_evaluation_result.json"),
            PROJECT_ROOT / "OutputResult" / "RiskevalAgent" / "risk_evaluation_result.json",
        ])
    if key == "patch_context":
        return _first_existing([
            latest_root / "patch_impact_agent" / "latest" / "patch_strategy_context.json",
            _latest_from_dir(latest_root / "patch_impact_agent", "patch_strategy_context.json"),
            PROJECT_ROOT / "OutputResult" / "PatchImAgent" / "patch_strategy_context.json",
        ])
    if key == "asset_fact_trace":
        return _first_existing([
            latest_root / "patch_impact_agent" / "latest" / "asset_fact_trace.json",
            _latest_from_dir(latest_root / "patch_impact_agent", "asset_fact_trace.json"),
            PROJECT_ROOT / "OutputResult" / "PatchImAgent" / "asset_fact_trace.json",
        ])
    if key == "raw_result":
        return _first_existing([
            latest_root / "vuln_collector_agent" / "latest" / "focused_selected_raw_cves.json",
            _latest_from_dir(latest_root / "vuln_collector_agent", "focused_selected_raw_cves.json"),
            REPO_ROOT / "vuln_runtime_result" / "focused_selected_raw_cves.json",
            PROJECT_ROOT / "OutputResult" / "VulAgent" / "focused_selected_raw_cves.json",
        ])
    if key == "patch_result":
        return _first_existing([
            latest_root / "patch_impact_agent" / "latest" / "patch_strategy_result.json",
            _latest_from_dir(latest_root / "patch_impact_agent", "patch_strategy_result.json"),
            PROJECT_ROOT / "OutputResult" / "PatchImAgent" / "patch_strategy_result.json",
        ])
    return None


def _prompt_json_file(label: str, key: str, *, required: bool) -> Any:
    default_path = _default_input_path(key)
    prompt = f"{label} 파일 경로"
    raw_value = _prompt_with_default(prompt, str(default_path) if default_path else None)
    if not raw_value:
        if required:
            raise ValueError(f"{label} 파일이 필요합니다.")
        return None

    path = Path(raw_value).expanduser()
    if not path.is_absolute():
        path = (PROJECT_ROOT / path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"파일을 찾을 수 없습니다: {path}")
    return _read_json(path)


def _build_payload_interactively() -> tuple[dict[str, Any], str]:
    mode, label = _choose_mode()
    region = _prompt_with_default("리전", os.environ.get("AWS_DEFAULT_REGION") or DEFAULT_REGION)
    stack_name = _prompt_with_default("스택 이름", os.environ.get("CF_STACK_NAME") or DEFAULT_STACK_NAME)
    cve_default = str(os.environ.get("VULN_CVE_IDS") or "").strip() or None

    payload: dict[str, Any] = {
        "mode": mode,
        "region": region,
        "stack_name": stack_name,
    }

    if mode in {"full", "vuln_only"}:
        cve_ids = _prompt_cve_ids(cve_default)
        if cve_ids:
            payload["cve_ids"] = cve_ids

    if mode == "asset_only":
        payload["asset_matching_payload"] = _prompt_json_file("asset_matching_payload", "asset_matching_payload", required=True)
    elif mode == "risk_only":
        payload["infra_context"] = _prompt_json_file("infra_context", "infra_context", required=True)
        payload["risk_assessment_payload"] = _prompt_json_file("risk_assessment_payload", "risk_assessment_payload", required=True)
    elif mode == "patch_only":
        patch_runtime_arn = _prompt_optional_runtime_arn("Patch runtime ARN", os.environ.get("PATCH_IMPACT_ARN") or DEFAULT_PATCH_IMPACT_ARN)
        payload["patch_impact_runtime_arn"] = _require_runtime_arn(
            patch_runtime_arn,
            "Patch runtime ARN",
            PATCH_IMPACT_RUNTIME_ARN_ENV_KEYS,
        )
        infra_matching_runtime_arn = _prompt_optional_runtime_arn(
            "Infra Matching runtime ARN",
            DEFAULT_INFRA_MATCHING_ARN,
        )
        payload["infra_matching_runtime_arn"] = _require_runtime_arn(
            infra_matching_runtime_arn,
            "Infra Matching runtime ARN",
            INFRA_MATCHING_RUNTIME_ARN_ENV_KEYS,
        )
        payload["infra_context"] = _prompt_json_file("infra_context", "infra_context", required=True)
        payload["risk_result"] = _prompt_json_file("risk_result", "risk_result", required=True)
        payload["operational_payload"] = _prompt_json_file("operational_payload", "operational_payload", required=True)
        payload["allow_followup"] = True
    elif mode == "patch_exec_only":
        patch_exec_runtime_arn = _prompt_optional_runtime_arn("Patch Execution runtime ARN", os.environ.get("PATCH_EXECUTION_ARN") or DEFAULT_PATCH_EXECUTION_ARN)
        payload["patch_execution_runtime_arn"] = _require_runtime_arn(
            patch_exec_runtime_arn,
            "Patch Execution runtime ARN",
            PATCH_EXECUTION_RUNTIME_ARN_ENV_KEYS,
        )

        payload["patch_strategy_result"] = _prompt_json_file("patch_result", "patch_result", required=True)
        payload["prompt"] = _prompt_with_default("패치 실행 프롬프트", "보안 패치 분석 및 자동 실행")

    elif mode == "test":
        stop_stage = _choose_stop_stage()
        payload["stop_stage"] = stop_stage
        if stop_stage == "vuln":
            cve_ids = _prompt_cve_ids(cve_default)
            if cve_ids:
                payload["cve_ids"] = cve_ids

        if stop_stage in {"patch_execution"}:
            patch_exec_runtime_arn = _prompt_optional_runtime_arn("Patch Execution runtime ARN", os.environ.get("PATCH_EXECUTION_ARN") or DEFAULT_PATCH_EXECUTION_ARN)
            payload["patch_execution_runtime_arn"] = _require_runtime_arn(
                patch_exec_runtime_arn,
                "Patch Execution runtime ARN",
                PATCH_EXECUTION_RUNTIME_ARN_ENV_KEYS,
            )

        if stop_stage == "patch":
            patch_runtime_arn = _prompt_optional_runtime_arn("Patch runtime ARN", os.environ.get("PATCH_IMPACT_ARN") or DEFAULT_PATCH_IMPACT_ARN)
            payload["patch_impact_runtime_arn"] = _require_runtime_arn(
                patch_runtime_arn,
                "Patch runtime ARN",
                PATCH_IMPACT_RUNTIME_ARN_ENV_KEYS,
            )
            infra_matching_runtime_arn = _prompt_optional_runtime_arn(
                "Infra Matching runtime ARN",
                DEFAULT_INFRA_MATCHING_ARN,
            )
            payload["infra_matching_runtime_arn"] = _require_runtime_arn(
                infra_matching_runtime_arn,
                "Infra Matching runtime ARN",
                INFRA_MATCHING_RUNTIME_ARN_ENV_KEYS,
            )
        test_inputs: dict[str, Any] = {}
        if stop_stage == "asset":
            test_inputs["asset_matching_payload"] = _prompt_json_file("asset_matching_payload", "asset_matching_payload", required=True)
        elif stop_stage == "risk":
            test_inputs["infra_context"] = _prompt_json_file("infra_context", "infra_context", required=True)
            test_inputs["risk_assessment_payload"] = _prompt_json_file("risk_assessment_payload", "risk_assessment_payload", required=True)
        elif stop_stage == "patch":
            test_inputs["infra_context"] = _prompt_json_file("infra_context", "infra_context", required=True)
            test_inputs["risk_result"] = _prompt_json_file("risk_result", "risk_result", required=True)
            test_inputs["operational_payload"] = _prompt_json_file("operational_payload", "operational_payload", required=True)
        elif stop_stage == "patch_execution":
            test_inputs["patch_strategy_result"] = _prompt_json_file("patch_result", "patch_result", required=True)
            payload["prompt"] = _prompt_with_default("패치 실행 프롬프트 (기본값)", "보안 패치 분석 및 자동 실행")

        payload["test_inputs"] = test_inputs

    return payload, label


def _invoke_orchestrator(runtime_arn: str, region: str, payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    client = boto3.client(
        "bedrock-agentcore",
        region_name=region,
        config=Config(
            read_timeout=int(os.environ.get("ORCHESTRATOR_READ_TIMEOUT", DEFAULT_READ_TIMEOUT)),
            connect_timeout=int(os.environ.get("ORCHESTRATOR_CONNECT_TIMEOUT", DEFAULT_CONNECT_TIMEOUT)),
        ),
    )
    session_id = "orchestrator-run-" + uuid.uuid4().hex
    response = client.invoke_agent_runtime(
        agentRuntimeArn=runtime_arn,
        runtimeSessionId=session_id,
        payload=json.dumps(payload).encode("utf-8"),
        qualifier="DEFAULT",
    )
    body = response["response"].read().decode("utf-8")
    parsed = json.loads(body)
    meta = {
        "statusCode": response.get("statusCode"),
        "runtimeSessionId": response.get("runtimeSessionId"),
        "agentRuntimeArn": runtime_arn,
        "region": region,
    }
    return parsed, meta


def _save_named_json(agent_name: str, run_tag: str, filename: str, data: Any) -> None:
    run_dir = RESULT_ROOT / agent_name / run_tag
    latest_dir = RESULT_ROOT / agent_name / "latest"
    _write_json(run_dir / filename, data)
    if _has_meaningful_json(data):
        _write_json(latest_dir / filename, data)


def _save_stage_wrapper(agent_name: str, run_tag: str, stage_data: dict[str, Any]) -> None:
    _save_named_json(agent_name, run_tag, "stage_response.json", stage_data)


def _cleanup_patch_impact_output_files(run_tag: str) -> None:
    stale_filenames = (
        "stage_response.json",
        "patch_strategy_context.json",
        "asset_fact_trace.json",
        "patch_impact_prejudge_result.json",
        "patch_impact_final_result.json",
        "additional_asset_response.json",
    )
    for target_dir in (
        RESULT_ROOT / "patch_impact_agent" / run_tag,
        RESULT_ROOT / "patch_impact_agent" / "latest",
    ):
        for filename in stale_filenames:
            target = target_dir / filename
            try:
                if target.exists():
                    target.unlink()
            except OSError:
                continue


def _normalize_patch_to_asset_log(asset_fact_trace: dict[str, Any], run_tag: str) -> dict[str, Any]:
    responses = asset_fact_trace.get("responses") if isinstance(asset_fact_trace.get("responses"), list) else []
    conversations: list[dict[str, Any]] = []

    for item in responses:
        if not isinstance(item, dict):
            continue
        question_bundle = item.get("question_bundle") if isinstance(item.get("question_bundle"), dict) else {}
        response_wrapper = item.get("response") if isinstance(item.get("response"), dict) else {}
        result_wrapper = response_wrapper.get("result") if isinstance(response_wrapper.get("result"), dict) else {}
        parsed_answer = result_wrapper.get("parsed_answer") if isinstance(result_wrapper.get("parsed_answer"), dict) else {}
        transcript = response_wrapper.get("transcript") if isinstance(response_wrapper.get("transcript"), list) else None

        if transcript is None and isinstance(item.get("transcript"), list):
            transcript = []
            for turn_number, turn in enumerate(item.get("transcript", []), start=1):
                if not isinstance(turn, dict):
                    continue
                question_info = turn.get("question") if isinstance(turn.get("question"), dict) else {}
                normalized_answer = turn.get("normalized_answer") if isinstance(turn.get("normalized_answer"), dict) else {}
                question = str(
                    question_info.get("question")
                    or normalized_answer.get("question")
                    or ""
                ).strip()
                question_type = str(
                    question_info.get("type")
                    or normalized_answer.get("type")
                    or "technical_fact_check"
                ).strip()
                if not question:
                    continue
                transcript.append(
                    {
                        "turn": turn_number,
                        "question_type": question_type,
                        "question": question,
                        "answer": str(normalized_answer.get("answer") or "").strip(),
                        "evidence": str(normalized_answer.get("evidence") or "").strip(),
                        "confidence": str(normalized_answer.get("confidence") or "").strip(),
                    }
                )

        if not question_bundle:
            answers = item.get("answers") if isinstance(item.get("answers"), list) else []
            question_bundle = {
                "questions": [
                    {
                        "id": str(answer.get("id") or "").strip(),
                        "question_type": str(answer.get("type") or "technical_fact_check").strip(),
                        "question": str(answer.get("question") or "").strip(),
                    }
                    for answer in answers
                    if isinstance(answer, dict) and str(answer.get("question") or "").strip()
                ]
            }
        if not question_bundle.get("questions") and str(item.get("question") or "").strip():
            question_bundle = {
                "questions": [
                    {
                        "id": "",
                        "question_type": "technical_fact_check",
                        "question": str(item.get("question") or "").strip(),
                    }
                ]
            }

        if not parsed_answer and (isinstance(item.get("answers"), list) or isinstance(item.get("unknowns"), list)):
            parsed_answer = {
                "answers": item.get("answers", []),
                "unknowns": item.get("unknowns", []),
            }
        if not parsed_answer and any(item.get(key) for key in ("answer", "confidence", "evidence", "error")):
            parsed_answer = {
                "answer": str(item.get("answer") or "").strip(),
                "confidence": str(item.get("confidence") or "").strip(),
                "evidence": item.get("evidence") if isinstance(item.get("evidence"), list) else [],
                "status": str(item.get("status") or "").strip(),
                "error": str(item.get("error") or "").strip(),
            }

        if transcript is None:
            transcript = []
            direct_question = str(item.get("question") or "").strip()
            direct_answer = str(item.get("answer") or "").strip()
            direct_confidence = str(item.get("confidence") or "").strip()
            direct_error = str(item.get("error") or "").strip()
            direct_evidence = item.get("evidence") if isinstance(item.get("evidence"), list) else []
            if direct_question:
                transcript.append(
                    {
                        "turn": 1,
                        "speaker": "patch_impact_agent",
                        "question_type": "technical_fact_check",
                        "question": direct_question,
                    }
                )
                if direct_answer or direct_error or direct_evidence:
                    transcript.append(
                        {
                            "turn": 2,
                            "speaker": "asset_matching_agent",
                            "answer": direct_answer or None,
                            "error": direct_error or None,
                            "confidence": direct_confidence or None,
                            "evidence": direct_evidence,
                        }
                    )
            else:
                for turn_number, question_item in enumerate(question_bundle.get("questions", []), start=1):
                    if isinstance(question_item, dict):
                        question = str(question_item.get("question") or question_item.get("prompt") or "").strip()
                        question_type = str(
                            question_item.get("question_type")
                            or question_item.get("type")
                            or "technical_fact_check"
                        ).strip()
                    else:
                        question = str(question_item or "").strip()
                        question_type = "technical_fact_check"
                    if not question:
                        continue
                    transcript.append(
                        {
                            "turn": turn_number,
                            "question_type": question_type,
                            "question": question,
                        }
                    )

        request_id = str(item.get("request_id") or "").strip()
        cve_id = str(item.get("cve_id") or "").strip()
        instance_id = str(item.get("instance_id") or item.get("asset_id") or "").strip()
        if not request_id:
            request_id = "__".join(part for part in (cve_id, instance_id) if part) or f"request-{uuid.uuid4().hex[:8]}"

        conversations.append(
            {
                "request_id": request_id,
                "cve_id": cve_id,
                "instance_id": instance_id,
                "source_agent": str(item.get("source_agent") or "patch_impact_agent").strip(),
                "target_agent": str(item.get("target_agent") or "asset_matching_agent").strip(),
                "tool_rounds_used": response_wrapper.get("tool_rounds_used") or (len(item.get("answers", [])) if isinstance(item.get("answers"), list) else None),
                "conversation_trace_path": response_wrapper.get("conversation_trace_path"),
                "question_bundle": question_bundle,
                "transcript": transcript,
                "final_answer": parsed_answer,
            }
        )

    return {
        "run_tag": run_tag,
        "generated_at": asset_fact_trace.get("generated_at"),
        "response_count": asset_fact_trace.get("response_count") or len(responses),
        "conversations": conversations,
    }


def _save_patch_to_asset_conversation_log(run_tag: str, asset_fact_trace: dict[str, Any]) -> None:
    PATCH_TO_ASSET_LOG_ROOT.mkdir(parents=True, exist_ok=True)
    run_dir = PATCH_TO_ASSET_LOG_ROOT / run_tag
    run_dir.mkdir(parents=True, exist_ok=True)

    normalized_log = _normalize_patch_to_asset_log(asset_fact_trace, run_tag)
    _write_json(run_dir / "conversation_log.json", normalized_log)
    _write_json(PATCH_TO_ASSET_LOG_ROOT / "latest.json", normalized_log)

    for conversation in normalized_log.get("conversations", []):
        if not isinstance(conversation, dict):
            continue
        request_id = str(conversation.get("request_id") or "").strip() or f"request-{uuid.uuid4().hex[:8]}"
        _write_json(run_dir / f"{request_id}.json", conversation)


def _normalize_risk_to_asset_log(risk_stage: dict[str, Any], run_tag: str) -> dict[str, Any]:
    queries = risk_stage.get("swarm_queries") if isinstance(risk_stage.get("swarm_queries"), list) else []
    conversations: list[dict[str, Any]] = []

    for index, item in enumerate(queries, start=1):
        if not isinstance(item, dict):
            continue
        instance_id = str(item.get("instance_id") or item.get("asset_id") or "").strip()
        question = str(item.get("question") or "").strip()
        answer = str(item.get("answer") or "").strip()
        confidence = str(item.get("confidence") or "").strip()
        error = str(item.get("error") or "").strip()
        if not (instance_id or question or answer or error):
            continue

        request_id = (
            str(item.get("request_id") or "").strip()
            or "__".join(part for part in (instance_id, f"q{index:02d}") if part)
            or f"risk-query-{uuid.uuid4().hex[:8]}"
        )
        transcript = []
        if question:
            transcript.append(
                {
                    "turn": 1,
                    "speaker": "risk_evaluation_agent",
                    "question": question,
                }
            )
        if answer or error:
            transcript.append(
                {
                    "turn": 2,
                    "speaker": "asset_matching_agent",
                    "answer": answer or None,
                    "error": error or None,
                    "confidence": confidence or None,
                }
            )

        conversations.append(
            {
                "request_id": request_id,
                "instance_id": instance_id,
                "source_agent": "risk_evaluation_agent",
                "target_agent": "asset_matching_agent",
                "question": question,
                "answer": answer,
                "confidence": confidence,
                "error": error,
                "transcript": transcript,
            }
        )

    return {
        "run_tag": run_tag,
        "generated_at": risk_stage.get("generated_at"),
        "query_count": len(conversations),
        "conversations": conversations,
    }


def _save_risk_to_asset_conversation_log(run_tag: str, risk_stage: dict[str, Any]) -> None:
    RISK_TO_ASSET_LOG_ROOT.mkdir(parents=True, exist_ok=True)
    run_dir = RISK_TO_ASSET_LOG_ROOT / run_tag
    run_dir.mkdir(parents=True, exist_ok=True)

    normalized_log = _normalize_risk_to_asset_log(risk_stage, run_tag)
    _write_json(run_dir / "conversation_log.json", normalized_log)
    _write_json(RISK_TO_ASSET_LOG_ROOT / "latest.json", normalized_log)

    for conversation in normalized_log.get("conversations", []):
        if not isinstance(conversation, dict):
            continue
        request_id = str(conversation.get("request_id") or "").strip() or f"risk-query-{uuid.uuid4().hex[:8]}"
        _write_json(run_dir / f"{request_id}.json", conversation)


def _save_result_bundle(result: dict[str, Any], request_payload: dict[str, Any], invoke_meta: dict[str, Any]) -> dict[str, Any]:
    mode = str(result.get("mode") or request_payload.get("mode") or "unknown")
    run_tag = f"{_utc_tag()}__{_safe_slug(mode)}"
    sanitized_request_payload = _redact_secrets(request_payload)

    orchestrator_agent_name = "orchestrator_agent"
    _save_named_json(orchestrator_agent_name, run_tag, "request_payload.json", sanitized_request_payload)
    _save_named_json(orchestrator_agent_name, run_tag, "invoke_meta.json", invoke_meta)
    _save_named_json(orchestrator_agent_name, run_tag, "response.json", result)

    vuln_stage = result.get("vuln_stage") if isinstance(result.get("vuln_stage"), dict) else None
    if vuln_stage:
        _save_stage_wrapper("vuln_collector_agent", run_tag, vuln_stage)
        for key, filename in VULN_RESULT_FILENAMES.items():
            if key in vuln_stage and _has_meaningful_json(vuln_stage.get(key)):
                _save_named_json("vuln_collector_agent", run_tag, filename, vuln_stage.get(key))

    asset_stage = result.get("asset_stage") if isinstance(result.get("asset_stage"), dict) else None
    if asset_stage:
        _save_stage_wrapper("asset_matching_agent", run_tag, asset_stage)
        if "result" in asset_stage:
            _save_named_json("asset_matching_agent", run_tag, "infra_context.json", asset_stage.get("result"))

    risk_stage = result.get("risk_stage") if isinstance(result.get("risk_stage"), dict) else None
    if risk_stage:
        _save_stage_wrapper("risk_evaluation_agent", run_tag, risk_stage)
        if "result" in risk_stage:
            _save_named_json("risk_evaluation_agent", run_tag, "risk_evaluation_result.json", risk_stage.get("result"))
        if isinstance(risk_stage.get("swarm_queries"), list):
            _save_risk_to_asset_conversation_log(run_tag, risk_stage)

    patch_stage = result.get("patch_stage") if isinstance(result.get("patch_stage"), dict) else None
    if patch_stage:
        asset_fact_trace = patch_stage.get("asset_fact_trace") if isinstance(patch_stage.get("asset_fact_trace"), dict) else None
        patch_result = patch_stage.get("result") if isinstance(patch_stage.get("result"), dict) else None
        _cleanup_patch_impact_output_files(run_tag)
        if asset_fact_trace:
            _save_patch_to_asset_conversation_log(run_tag, asset_fact_trace)
        if patch_result:
            _save_named_json("patch_impact_agent", run_tag, "patch_strategy_result.json", patch_result)

    patch_execution_stage = result.get("patch_execution_stage") if isinstance(result.get("patch_execution_stage"), dict) else None
    if patch_execution_stage:
        _save_stage_wrapper("patch_execution_agent", run_tag, {"stage": "patch_execution", **patch_execution_stage})
        if "result" in patch_execution_stage:
            _save_named_json("patch_execution_agent", run_tag, "patch_execution_result.json", patch_execution_stage.get("result"))

    summary = {
        "run_tag": run_tag,
        "mode": mode,
        "pipeline": result.get("pipeline", []),
        "agent_message": result.get("agent_message"),
        "orchestrator_result_dir": str(RESULT_ROOT / orchestrator_agent_name / run_tag),
        "saved_agent_dirs": {
            "vuln_collector_agent": str(RESULT_ROOT / "vuln_collector_agent" / run_tag) if vuln_stage else None,
            "asset_matching_agent": str(RESULT_ROOT / "asset_matching_agent" / run_tag) if asset_stage else None,
            "risk_evaluation_agent": str(RESULT_ROOT / "risk_evaluation_agent" / run_tag) if risk_stage else None,
            "patch_impact_agent": str(RESULT_ROOT / "patch_impact_agent" / run_tag)
            if patch_stage is not None
            else None,
            "patch_execution_agent": str(RESULT_ROOT / "patch_execution_agent" / run_tag) if patch_execution_stage else None,
        },
    }
    _save_named_json(orchestrator_agent_name, run_tag, "summary.json", summary)
    return summary


def main() -> int:
    _load_env()
    _refresh_runtime_defaults()
    RESULT_ROOT.mkdir(parents=True, exist_ok=True)

    print("\n오케스트라 런타임 실행기")
    _print_usage_guide()
    runtime_arn = DEFAULT_ORCHESTRATOR_ARN.strip()
    if runtime_arn:
        print(f"오케스트라 런타임 ARN (.env): {runtime_arn}")
    else:
        runtime_arn = _prompt_with_default("오케스트라 런타임 ARN")
    runtime_arn = _require_runtime_arn(runtime_arn, "오케스트라 런타임 ARN", ORCHESTRATOR_RUNTIME_ARN_ENV_KEYS)
    payload, label = _build_payload_interactively()

    print("\n실행 요청")
    print(json.dumps(_redact_secrets(payload), ensure_ascii=False, indent=2))
    if not _prompt_yes_no(f"{label} 모드로 실행할까요?", default=True):
        print("취소했습니다.")
        return 0

    result, invoke_meta = _invoke_orchestrator(runtime_arn, payload["region"], payload)
    summary = _save_result_bundle(result, payload, invoke_meta)

    print("\n실행 완료")
    print(json.dumps(invoke_meta, ensure_ascii=False, indent=2))
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
