from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

try:
    from strands import Agent, tool
    from strands.models.bedrock import BedrockModel
except Exception:  # noqa: BLE001
    Agent = None
    BedrockModel = None

    def tool(func):  # type: ignore[no-redef]
        return func


DEFAULT_REGION = os.environ.get("AWS_REGION") or os.environ.get("DEFAULT_REGION") or "ap-northeast-2"
DEFAULT_MODEL_ID = (
    os.environ.get("PATCH_IMPACT_BEDROCK_MODEL_ID")
    or os.environ.get("BEDROCK_MODEL_ID")
    or "global.anthropic.claude-sonnet-4-5-20250929-v1:0"
)
DEFAULT_AGENTCORE_READ_TIMEOUT = int(os.environ.get("AGENTCORE_READ_TIMEOUT", "900"))
DEFAULT_AGENTCORE_CONNECT_TIMEOUT = int(os.environ.get("AGENTCORE_CONNECT_TIMEOUT", "10"))

MAX_FOLLOWUPS_PER_RECORD = int(os.environ.get("PATCH_MAX_FOLLOWUPS_PER_RECORD", "8"))
MAX_RECORD_WALL_TIME_SECONDS = int(os.environ.get("PATCH_MAX_RECORD_WALL_TIME_SECONDS", "240"))
MAX_TOTAL_WALL_TIME_SECONDS = int(os.environ.get("PATCH_MAX_TOTAL_WALL_TIME_SECONDS", "900"))

ALLOWED_RISK_LEVELS = {"critical", "high", "medium", "low"}
ALLOWED_CHANGE_SURFACES = {
    "os_package",
    "app_dependency",
    "binary_artifact",
    "container_image",
    "configuration",
    "source_code",
    "unknown",
}
ALLOWED_DEPLOYMENT_REQUIREMENTS = {"none", "service_restart", "redeploy", "host_reboot", "unknown"}
ALLOWED_PATCH_FEASIBLE = {"yes", "no", "unknown"}
ALLOWED_MITIGATION_AVAILABLE = {"yes", "no", "unknown"}
ALLOWED_SELECTED_ACTIONS = {
    "apply_patch_now",
    "apply_patch_planned",
    "apply_mitigation_now",
    "human_review",
}
ALLOWED_CONFIDENCE = {"high", "medium", "low"}

_CLIENT_CACHE: dict[tuple[str, str], Any] = {}
_RUNTIME_STATE: dict[str, Any] = {
    "started_at": 0.0,
    "record_started_at": {},
    "record_query_count": {},
    "responses": [],
    "asset_index": {},
    "allow_followup": True,
    "runtime_arn": "",
    "region": DEFAULT_REGION,
}


class PatchStrategyRecord(BaseModel):
    asset_id: str
    cve_id: str
    risk_level: str
    affected_component: str
    current_version: str
    target_version: str
    change_surface: str
    deployment_requirement: str
    patch_feasible: str
    mitigation_available: str
    mitigation_summary: str
    selected_action: str
    decision: str
    confidence: str
    reason_summary: str
    validation_checks: list[str] = Field(default_factory=list)
    remaining_unknowns: list[str] = Field(default_factory=list)


class PatchStrategyResult(BaseModel):
    records: list[PatchStrategyRecord] = Field(default_factory=list)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_json(path_like: str | Path | None, data: Any) -> None:
    if not path_like:
        return
    path = Path(path_like)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _agentcore_client(region: str) -> Any:
    import boto3
    from botocore.config import Config

    key = ("bedrock-agentcore", region)
    client = _CLIENT_CACHE.get(key)
    if client is None:
        client = boto3.client(
            "bedrock-agentcore",
            region_name=region,
            config=Config(
                read_timeout=DEFAULT_AGENTCORE_READ_TIMEOUT,
                connect_timeout=DEFAULT_AGENTCORE_CONNECT_TIMEOUT,
            ),
        )
        _CLIENT_CACHE[key] = client
    return client


def _build_bedrock_model() -> Any:
    if BedrockModel is None:
        raise RuntimeError("strands BedrockModel 을 불러올 수 없습니다.")

    region = (
        os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
        or DEFAULT_REGION
    )
    return BedrockModel(
        region_name=region,
        model_id=DEFAULT_MODEL_ID,
        temperature=0,
    )


def _invoke_agentcore_runtime(runtime_arn: str, request_payload: dict[str, Any], region: str) -> dict[str, Any]:
    from botocore.exceptions import ClientError

    try:
        response = _agentcore_client(region).invoke_agent_runtime(
            agentRuntimeArn=runtime_arn,
            payload=json.dumps(request_payload).encode("utf-8"),
        )
    except ClientError as exc:
        raise RuntimeError(f"AgentCore 호출 실패 ({runtime_arn.split('/')[-1]}): {exc}") from exc

    raw = response["response"].read()
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, str):
            parsed = json.loads(parsed)
        if isinstance(parsed, dict):
            return parsed
        return {"result": parsed}
    except json.JSONDecodeError:
        return {"raw": raw.decode("utf-8", errors="replace")}


def _safe_lower(value: Any) -> str:
    return str(value or "").strip().lower()


def _normalize_risk_level(value: Any) -> str:
    normalized = _safe_lower(value)
    return normalized if normalized in ALLOWED_RISK_LEVELS else "medium"


def _normalize_enum(value: Any, allowed: set[str], default: str) -> str:
    normalized = _safe_lower(value)
    return normalized if normalized in allowed else default


def _listify_str(items: Any) -> list[str]:
    if isinstance(items, list):
        return [str(item).strip() for item in items if str(item).strip()]
    if isinstance(items, str) and items.strip():
        return [items.strip()]
    return []


def _extract_json_text(raw_text: str) -> str:
    text = (raw_text or "").strip()
    if not text:
        return text
    if "```" in text:
        parts = text.split("```")
        for part in parts:
            cleaned = part.strip()
            if cleaned.startswith("json"):
                cleaned = cleaned[4:].strip()
            if cleaned.startswith("{") or cleaned.startswith("["):
                return cleaned
    match = re.search(r"(\{.*\}|\[.*\])", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text


def _extract_agent_text(result: Any) -> str:
    try:
        content = result.message.get("content", [])
        chunks: list[str] = []
        for block in content:
            if isinstance(block, dict):
                text = block.get("text")
                if isinstance(text, str) and text.strip():
                    chunks.append(text.strip())
        if chunks:
            return "\n".join(chunks).strip()
    except Exception:  # noqa: BLE001
        pass
    return str(result).strip()


def _extract_risk_records(risk_result: Any) -> list[dict[str, Any]]:
    if isinstance(risk_result, list):
        return [item for item in risk_result if isinstance(item, dict)]
    if isinstance(risk_result, dict):
        if isinstance(risk_result.get("risk_report"), list):
            return [item for item in risk_result["risk_report"] if isinstance(item, dict)]
        if isinstance(risk_result.get("result"), list):
            return [item for item in risk_result["result"] if isinstance(item, dict)]
        if isinstance(risk_result.get("records"), list):
            return [item for item in risk_result["records"] if isinstance(item, dict)]
    return []


def _extract_operational_records(operational_payload: Any) -> list[dict[str, Any]]:
    if isinstance(operational_payload, dict) and isinstance(operational_payload.get("records"), list):
        return [item for item in operational_payload["records"] if isinstance(item, dict)]
    if isinstance(operational_payload, list):
        return [item for item in operational_payload if isinstance(item, dict)]
    return []


def _compact_asset(asset: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(asset, dict):
        return {}
    return {
        "asset_id": asset.get("asset_id") or asset.get("instance_id"),
        "tier": asset.get("tier"),
        "metadata": asset.get("metadata"),
        "network_context": asset.get("network_context"),
        "security_context": asset.get("security_context"),
        "installed_software": asset.get("installed_software"),
        "services": asset.get("services"),
        "config_findings": asset.get("config_findings"),
        "file_findings": asset.get("file_findings"),
        "container_images": asset.get("container_images"),
        "deployment_context": asset.get("deployment_context"),
    }


def _compact_operational(record: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(record, dict):
        return {}
    return {
        "cve_id": record.get("cve_id"),
        "title": record.get("title"),
        "primary_remediation": record.get("primary_remediation"),
        "dependency_checks": record.get("dependency_checks"),
        "fallback_mitigations": record.get("fallback_mitigations"),
        "validation_checks": record.get("validation_checks"),
        "operational_risk": record.get("operational_risk"),
        "rollout_guidance": record.get("rollout_guidance"),
    }


def _summarize_prior_asset_findings(value: Any) -> list[dict[str, Any]]:
    responses: list[dict[str, Any]] = []
    if not isinstance(value, dict):
        return responses
    source = value.get("responses")
    if not isinstance(source, list):
        return responses
    for item in source:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("answers"), list):
            for answer in item["answers"]:
                if not isinstance(answer, dict):
                    continue
                responses.append(
                    {
                        "asset_id": item.get("asset_id") or item.get("instance_id"),
                        "cve_id": item.get("cve_id"),
                        "question": answer.get("question"),
                        "answer": answer.get("answer"),
                        "confidence": answer.get("confidence"),
                        "evidence": answer.get("evidence"),
                    }
                )
            continue
        responses.append(
            {
                "asset_id": item.get("asset_id"),
                "cve_id": item.get("cve_id"),
                "question": item.get("question"),
                "answer": item.get("answer"),
                "confidence": item.get("confidence"),
                "evidence": item.get("evidence"),
            }
        )
    return responses


def _build_strategy_context(payload: dict[str, Any]) -> dict[str, Any]:
    risk_result = payload.get("risk_result") or payload.get("risk_evaluation_result") or {}
    infra_context = payload.get("infra_context") or {}
    operational_payload = payload.get("operational_payload") or payload.get("operational_impact_payloads") or {}
    prior_asset_findings = payload.get("additional_asset_response") or payload.get("asset_fact_trace") or {}

    risk_records = _extract_risk_records(risk_result)
    operational_records = _extract_operational_records(operational_payload)
    assets = infra_context.get("assets") if isinstance(infra_context, dict) else []
    asset_index = {
        str(asset.get("asset_id") or asset.get("instance_id")): asset
        for asset in assets
        if isinstance(asset, dict) and (asset.get("asset_id") or asset.get("instance_id"))
    }
    operational_by_cve = {
        str(record.get("cve_id")): record
        for record in operational_records
        if isinstance(record, dict) and record.get("cve_id")
    }
    prior_findings = _summarize_prior_asset_findings(prior_asset_findings)

    records: list[dict[str, Any]] = []
    for risk_record in risk_records:
        cve_id = str(risk_record.get("cve_id") or "").strip()
        if not cve_id:
            continue
        title = str(risk_record.get("title") or "").strip()
        operational_record = operational_by_cve.get(cve_id, {})
        impacted_assets = risk_record.get("impacted_assets") if isinstance(risk_record.get("impacted_assets"), list) else []
        for impacted in impacted_assets:
            if not isinstance(impacted, dict):
                continue
            asset_id = str(impacted.get("instance_id") or impacted.get("asset_id") or "").strip()
            if not asset_id:
                continue
            related_findings = [
                finding
                for finding in prior_findings
                if str(finding.get("asset_id") or "").strip() == asset_id
                and str(finding.get("cve_id") or "").strip() == cve_id
            ]
            records.append(
                {
                    "asset_id": asset_id,
                    "cve_id": cve_id,
                    "title": title,
                    "risk_level": _normalize_risk_level(impacted.get("calculated_risk")),
                    "risk_reference": {
                        "base_cvss": impacted.get("base_cvss"),
                        "calculated_risk": impacted.get("calculated_risk"),
                        "exposure_level": impacted.get("exposure_level"),
                        "risk_adjustment_reason": impacted.get("risk_adjustment_reason"),
                    },
                    "infra_asset": _compact_asset(asset_index.get(asset_id, {})),
                    "operational_context": _compact_operational(operational_record),
                    "prior_asset_findings": related_findings,
                }
            )

    return {
        "generated_at": _utc_now(),
        "planner_intent": "risk-driven patch strategy planner",
        "allow_followup": bool(payload.get("allow_followup", True)),
        "record_count": len(records),
        "records": records,
    }


def _record_key(asset_id: str, cve_id: str) -> str:
    return f"{asset_id}::{cve_id}"


def _followup_budget_blocked(asset_id: str, cve_id: str) -> str | None:
    if not _RUNTIME_STATE.get("allow_followup", True):
        return "followup_disabled"

    now = time.time()
    total_started_at = float(_RUNTIME_STATE.get("started_at") or now)
    if now - total_started_at > MAX_TOTAL_WALL_TIME_SECONDS:
        return "total_time_budget_exceeded"

    key = _record_key(asset_id, cve_id)
    record_started_at = _RUNTIME_STATE["record_started_at"].setdefault(key, now)
    if now - float(record_started_at) > MAX_RECORD_WALL_TIME_SECONDS:
        return "record_time_budget_exceeded"

    count = int(_RUNTIME_STATE["record_query_count"].get(key, 0))
    if count >= MAX_FOLLOWUPS_PER_RECORD:
        return "record_query_budget_exceeded"

    return None


@tool
def query_asset_fact(asset_id: str, cve_id: str, question: str) -> str:
    """자산 runtime에 직접 관측 가능한 기술 사실만 좁게 질문한다."""
    budget_block = _followup_budget_blocked(asset_id, cve_id)
    if budget_block:
        response = {
            "asset_id": asset_id,
            "cve_id": cve_id,
            "question": question,
            "status": "skipped",
            "error": budget_block,
            "answer": "",
            "confidence": "none",
            "evidence": [],
        }
        _RUNTIME_STATE["responses"].append(response)
        return json.dumps(response, ensure_ascii=False)

    asset_info = _RUNTIME_STATE.get("asset_index", {}).get(asset_id)
    runtime_arn = str(_RUNTIME_STATE.get("runtime_arn") or "").strip()
    region = str(_RUNTIME_STATE.get("region") or DEFAULT_REGION)
    if not asset_info or not runtime_arn:
        response = {
            "asset_id": asset_id,
            "cve_id": cve_id,
            "question": question,
            "status": "error",
            "error": "asset_info_or_runtime_arn_missing",
            "answer": "",
            "confidence": "none",
            "evidence": [],
        }
        _RUNTIME_STATE["responses"].append(response)
        return json.dumps(response, ensure_ascii=False)

    _RUNTIME_STATE["record_query_count"][_record_key(asset_id, cve_id)] = (
        int(_RUNTIME_STATE["record_query_count"].get(_record_key(asset_id, cve_id), 0)) + 1
    )

    try:
        body = _invoke_agentcore_runtime(
            runtime_arn,
            {
                "mode": "query",
                "region": region,
                "instance_id": asset_id,
                "asset_info": asset_info,
                "question": question,
            },
            region,
        )
        if "error" in body:
            response = {
                "asset_id": asset_id,
                "cve_id": cve_id,
                "question": question,
                "status": "error",
                "error": str(body["error"]),
                "answer": "",
                "confidence": "none",
                "evidence": [],
            }
        else:
            response = {
                "asset_id": asset_id,
                "cve_id": cve_id,
                "question": question,
                "status": "ok",
                "answer": str(body.get("answer") or "").strip(),
                "confidence": str(body.get("confidence") or "").strip(),
                "evidence": body.get("evidence") if isinstance(body.get("evidence"), list) else [],
            }
    except Exception as exc:  # noqa: BLE001
        response = {
            "asset_id": asset_id,
            "cve_id": cve_id,
            "question": question,
            "status": "error",
            "error": f"{type(exc).__name__}: {exc}",
            "answer": "",
            "confidence": "none",
            "evidence": [],
        }

    _RUNTIME_STATE["responses"].append(response)
    return json.dumps(response, ensure_ascii=False)


def _planner_system_prompt() -> str:
    return """
당신은 누구인가:
- 당신은 패치 전문가입니다. 즉, 주어진 cve 취약점을 대상 자산에 패치할 때, 단순히 기술적 패치 가능 여부뿐만 아니라, 운영 환경에서의 실제 적용 가능성, 완화책 존재 여부, 그리고 최종적으로 어떤 조치를 선택할지까지 판단하는 역할입니다.

Available evidence / 초기 사용 가능한 근거:
- risk evaluation context
- infrastructure context
- operational impact payload context
- prior asset fact findings if present

Your task / 해야 할 일:
- 단순히 패치 및 업그레이드만으로 안되는 상황이 있을 수도 있습니다. 코드간 의존성 및 운영 환경 제약으로 인해 패치 적용이 어려울 수 있습니다. 또한 임시 완화책이 존재할 수도 있습니다. 따라서 패치 적용 가능 여부뿐만 아니라 완화책 적용 가능 여부도 함께 판단하십시오.
- 일단 주어진 초기 사용 가능한 근거 json 파일들을 모두 읽으세요. 그리고 각 필드에 필요한 정보를 채우기에 근거가 충분한지 판단하십시오. 각 필드에 대한 설명은 Field definitions 을 참조하시면 됩니다.
- 각 필드의 정보를 작성하기에 기존 정보만으로 충분하지 않으면 query_asset_fact tool을 사용하여 직접 기술적 사실을 수집한 뒤, 그 응답으로 다시 해당 필드를 채우십시오.
- query_asset_fact tool을 사용할 때는 내부적으로 자산 수집 에이전트에 아래 payload가 전달된다는 점을 이해하고 질문하십시오:
  {
    "mode": "query",
    "region": "...",
    "instance_id": "...",
    "asset_info": {...},
    "question": "..."
  }


- asset_info는 이미 수집된 자산 컨텍스트로 자동 전달됩니다. 여기에는 보통 tier, metadata, network_context, security_context, installed_software, services, config_findings, file_findings, container_images, deployment_context 등이 포함될 수 있습니다.
- planner가 직접 작성해야 하는 값은 asset_id, cve_id, question 입니다.
- 따라서 question은 asset_info에 이미 들어 있는 일반 문맥을 반복 설명하기보다, 그 문맥을 바탕으로 확인이 필요한 직접 관측 사실에 집중해서 작성하십시오.
- 질문은 반드시 좁고 관측 가능 및 구체적이어야 하며, 자산 수집 에이전트가 실제 명령/설정/파일/프로세스 확인으로 답할 수 있어야 합니다.
- 여러 사실을 한 번에 묻지 말고, 답변이 모호해질 수 있으면 질문을 더 잘게 나누십시오.

판단할 때 주의 사항
- 특정 기능의 사용 여부나 취약 동작 가능성을 판단할 때, 설정 파일 안에 해당 기능이 직접적으로 명시되어 있는지만 기준으로 삼지 마십시오.
- 관련 소프트웨어의 버전, 실제 실행 경로, 외부 입력이 기능이 사용되는 처리 흐름까지 도달하는지 여부, 그리고 기능이 비활성화되었거나 제거되었다는 근거를 함께 종합해서 판단하십시오.
- 즉, 설정 파일에 특정 키워드가 없다는 이유만으로 곧바로 안전하거나 비활성이라고 결론내리지 말고, 기본 동작 상태와 입력 도달성, 비활성화 근거 유무를 함께 보십시오.
- 반대로 기능이 차단되었거나 제거되었거나 안전한 대체 동작으로 제한되었다는 명시적 근거가 있으면 그 사실을 우선 사용하십시오.
- selected_action 에서 주의 사항은 꼭 읽고 지켜주세요.

Output schema / 출력 스키마:
{
  "records": [
    {
      "asset_id": "string",
      "cve_id": "string",
      "risk_level": "critical | high | medium | low",
      "affected_component": "string",
      "current_version": "string | unknown",
      "target_version": "string | unknown",
      "change_surface": "os_package | app_dependency | binary_artifact | container_image | configuration | source_code | unknown",
      "deployment_requirement": "none | service_restart | redeploy | host_reboot | unknown",
      "patch_feasible": "yes | no | unknown",
      "mitigation_available": "yes | no | unknown",
      "mitigation_summary": "string",
      "selected_action": "apply_patch_now | apply_patch_planned | apply_mitigation_now | human_review",
      "decision": "string",
      "confidence": "high | medium | low",
      "reason_summary": "string",
      "validation_checks": [],
      "remaining_unknowns": []
    }
  ]
}
Field definitions / 필드 정의

- asset_id
  - 의미: 대상 자산의 고유 식별자입니다.
  - 작성 방식: 입력 자료에 있는 실제 자산 ID를 그대로 사용하십시오. 보통 EC2 인스턴스 ID입니다.
  - 예: "i-0123456789abcdef0"

- cve_id
  - 의미: 해당 취약점의 CVE 번호입니다.
  - 작성 방식: 입력 자료의 CVE ID를 그대로 사용하십시오.
  - 예: "CVE-2021-44228"

- risk_level
  - 의미: 앞단 risk evaluation이 판단한 위험도입니다.
  - 작성 방식: 입력 자료의 위험도를 사용하고, 임의로 새 수준을 만들지 마십시오.
  - 허용값: critical | high | medium | low

- affected_component
  - 의미: 실제로 패치 또는 완화 대상이 되는 구성요소입니다.
  - 작성 방식: 가능한 한 구체적인 컴포넌트 이름을 쓰십시오. 단순히 "application"처럼 뭉뚱그리지 마십시오.
  - 예: "nginx", "log4j-core", "openssl"

- current_version
  - 의미: 현재 확인된 취약 구성요소의 버전입니다.
  - 작성 방식: 입력 자료나 추가 확인 결과로 명확할 때만 실제 버전을 쓰고, 불명확하면 "unknown"을 사용하십시오.
  - 예: "1.20.0", "2.14.1", "unknown"

- target_version
  - 의미: 목표 패치 버전 또는 권장 버전입니다.
  - 작성 방식: 입력 자료의 remediation 근거가 명확할 때만 채우고, 불명확하면 "unknown"을 사용하십시오.
  - 예: "1.20.1", "2.17.1", "unknown"

- change_surface
  - 의미: 실제로 무엇을 바꾸는 패치인지 나타내는 분류입니다.
  - 작성 방식: 패치가 적용되는 기술 면을 가장 잘 설명하는 값을 하나 선택하십시오.
  - 허용값:
    - os_package: OS 패키지 업데이트
    - app_dependency: 애플리케이션 의존성 버전 변경
    - binary_artifact: jar, dll, binary 파일 자체 교체
    - container_image: 컨테이너 이미지 재빌드 또는 재배포
    - configuration: 설정 변경 중심 조치
    - source_code: 소스 코드 수정 필요
    - unknown: 확정 불가

- deployment_requirement
  - 의미: 조치를 반영하려면 어느 수준의 반영 작업이 필요한지 나타냅니다.
  - 작성 방식: 직접 근거가 있을 때만 구체값을 쓰고, 없으면 "unknown"을 사용하십시오.
  - 허용값:
    - none: 별도 재시작/재배포 불필요
    - service_restart: 서비스 재시작 필요
    - redeploy: 애플리케이션 또는 컨테이너 재배포 필요
    - host_reboot: 호스트 재부팅 필요
    - unknown: 확정 불가

- patch_feasible
  - 의미: 현재 증거 기준으로 정식 패치 또는 버전 업그레이드를 바로 진행할 수 있는지 여부입니다.
  - 작성 방식: 가능 여부가 충분히 뒷받침될 때만 yes/no를 쓰고, 애매하면 unknown을 사용하십시오.
  - 허용값:
    - yes: 지금 정식 패치 가능
    - no: 지금 바로 패치하기 어려움
    - unknown: 근거 부족

- mitigation_available
  - 의미: 정식 패치 전에 위험을 낮출 수 있는 임시 완화 조치가 존재하는지 여부입니다.
  - 작성 방식: 현실적으로 적용 가능한 완화책이 확인된 경우에만 yes를 쓰고, 없으면 no, 애매하면 unknown을 사용하십시오.
  - 허용값:
    - yes: 사용 가능한 완화책 있음
    - no: 실질적 완화책 없음
    - unknown: 확정 불가

- mitigation_summary
  - 의미: 가능한 완화 조치를 짧게 설명하는 필드입니다.
  - 작성 방식: mitigation_available이 yes인 경우 구체적 완화 내용을 한 줄로 쓰십시오. no 또는 unknown이면 빈 문자열 또는 매우 짧은 설명을 사용할 수 있습니다.
  - 예: "JndiLookup.class 제거 가능", "resolver 지시문 비활성화 가능"

- selected_action
  - 의미: 최종적으로 지금 선택한 조치입니다.
  - 작성 방식: 반드시 하나만 선택하십시오. patch와 mitigation을 동시에 선택하지 마십시오.
  - 허용값:
    - apply_patch_now: 지금 바로 정식 패치를 적용
    - apply_patch_planned: 정식 패치는 하되 계획된 시점에 적용
    - apply_mitigation_now: 지금은 임시 완화 조치를 우선 적용
    - human_review: 근거 부족 또는 불확실성 때문에 사람 검토 필요
  - 주의 사항:
    - patch_feasible이 unknown이면 apply_patch_now를 선택하지 말고 human_review 또는 apply_mitigation_now로 기울어라
    - 위험도와 패치 가능성은 별도로 판단하라
    - 위험도가 높아도 운영 영향 불확실성만으로 즉시 패치를 정당화하지 마라

- decision
  - 의미: selected_action을 사람이 바로 이해할 수 있는 실행 문장으로 풀어쓴 최종 결론
  - 지금까지 나온 근거들을 바탕으로 최종 결론을 내리는 필드입니다.
  - selected_action을 그대로 반복하지 말고, 어떤 자산에 대해 지금 무엇을 해야 하는지와 필요한 후속 방향을 함께 적으십시오.
  - 최대한 구체적으로 적어주시면 좋습니다.
    
- confidence
  - 의미: 전체 판단의 신뢰 수준입니다.
  - 작성 방식: 핵심 근거가 충분하면 high, 일부 불확실성이 있으면 medium, 중요한 정보가 비어 있으면 low를 선택하십시오.
  - 허용값:
    - high: 근거 충분
    - medium: 일부 불확실성 존재
    - low: 핵심 정보 부족

- reason_summary
  - 의미: 최종 판단 근거를 요약하는 설명입니다.
  - 작성 방식: 한국어로 작성하십시오. 이 필드는 단순히 "위험도가 높아 패치가 필요하다"를 반복하는 항목이 아니라, 왜 이 자산에 이 전략을 선택했는지 운영 관점에서 설명하는 항목입니다.
  - 반드시 아래 내용을 포함하십시오.
    - 변경 대상: change_surface 분류명만 적지 말고, 실제로 무엇을 무엇으로 바꾸는지 구체적으로 설명하십시오.
    - 실제 적용 방식: deployment_requirement 분류명만 적지 말고, 서비스 재시작, 애플리케이션 재배포, 재빌드 후 재배포, 설정 변경 후 재기동 등 실제 운영 절차를 한글 문장으로 풀어서 설명하십시오.
    - 적용 가능성 근거: 왜 지금 이 전략이 가능한지 또는 제약이 있는지 자산 근거를 포함하십시오. 커스텀 모듈 사용 여부, 표준 패키지 사용 여부, 라이브러리 위치 확인 여부, 실행 중 classpath 확인 여부, 별도 호환성 제약 확인 여부 등 실제 자산에서 확인된 사실을 기반으로 설명하십시오. 근거가 없는 내용은 추정하지 말고 `확인되지 않음`이라고 명시하십시오.
    - 임시 완화 대비 최종 조치 우선순위: 임시 완화가 가능한지 설명하고, 가능하더라도 왜 최종 패치가 우선인지 또는 왜 임시 완화가 우선인지 운영 관점에서 설명하십시오.
  - 금지:
    - 위험도만 반복하는 문장
    - os_package, app_dependency, service_restart, redeploy 같은 분류명만 단독으로 나열하는 문장
    - 무엇을 어디서 어디로 바꾸는지 없이 "즉시 패치 가능"이라고만 쓰는 문장
    - 근거 없는 호환성 추정

- validation_checks
  - 의미: 선택한 조치 후 확인해야 하는 검증 항목 목록입니다.
  - 작성 방식: 문자열 배열로 작성하고, 실제로 확인 가능한 점검 항목만 넣으십시오.
  - 예:
    - "nginx version 확인"
    - "애플리케이션 재기동 후 오류 로그 확인"
    - "취약 artifact 교체 여부 확인"

- remaining_unknowns
  - 의미: 끝까지 확정하지 못한 정보 목록입니다.
  - 작성 방식: 짧은 문자열 배열로 작성하십시오. 최종 판단에 영향을 준 미해결 항목을 남기십시오.
  - 예:
    - "hidden embedded copy path"
    - "framework compatibility"
    - "exact target version"

Selection fields / 선택형 필드 의미

- risk_level
  - critical: 매우 시급한 위험
  - high: 시급한 위험
  - medium: 계획 패치가 기본인 중간 수준 위험
  - low: 상대적으로 낮은 위험

- change_surface
  - os_package: OS 패키지 업데이트로 해결
  - app_dependency: 애플리케이션 의존성 버전 변경으로 해결
  - binary_artifact: 파일 자체 교체로 해결
  - container_image: 이미지 재빌드/재배포로 해결
  - configuration: 설정 변경 중심 조치
  - source_code: 코드 수정 필요
  - unknown: 아직 확정 불가

- deployment_requirement
  - none: 즉시 반영 가능
  - service_restart: 서비스만 재시작하면 됨
  - redeploy: 배포 단위 재배포 필요
  - host_reboot: 호스트 자체 재부팅 필요
  - unknown: 아직 모름

- patch_feasible
  - yes: 현재 근거로 정식 패치 가능
  - no: 현재 바로 패치 곤란
  - unknown: 아직 확정 못 함

- mitigation_available
  - yes: 임시 완화 가능
  - no: 임시 완화 어려움
  - unknown: 아직 확정 못 함

- selected_action
  - apply_patch_now: 지금 바로 패치
  - apply_patch_planned: 계획된 일정에 패치
  - apply_mitigation_now: 지금은 완화 먼저
  - human_review: 사람 검토 필요
  
- confidence
  - high: 강한 근거 기반
  - medium: 대체로 근거는 있으나 일부 공백 존재
  - low: 핵심 공백이 커서 판단 약함

Consistency rules / 일관성 규칙

- selected_action은 반드시 하나만 선택하십시오.
- decision은 selected_action과 논리적으로 일치해야 합니다.
- patch_feasible이 no인데 apply_patch_now를 선택하지 마십시오.
- mitigation_available이 no인데 apply_mitigation_now를 선택하지 마십시오.
- current_version, deployment_requirement, mitigation applicability 같은 핵심 필드가 약하면 confidence를 낮추거나 human_review를 선택하십시오.
- reason_summary와 selected_action은 서로 논리적으로 일치해야 합니다.


"""


def _planner_user_message(strategy_context: dict[str, Any]) -> str:
    return (
        "다음 context를 바탕으로 final patch strategy JSON을 생성하십시오.\n"
        "어떤 필드가 context만으로 충분히 뒷받침되지 않으면 query_asset_fact로 direct technical fact를 수집하십시오.\n\n"
        f"{json.dumps(strategy_context, ensure_ascii=False, indent=2)}"
    )


def _call_planner(strategy_context: dict[str, Any]) -> str:
    system_prompt = _planner_system_prompt()
    user_message = _planner_user_message(strategy_context)

    if Agent is not None:
        agent = Agent(
            model=_build_bedrock_model(),
            system_prompt=system_prompt,
            tools=[query_asset_fact],
        )
        result = agent(user_message)
        return _extract_agent_text(result)

    from patch_runtime.bedrock_json import call_bedrock_text

    return call_bedrock_text(
        instructions=system_prompt,
        prompt=user_message,
        model_name=DEFAULT_MODEL_ID,
    )


def _fallback_record(context_record: dict[str, Any], reason: str, unknowns: list[str] | None = None) -> dict[str, Any]:
    operational = context_record.get("operational_context") if isinstance(context_record.get("operational_context"), dict) else {}
    validation_checks = _listify_str(operational.get("validation_checks"))
    return {
        "asset_id": str(context_record.get("asset_id") or ""),
        "cve_id": str(context_record.get("cve_id") or ""),
        "risk_level": _normalize_risk_level(context_record.get("risk_level")),
        "affected_component": "unknown",
        "current_version": "unknown",
        "target_version": "unknown",
        "change_surface": "unknown",
        "deployment_requirement": "unknown",
        "patch_feasible": "unknown",
        "mitigation_available": "unknown",
        "mitigation_summary": "",
        "selected_action": "human_review",
        "decision": "현재 근거가 부족하므로 담당자가 패치 가능성과 완화 가능성을 검토해야 합니다.",
        "confidence": "low",
        "reason_summary": reason,
        "validation_checks": validation_checks,
        "remaining_unknowns": unknowns or ["insufficient_evidence"],
    }


def _normalize_record(record: dict[str, Any], context_record: dict[str, Any]) -> dict[str, Any]:
    selected_action = _normalize_enum(record.get("selected_action"), ALLOWED_SELECTED_ACTIONS, "human_review")
    normalized = {
        "asset_id": str(record.get("asset_id") or context_record.get("asset_id") or "").strip(),
        "cve_id": str(record.get("cve_id") or context_record.get("cve_id") or "").strip(),
        "risk_level": _normalize_risk_level(record.get("risk_level") or context_record.get("risk_level")),
        "affected_component": str(record.get("affected_component") or "unknown").strip() or "unknown",
        "current_version": str(record.get("current_version") or "unknown").strip() or "unknown",
        "target_version": str(record.get("target_version") or "unknown").strip() or "unknown",
        "change_surface": _normalize_enum(record.get("change_surface"), ALLOWED_CHANGE_SURFACES, "unknown"),
        "deployment_requirement": _normalize_enum(
            record.get("deployment_requirement"),
            ALLOWED_DEPLOYMENT_REQUIREMENTS,
            "unknown",
        ),
        "patch_feasible": _normalize_enum(record.get("patch_feasible"), ALLOWED_PATCH_FEASIBLE, "unknown"),
        "mitigation_available": _normalize_enum(
            record.get("mitigation_available"),
            ALLOWED_MITIGATION_AVAILABLE,
            "unknown",
        ),
        "mitigation_summary": str(record.get("mitigation_summary") or "").strip(),
        "selected_action": selected_action,
        "decision": str(record.get("decision") or "").strip(),
        "confidence": _normalize_enum(record.get("confidence"), ALLOWED_CONFIDENCE, "low"),
        "reason_summary": str(record.get("reason_summary") or "").strip()
        or "근거가 부족하여 담당자 검토가 필요합니다.",
        "validation_checks": _listify_str(record.get("validation_checks")),
        "remaining_unknowns": _listify_str(record.get("remaining_unknowns")),
    }
    return normalized


def _normalize_final_result(raw_result: Any, strategy_context: dict[str, Any]) -> dict[str, Any]:
    context_records = strategy_context.get("records") if isinstance(strategy_context.get("records"), list) else []
    parsed_records: list[dict[str, Any]] = []

    if isinstance(raw_result, dict) and isinstance(raw_result.get("records"), list):
        parsed_records = [item for item in raw_result["records"] if isinstance(item, dict)]

    context_index = {
        _record_key(str(record.get("asset_id") or ""), str(record.get("cve_id") or "")): record
        for record in context_records
        if isinstance(record, dict)
    }

    normalized_records: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    for parsed in parsed_records:
        key = _record_key(str(parsed.get("asset_id") or ""), str(parsed.get("cve_id") or ""))
        context_record = context_index.get(key)
        if not context_record:
            continue
        normalized = _normalize_record(parsed, context_record)
        normalized_records.append(normalized)
        seen_keys.add(key)

    for key, context_record in context_index.items():
        if key in seen_keys:
            continue
        normalized_records.append(
            _fallback_record(
                context_record,
                "필수 필드가 충분히 채워지지 않아 담당자 검토가 필요합니다.",
            )
        )

    return PatchStrategyResult(records=[PatchStrategyRecord(**record) for record in normalized_records]).model_dump()


def _run_patch_strategy(payload: dict[str, Any]) -> dict[str, Any]:
    strategy_context = _build_strategy_context(payload)
    assets = payload.get("infra_context", {}).get("assets") if isinstance(payload.get("infra_context"), dict) else []
    _RUNTIME_STATE["started_at"] = time.time()
    _RUNTIME_STATE["record_started_at"] = {}
    _RUNTIME_STATE["record_query_count"] = {}
    _RUNTIME_STATE["responses"] = []
    _RUNTIME_STATE["asset_index"] = {
        str(asset.get("asset_id") or asset.get("instance_id")): asset
        for asset in assets
        if isinstance(asset, dict) and (asset.get("asset_id") or asset.get("instance_id"))
    }
    _RUNTIME_STATE["allow_followup"] = bool(payload.get("allow_followup", True))
    _RUNTIME_STATE["runtime_arn"] = str(
        payload.get("infra_matching_runtime_arn")
        or payload.get("asset_matching_runtime_arn")
        or os.environ.get("INFRA_MATCHING_AGENTCORE_ARN")
        or os.environ.get("ASSET_MATCHING_AGENTCORE_ARN")
        or os.environ.get("ASSET_MATCHING_ARN")
        or ""
    ).strip()
    _RUNTIME_STATE["region"] = str(payload.get("region") or DEFAULT_REGION)

    raw_text = _call_planner(strategy_context)
    json_text = _extract_json_text(raw_text)
    try:
        parsed_result = json.loads(json_text)
    except Exception:  # noqa: BLE001
        parsed_result = {}

    final_result = _normalize_final_result(parsed_result, strategy_context)
    asset_fact_trace = {
        "generated_at": _utc_now(),
        "response_count": len(_RUNTIME_STATE["responses"]),
        "responses": _RUNTIME_STATE["responses"],
    }

    _write_json(payload.get("context_save_path"), strategy_context)
    _write_json(payload.get("asset_fact_trace_path"), asset_fact_trace)
    _write_json(payload.get("save_path"), final_result)

    return {
        "action": "run_patch_strategy",
        "generated_at": _utc_now(),
        "strategy_context": strategy_context,
        "asset_fact_trace": asset_fact_trace,
        "result": final_result,
    }


def invoke(payload: dict[str, Any] | None) -> dict[str, Any]:
    request = payload or {}
    action = str(request.get("action") or "run_patch_strategy").strip().lower()

    if action in {"build_patch_strategy_context", "build_context"}:
        context = _build_strategy_context(request)
        _write_json(request.get("context_save_path") or request.get("save_path"), context)
        return {
            "action": action,
            "generated_at": _utc_now(),
            "result": context,
        }

    if action in {"run_patch_strategy", "patch", "pipeline", "query_patch_strategy", "query"}:
        return _run_patch_strategy(request)

    raise ValueError(f"unsupported patch impact action: {action}")
