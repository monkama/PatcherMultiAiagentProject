from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

try:
    from patch_runtime.bedrock_json import call_bedrock_text
except ModuleNotFoundError:  # local execution from this folder
    from bedrock_json import call_bedrock_text  # type: ignore


AGENT_ROOT = Path(__file__).resolve().parent
RUNTIME_ROOT = Path(os.environ.get("MULTIAI_RUNTIME_ROOT") or AGENT_ROOT.parent.parent)
OUTPUT_RESULT_DIR = RUNTIME_ROOT / "OutputResult"
RESULT_DIR = OUTPUT_RESULT_DIR / "PatchImAgent"
STAGE1_RESULT_DIR = RESULT_DIR / "stage1_prejudge"
STAGE2_RESULT_DIR = RESULT_DIR / "stage2_followup"
STAGE3_RESULT_DIR = RESULT_DIR / "stage3_final"

DEFAULT_RISK_PATH = OUTPUT_RESULT_DIR / "RiskevalAgent" / "risk_evaluation_result.json"
DEFAULT_INFRA_PATH = OUTPUT_RESULT_DIR / "AssetAgent" / "infra_context.json"
DEFAULT_OPERATIONAL_PATH = OUTPUT_RESULT_DIR / "VulAgent" / "operational_impact_payloads.json"
PATCH_IMPACT_RESULT_PATH = STAGE1_RESULT_DIR / "patch_impact_prejudge_result.json"
ADDITIONAL_ASSET_REQUEST_PATH = STAGE2_RESULT_DIR / "additional_asset_request.json"
DEFAULT_FOLLOWUP_CONTEXT_PATH = OUTPUT_RESULT_DIR / "SwarmAgent" / "additional_asset_response.json"
FINAL_RESULT_PATH = STAGE3_RESULT_DIR / "patch_impact_final_result.json"

DEFAULT_BEDROCK_MODEL = (
    os.environ.get("PATCH_IMPACT_BEDROCK_MODEL")
    or os.environ.get("BEDROCK_MODEL_ID")
    or "global.anthropic.claude-haiku-4-5-20251001-v1:0"
)
MAX_RETRIES = 3
RETRY_DELAY = 5

JSONDict = dict[str, Any]
QUESTION_TYPES = {
    "dependency_check",
    "shaded_copy_check",
    "config_compatibility",
    "restart_requirement",
    "rollback_check",
    "deployment_binding",
    "patch_followup",
}
IMPACT_VALUES = {"none", "low", "medium", "high", "unknown"}
DECISION_VALUES = {"patch_now", "patch_planned", "mitigate_then_patch", "manual_review", "no_action"}
SEVERITY_VALUES = {"critical", "high", "medium", "low", "unknown"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve_path(path_value: Optional[Union[str, Path]], base_dir: Path = AGENT_ROOT) -> Optional[Path]:
    if path_value is None:
        return None
    path = Path(path_value)
    if not path.is_absolute():
        path = base_dir / path
    return path


def _load_json_file(path_value: Optional[Union[str, Path]], default: Any) -> Any:
    path = _resolve_path(path_value)
    if path is None or not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _save_json_file(path_value: Union[str, Path], data: Any) -> Path:
    path = _resolve_path(path_value)
    if path is None:
        raise ValueError("저장 경로가 필요합니다.")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _safe_string(value: Any, default: str = "") -> str:
    text = str(value or "").strip()
    return text or default


def _safe_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _safe_text_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _normalize_impact(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in IMPACT_VALUES else "unknown"


def _normalize_decision(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    legacy_map = {
        "auto_update": "patch_now",
        "wait_for_maintenance": "patch_planned",
        "manual_approval": "manual_review",
    }
    normalized = legacy_map.get(normalized, normalized)
    return normalized if normalized in DECISION_VALUES else "manual_review"


def _normalize_security_severity(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in SEVERITY_VALUES else "unknown"


def _normalize_question_type(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in QUESTION_TYPES else "patch_followup"


def _normalize_missing_key(value: Any) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _extract_json_blob(text: str) -> Any:
    raw = str(text or "").strip()
    if not raw:
        return None
    fence_match = re.search(r"```(?:json)?\s*(.*?)```", raw, re.DOTALL)
    if fence_match:
        raw = fence_match.group(1).strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    for idx, ch in enumerate(raw):
        if ch not in "[{":
            continue
        try:
            parsed, _ = decoder.raw_decode(raw[idx:])
            return parsed
        except json.JSONDecodeError:
            continue
    return None


def _normalize_json_like(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str) and value.strip():
        parsed = _extract_json_blob(value)
        if parsed is not None:
            return parsed
    return value


def _call_llm_json(instructions: str, payload: dict[str, Any], bedrock_model: Any = None) -> Any:
    prompt = json.dumps(payload, ensure_ascii=False, indent=2)
    text = call_bedrock_text(
        instructions=instructions,
        prompt=prompt,
        model_name=str(bedrock_model or "").strip() or DEFAULT_BEDROCK_MODEL,
        max_retries=MAX_RETRIES,
        retry_delay=RETRY_DELAY,
    )
    parsed = _extract_json_blob(text)
    if parsed is None:
        raise ValueError("LLM 응답에서 JSON을 추출하지 못했습니다.")
    return parsed


def _coerce_risk_records(risk_result: Any) -> list[dict[str, Any]]:
    if isinstance(risk_result, list):
        return [item for item in risk_result if isinstance(item, dict)]
    if isinstance(risk_result, dict):
        for key in ("records", "results", "items"):
            value = risk_result.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        if risk_result.get("cve_id"):
            return [risk_result]
    return []


def _index_assets(infra_context: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(infra_context, dict):
        return {}
    assets = infra_context.get("assets")
    if not isinstance(assets, list):
        return {}
    indexed: dict[str, dict[str, Any]] = {}
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        asset_id = _safe_string(asset.get("asset_id"))
        if asset_id:
            indexed[asset_id] = asset
    return indexed


def _index_operational_records(operational_payload: Any) -> dict[str, dict[str, Any]]:
    records: list[Any]
    if isinstance(operational_payload, dict):
        records = _safe_list(operational_payload.get("records"))
    elif isinstance(operational_payload, list):
        records = operational_payload
    else:
        records = []
    indexed: dict[str, dict[str, Any]] = {}
    for record in records:
        if isinstance(record, dict):
            cve_id = _safe_string(record.get("cve_id"))
            if cve_id:
                indexed[cve_id] = record
    return indexed


def _compact_asset(asset: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(asset, dict):
        return {}
    keep = (
        "asset_id",
        "hostname",
        "tier",
        "availability_zone",
        "private_ip",
        "public_ip",
        "metadata",
        "network_context",
        "security_context",
        "os_info",
        "installed_software",
        "running_processes",
        "services",
        "config_findings",
        "file_findings",
        "container_images",
        "deployment_context",
        "rollback_context",
    )
    return {key: asset[key] for key in keep if asset.get(key) not in (None, "", [], {})}


def _compact_operational(record: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(record, dict):
        return {}
    keep = (
        "cve_id",
        "title",
        "primary_remediation",
        "operational_risk",
        "dependency_checks",
        "fallback_mitigations",
        "rollout_guidance",
        "validation_checks",
    )
    compact = {key: record[key] for key in keep if record.get(key) not in (None, "", [], {})}
    # 구 구조 호환
    if "primary_remediation" not in compact and record.get("mitigation_summaries"):
        compact["primary_remediation"] = "; ".join(_safe_text_list(record.get("mitigation_summaries")))
    if "operational_risk" not in compact and record.get("operational_impacts"):
        compact["operational_risk"] = "; ".join(_safe_text_list(record.get("operational_impacts")))
    if "rollout_guidance" not in compact and record.get("rollout_considerations"):
        compact["rollout_guidance"] = "; ".join(_safe_text_list(record.get("rollout_considerations")))
    if "validation_checks" not in compact and record.get("validation_focus"):
        compact["validation_checks"] = _safe_text_list(record.get("validation_focus"))
    return compact


def _compact_risk_reference(impacted: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(impacted, dict):
        return {}
    keep = (
        "instance_id",
        "asset_id",
        "base_cvss",
        "calculated_risk",
        "exposure_level",
        "mitigations_found",
        "risk_adjustment_reason",
    )
    return {key: impacted[key] for key in keep if impacted.get(key) not in (None, "", [], {})}


def _build_stage1_dataset(
    risk_result: Any,
    infra_context: Any,
    operational_payload: Any,
) -> dict[str, Any]:
    risk_records = _coerce_risk_records(risk_result)
    assets_by_id = _index_assets(infra_context)
    operational_by_cve = _index_operational_records(operational_payload)

    stage_records: list[dict[str, Any]] = []
    for risk_record in risk_records:
        cve_id = _safe_string(risk_record.get("cve_id"))
        op_record = operational_by_cve.get(cve_id, {})
        impacted_assets = _safe_list(risk_record.get("impacted_assets"))
        stage_assets: list[dict[str, Any]] = []
        for impacted in impacted_assets:
            if not isinstance(impacted, dict):
                continue
            instance_id = _safe_string(impacted.get("instance_id") or impacted.get("asset_id"))
            asset = assets_by_id.get(instance_id, {})
            stage_assets.append({
                "instance_id": instance_id,
                "risk_reference": _compact_risk_reference(impacted),
                "infra_context": _compact_asset(asset),
            })
        stage_records.append({
            "cve_id": cve_id,
            "title": _safe_string(op_record.get("title") or risk_record.get("title")),
            "operational_context": _compact_operational(op_record),
            "risk_record": {
                "cve_id": cve_id,
                "title": _safe_string(risk_record.get("title")),
                "impacted_assets": stage_assets,
            },
        })

    return {
        "input_contract": {
            "purpose": "자산별 패치 관련 1차 정보 정리와 follow-up 질문 생성",
            "output_schema": "compressed_prejudge.v1",
        },
        "risk_records": stage_records,
    }


def _stage1_system_prompt() -> str:
    return """당신은 patch_impact_prejudge AI입니다.

목표:
위험도 평가 결과, infra context, 운영 영향 payload를 종합해 자산별 패치 관련 1차 정보 정리를 생성합니다.
이 단계는 최종 판단이 아닙니다.
현재 입력만으로 확인 가능한 사실을 구조화하고, 부족한 정보가 있으면 자산 수집 에이전트에게 확인할 follow-up 질문을 생성합니다.

당신은 보안 위험도 자체를 재평가하지 않습니다.
CVSS, severity, exploitability score를 새로 만들지 않습니다.
당신은 이 단계에서 patch_impact나 최종 조치 방향을 결정하지 않습니다.
당신의 역할은 패치 운영 영향 판단에 필요한 사실, 운영 문맥, 부족한 정보, 확인 질문을 구조화하는 것입니다.

반드시 JSON object 하나만 반환하세요.
마크다운, 설명문, 코드블록을 출력하지 마세요.

출력 스키마:
{
  "records": [
    {
      "cve_id": "",
      "title": "",
      "patch_summary": "",
      "asset_prejudgements": [
        {
          "asset_id": "",
          "asset_context": "",
          "security_severity": "critical | high | medium | low | unknown",
          "known_facts": [],
          "missing_information": [],
          "followup_questions": [
            {
              "id": "",
              "type": "dependency_check | shaded_copy_check | config_compatibility | restart_requirement | rollback_check | deployment_binding | patch_followup",
              "question": "",
              "why_needed": "",
              "source_missing_information": ""
            }
          ]
        }
      ]
    }
  ]
}

필드 의미:
- cve_id: 판단 대상 CVE ID입니다.
- title: 취약점 제목입니다.
- patch_summary: 해당 CVE의 정식 조치, 운영 위험, 임시 완화책, 검증 포인트를 한 문단으로 압축한 값입니다.
- asset_prejudgements: 자산별 1차 정보 정리 목록입니다. 이 단계에서는 최종 조치 결론을 내리지 않습니다.
- asset_id: 판단 대상 자산 ID입니다.
- asset_context: 자산의 핵심 운영 상태를 한 문장으로 압축한 값입니다.
- security_severity: 위험도 평가 단계가 전달한 자산별 보안 위험도 참고값입니다.
- known_facts: 현재 입력만으로 확인 가능한 핵심 사실 목록입니다. 최종 조치 결론이 아니라 판단에 필요한 근거 요약입니다.
- missing_information: 신뢰도 있는 최종 판단을 위해 부족한 사실 정보입니다.
- followup_questions: 자산 수집 에이전트가 관측 가능한 사실로 답해야 하는 질문 목록입니다.
- followup_questions[].source_missing_information: 이 질문이 주로 해결하려는 missing_information 원문입니다.

입력 사용 규칙:
1. operational_impact_payloads.records[]는 CVE별 패치 문맥입니다.
   - patch_summary는 primary_remediation, operational_risk, fallback_mitigations, rollout_guidance, validation_checks를 조합해 만듭니다.
   - primary_remediation이 명확하면 반드시 반영합니다.
   - fallback_mitigations는 정식 패치를 바로 적용하지 못할 때의 임시 완화책으로만 취급합니다.
   - dependency_checks는 missing_information과 followup_questions를 만들 때 우선 참고합니다.
2. risk_evaluation_result[]는 자산별 보안 위험도 참고값입니다.
   - asset_prejudgements는 impacted_assets[]를 기준으로 만듭니다.
   - impacted_assets[].instance_id를 asset_id로 사용합니다.
   - calculated_risk, exposure_level, risk_adjustment_reason, mitigations_found를 참고합니다.
   - remediation은 risk 판단 결과의 조치 문장일 뿐이므로 patch 조치 판단 근거로 사용하지 마세요.
3. infra_context.assets[]는 실제 자산 문맥입니다.
   - impacted_assets[].instance_id와 infra_context.assets[].asset_id를 매칭합니다.
   - asset_context는 tier, metadata, network_context, security_context, installed_software를 조합해 작성합니다.
   - public/private 노출, listening port, root 실행 여부, 설치 제품/버전/경로는 중요하게 반영합니다.
4. 이 단계의 역할은 최종 조치 방향을 정하는 것이 아니라, 현재까지 확인된 사실과 부족한 정보를 구조화하는 것입니다.
   - patch_now, patch_planned, manual_review 같은 최종 decision enum을 만들지 마세요.
   - 패치 영향도 high/low 같은 결론도 만들지 마세요.
   - 대신 known_facts, missing_information, followup_questions를 더 정확하게 작성하세요.

known_facts 작성 기준:
- 현재 입력에서 직접 확인되는 사실만 적습니다.
- 보안 위험도 참고값, 자산 노출 상태, 설치 흔적, 런타임 흔적, 설정 흔적, 운영상 중요한 구조를 요약합니다.
- 결론형 문장보다 관측 사실 위주로 씁니다.
- 보통 2~5개 정도로 제한합니다.

followup_questions 작성 규칙:
- 질문은 관측 가능한 사실만 물어야 합니다.
- 질문은 yes, no, unknown 또는 구체 값으로 답할 수 있어야 합니다.
- 운영 판단, 위험도 판단, 승인 여부를 묻지 마세요.
- missing_information에 항목이 하나라도 있으면, followup_questions도 원칙적으로 비어 있으면 안 됩니다.
- followup_questions는 missing_information을 메우기 위한 질문이어야 합니다.
- 서로 다른 missing_information 항목은 가능한 한 각각 별도 질문으로 분리하세요.
- 원칙적으로 중요한 missing_information 항목 하나당 대응하는 followup question 하나가 있어야 합니다.
- 입력만으로 충분히 판단 가능하면 followup_questions는 빈 배열로 둡니다.

followup_questions[].type 선택 기준:
- dependency_check: 취약 구성요소가 실제 사용 또는 연결되어 있는지 확인해야 할 때 사용합니다.
- shaded_copy_check: 숨겨진 내장 또는 재패키징 복사본 존재 여부를 확인해야 할 때 사용합니다.
- config_compatibility: 현재 설정과 패치/완화 조치의 충돌 가능성을 확인해야 할 때 사용합니다.
- restart_requirement: 조치 적용에 실행 상태 변경이 필요한지 확인해야 할 때 사용합니다.
- rollback_check: 조치 실패 시 원복 가능성을 확인해야 할 때 사용합니다.
- deployment_binding: 자산이 운영 트래픽 또는 배포 경로와 연결되어 있는지 확인해야 할 때 사용합니다.
- patch_followup: 위 유형에 명확히 속하지 않는 패치 관련 사실 확인에 사용합니다.

압축 규칙:
- 유지보수 시간, OS 재부팅 여부, 예상 다운타임, 데이터 손실 위험, 설정 덮어쓰기 위험, 롤백 복잡도, 순차 배포 필요 여부 같은 세부 운영 항목은 별도 키로 출력하지 않습니다.
- 해당 정보가 판단에 중요하면 known_facts, missing_information, followup_questions 중 하나에 자연어로 압축해 포함합니다.

금지:
- 보안 severity나 CVSS를 재평가하지 마세요.
- 입력에 없는 유지보수 시간, 다운타임, 배포 구조를 만들지 마세요.
- unknown을 no 또는 safe처럼 취급하지 마세요.
- fixed version 또는 primary_remediation이 입력에 있는데 unknown으로 바꾸지 마세요.
- 일반론만 쓰지 말고 입력 근거에 기반해 작성하세요.
"""


def _default_patch_summary(operational_context: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("primary_remediation", "operational_risk", "rollout_guidance"):
        text = _safe_string(operational_context.get(key))
        if text:
            parts.append(text)
    fallback = operational_context.get("fallback_mitigations")
    if isinstance(fallback, list) and fallback:
        mitigations = []
        for item in fallback[:2]:
            if isinstance(item, dict):
                text = _safe_string(item.get("mitigation"))
                if text:
                    mitigations.append(text)
            elif isinstance(item, str) and item.strip():
                mitigations.append(item.strip())
        if mitigations:
            parts.append("임시 완화책: " + "; ".join(mitigations))
    validations = _safe_text_list(operational_context.get("validation_checks"))
    if validations:
        parts.append("검증: " + "; ".join(validations[:3]))
    return " ".join(parts).strip()


def _default_asset_context(asset: dict[str, Any], risk_ref: dict[str, Any]) -> str:
    chunks: list[str] = []
    tier = _safe_string(asset.get("tier"))
    metadata = asset.get("metadata") if isinstance(asset.get("metadata"), dict) else {}
    network = asset.get("network_context") if isinstance(asset.get("network_context"), dict) else {}
    security = asset.get("security_context") if isinstance(asset.get("security_context"), dict) else {}
    software = asset.get("installed_software") if isinstance(asset.get("installed_software"), list) else []
    if tier:
        chunks.append(f"tier={tier}")
    for key in ("environment", "network_exposure", "business_criticality"):
        if _safe_string(metadata.get(key)):
            chunks.append(f"{key}={metadata.get(key)}")
    if _safe_string(network.get("public_ip")):
        chunks.append(f"public_ip={network.get('public_ip')}")
    if network.get("listening_ports") not in (None, "", [], {}):
        chunks.append(f"listening_ports={network.get('listening_ports')}")
    if security.get("running_as_root") not in (None, "", [], {}):
        chunks.append(f"running_as_root={security.get('running_as_root')}")
    if software:
        compact_sw = []
        for item in software[:3]:
            if isinstance(item, dict):
                compact_sw.append(" ".join(filter(None, [_safe_string(item.get("product")), _safe_string(item.get("version")), _safe_string(item.get("source_path"))])))
        if compact_sw:
            chunks.append("software=" + "; ".join(compact_sw))
    risk_reason = _safe_string(risk_ref.get("risk_adjustment_reason"))
    if risk_reason:
        chunks.append("risk_evidence=" + risk_reason[:500])
    return ", ".join(chunks) if chunks else "자산 문맥 정보가 충분하지 않습니다."


def _normalize_followup_questions(value: Any) -> list[dict[str, str]]:
    items = value if isinstance(value, list) else []
    out: list[dict[str, str]] = []
    for idx, item in enumerate(items, start=1):
        if isinstance(item, str):
            question = item.strip()
            if not question:
                continue
            out.append({
                "id": f"q{idx}",
                "type": "patch_followup",
                "question": question,
                "why_needed": "최종 패치 운영 영향 판단에 필요한 추가 사실입니다.",
                "source_missing_information": "",
            })
        elif isinstance(item, dict):
            question = _safe_string(item.get("question"))
            if not question:
                continue
            out.append({
                "id": _safe_string(item.get("id"), f"q{idx}"),
                "type": _normalize_question_type(item.get("type")),
                "question": question,
                "why_needed": _safe_string(item.get("why_needed")),
                "source_missing_information": _safe_string(item.get("source_missing_information")),
            })
    return out


def _stage1_followup_repair_system_prompt() -> str:
    return """당신은 patch_impact_prejudge AI의 follow-up question repair 담당입니다.

목표:
이미 생성된 stage1 정보 정리 결과에서 missing_information은 있는데 followup_questions가 부족한 자산에 대해,
기존 질문을 최대한 유지하면서 빠진 follow-up 질문만 보충합니다.

규칙:
- 출력은 반드시 JSON object 하나만 반환합니다.
- 운영 판단, 위험도 판단, 승인 판단을 하지 마세요.
- 질문은 관측 가능한 사실만 물어야 합니다.
- 질문은 yes, no, unknown 또는 구체 값으로 답할 수 있어야 합니다.
- 서로 다른 missing_information 항목은 가능한 한 각각 별도 질문으로 분리하세요.
- 기존 followup_questions가 적절하면 재사용하고, 부족한 질문만 추가하세요.
- 중요한 missing_information 항목 하나당 대응하는 followup question 하나가 있어야 합니다.
- 각 followup question은 source_missing_information에 대응하는 missing_information 원문 하나를 반드시 적어야 합니다.

출력 스키마:
{
  "followup_questions": [
    {
      "id": "",
      "type": "dependency_check | shaded_copy_check | config_compatibility | restart_requirement | rollback_check | deployment_binding | patch_followup",
      "question": "",
      "why_needed": "",
      "source_missing_information": ""
    }
  ]
}
"""


def _dedupe_followup_questions(items: list[dict[str, str]]) -> list[dict[str, str]]:
    deduped: list[dict[str, str]] = []
    seen: set[str] = set()
    for idx, item in enumerate(items, start=1):
        question = _safe_string(item.get("question"))
        if not question:
            continue
        source_missing_information = _safe_string(item.get("source_missing_information"))
        normalized = _normalize_missing_key(source_missing_information) or _normalize_missing_key(question)
        if normalized and normalized in seen:
            continue
        if normalized:
            seen.add(normalized)
        deduped.append({
            "id": _safe_string(item.get("id"), f"q{idx}"),
            "type": _normalize_question_type(item.get("type")),
            "question": question,
            "why_needed": _safe_string(item.get("why_needed")),
            "source_missing_information": source_missing_information,
        })
    return deduped


def _missing_item_to_question_text(missing_item: str) -> str:
    text = _safe_string(missing_item).rstrip(".")
    if text.endswith("여부 확인 필요"):
        base = text[: -len("여부 확인 필요")].strip()
        if base:
            return f"{base} 여부를 확인할 수 있는가?"
    if text.endswith("확인 필요"):
        base = text[: -len("확인 필요")].strip()
        if base:
            return f"{base}를 확인할 수 있는가?"
    if text.endswith("필요"):
        return f"{text} 관련 사실을 확인할 수 있는가?"
    return f"다음 항목을 직접 확인할 수 있는가: {text}"


def _covered_missing_information(questions: list[dict[str, str]]) -> set[str]:
    covered: set[str] = set()
    for item in questions:
        source = _safe_string(item.get("source_missing_information"))
        normalized = _normalize_missing_key(source)
        if normalized:
            covered.add(normalized)
    return covered


def _assign_followup_sources(
    missing_information: list[str],
    questions: list[dict[str, str]],
) -> list[dict[str, str]]:
    missing_items = _safe_text_list(missing_information)
    canonical_by_key = {_normalize_missing_key(item): item for item in missing_items}
    used_keys: set[str] = set()
    assigned: list[dict[str, str]] = []

    for idx, item in enumerate(questions, start=1):
        source = _safe_string(item.get("source_missing_information") or item.get("why_needed"))
        source_key = _normalize_missing_key(source)
        canonical_source = canonical_by_key.get(source_key, "")
        if canonical_source:
            used_keys.add(source_key)
        assigned.append({
            "id": _safe_string(item.get("id"), f"q{idx}"),
            "type": _normalize_question_type(item.get("type")),
            "question": _safe_string(item.get("question")),
            "why_needed": _safe_string(item.get("why_needed")),
            "source_missing_information": canonical_source,
        })

    remaining_missing = [
        item for item in missing_items if _normalize_missing_key(item) not in used_keys
    ]
    missing_iter = iter(remaining_missing)
    for item in assigned:
        if _safe_string(item.get("source_missing_information")):
            continue
        try:
            item["source_missing_information"] = next(missing_iter)
        except StopIteration:
            break
    return _dedupe_followup_questions(assigned)


def _fallback_followup_questions(
    missing_information: list[str],
    existing_questions: list[dict[str, str]],
) -> list[dict[str, str]]:
    questions = _assign_followup_sources(missing_information, existing_questions)
    covered = _covered_missing_information(questions)
    next_index = len(questions) + 1
    for missing in missing_information:
        missing_key = _normalize_missing_key(missing)
        if missing_key in covered:
            continue
        questions.append({
            "id": f"q{next_index}",
            "type": "patch_followup",
            "question": _missing_item_to_question_text(missing),
            "why_needed": _safe_string(missing),
            "source_missing_information": _safe_string(missing),
        })
        covered.add(missing_key)
        next_index += 1
    return _assign_followup_sources(missing_information, questions)


def _repair_followup_questions_with_llm(
    *,
    cve_id: str,
    title: str,
    patch_summary: str,
    asset_id: str,
    asset_context: str,
    known_facts: list[str],
    missing_information: list[str],
    followup_questions: list[dict[str, str]],
    bedrock_model: Any = None,
) -> list[dict[str, str]]:
    payload = {
        "cve_id": cve_id,
        "title": title,
        "patch_summary": patch_summary,
        "asset_id": asset_id,
        "asset_context": asset_context,
        "known_facts": known_facts,
        "missing_information": missing_information,
        "existing_followup_questions": followup_questions,
    }
    try:
        raw = _call_llm_json(_stage1_followup_repair_system_prompt(), payload, bedrock_model=bedrock_model)
    except Exception:
        return []
    if not isinstance(raw, dict):
        return []
    return _normalize_followup_questions(raw.get("followup_questions"))


def _ensure_followup_questions(
    *,
    cve_id: str,
    title: str,
    patch_summary: str,
    asset_id: str,
    asset_context: str,
    known_facts: list[str],
    missing_information: list[str],
    followup_questions: list[dict[str, str]],
    bedrock_model: Any = None,
) -> list[dict[str, str]]:
    missing = _safe_text_list(missing_information)
    questions = _assign_followup_sources(missing, followup_questions)
    if not missing:
        return questions
    covered = _covered_missing_information(questions)
    if all(_normalize_missing_key(item) in covered for item in missing):
        return questions

    repaired = _repair_followup_questions_with_llm(
        cve_id=cve_id,
        title=title,
        patch_summary=patch_summary,
        asset_id=asset_id,
        asset_context=asset_context,
        known_facts=known_facts,
        missing_information=missing,
        followup_questions=questions,
        bedrock_model=bedrock_model,
    )
    if repaired:
        questions = _assign_followup_sources(missing, repaired)
    covered = _covered_missing_information(questions)
    if all(_normalize_missing_key(item) in covered for item in missing):
        return questions
    return _fallback_followup_questions(missing, questions)


def _coerce_stage1_records(raw: Any, stage_payload: dict[str, Any], bedrock_model: Any = None) -> list[dict[str, Any]]:
    raw_records = raw.get("records") if isinstance(raw, dict) else raw
    if not isinstance(raw_records, list):
        raw_records = []
    by_cve_payload = {r.get("cve_id"): r for r in _safe_list(stage_payload.get("risk_records")) if isinstance(r, dict)}

    normalized: list[dict[str, Any]] = []
    for raw_record in raw_records:
        if not isinstance(raw_record, dict):
            continue
        cve_id = _safe_string(raw_record.get("cve_id"))
        payload_record = by_cve_payload.get(cve_id, {})
        op_ctx = payload_record.get("operational_context") if isinstance(payload_record.get("operational_context"), dict) else {}
        patch_summary = _safe_string(raw_record.get("patch_summary")) or _default_patch_summary(op_ctx)
        title = _safe_string(raw_record.get("title") or payload_record.get("title"))

        risk_assets = []
        risk_record = payload_record.get("risk_record") if isinstance(payload_record.get("risk_record"), dict) else {}
        for item in _safe_list(risk_record.get("impacted_assets")):
            if isinstance(item, dict):
                risk_assets.append(item)
        llm_assets = raw_record.get("asset_prejudgements") if isinstance(raw_record.get("asset_prejudgements"), list) else []
        llm_by_asset = {_safe_string(x.get("asset_id")): x for x in llm_assets if isinstance(x, dict)}

        prejudgements: list[dict[str, Any]] = []
        for asset_item in risk_assets:
            asset_id = _safe_string(asset_item.get("instance_id"))
            llm_item = llm_by_asset.get(asset_id, {})
            infra_asset = asset_item.get("infra_context") if isinstance(asset_item.get("infra_context"), dict) else {}
            risk_ref = asset_item.get("risk_reference") if isinstance(asset_item.get("risk_reference"), dict) else {}
            known_facts = _safe_text_list(llm_item.get("known_facts"))
            missing = _safe_text_list(llm_item.get("missing_information"))
            asset_context = _safe_string(llm_item.get("asset_context")) or _default_asset_context(infra_asset, risk_ref)
            questions = _ensure_followup_questions(
                cve_id=cve_id,
                title=title,
                patch_summary=patch_summary,
                asset_id=asset_id,
                asset_context=asset_context,
                known_facts=known_facts,
                missing_information=missing,
                followup_questions=_normalize_followup_questions(llm_item.get("followup_questions")),
                bedrock_model=bedrock_model,
            )
            prejudgements.append({
                "asset_id": asset_id,
                "asset_context": asset_context,
                "security_severity": _normalize_security_severity(risk_ref.get("calculated_risk")),
                "known_facts": known_facts,
                "missing_information": missing,
                "followup_questions": questions,
            })

        # If LLM returned assets not in risk_assets, preserve them too.
        known = {item["asset_id"] for item in prejudgements}
        for llm_item in llm_assets:
            if not isinstance(llm_item, dict):
                continue
            asset_id = _safe_string(llm_item.get("asset_id"))
            if not asset_id or asset_id in known:
                continue
            known_facts = _safe_text_list(llm_item.get("known_facts"))
            missing = _safe_text_list(llm_item.get("missing_information"))
            asset_context = _safe_string(llm_item.get("asset_context"))
            prejudgements.append({
                "asset_id": asset_id,
                "asset_context": asset_context,
                "security_severity": _normalize_security_severity(llm_item.get("security_severity")),
                "known_facts": known_facts,
                "missing_information": missing,
                "followup_questions": _ensure_followup_questions(
                    cve_id=cve_id,
                    title=title,
                    patch_summary=patch_summary,
                    asset_id=asset_id,
                    asset_context=asset_context,
                    known_facts=known_facts,
                    missing_information=missing,
                    followup_questions=_normalize_followup_questions(llm_item.get("followup_questions")),
                    bedrock_model=bedrock_model,
                ),
            })

        normalized.append({
            "cve_id": cve_id,
            "title": title,
            "patch_summary": patch_summary,
            "asset_prejudgements": prejudgements,
        })
    return normalized


def _build_additional_requests(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    requests: list[dict[str, Any]] = []
    for record in records:
        for asset in _safe_list(record.get("asset_prejudgements")):
            if not isinstance(asset, dict):
                continue
            questions = _normalize_followup_questions(asset.get("followup_questions"))
            if not questions:
                continue
            requests.append({
                "cve_id": _safe_string(record.get("cve_id")),
                "title": _safe_string(record.get("title")),
                "asset_id": _safe_string(asset.get("asset_id")),
                "asset_context": _safe_string(asset.get("asset_context")),
                "security_severity": _normalize_security_severity(asset.get("security_severity")),
                "known_facts": _safe_text_list(asset.get("known_facts")),
                "patch_summary": _safe_string(record.get("patch_summary")),
                "missing_information": _safe_text_list(asset.get("missing_information")),
                "questions": questions,
            })
    return requests


def _additional_request_meta() -> dict[str, Any]:
    return {
        "payload_type": "patch_followup_request_bundle",
        "payload_purpose": "stage1 1차 패치 영향 판단에서 부족한 사실 정보를 자산 에이전트가 수집하기 위한 추가 질문 묶음입니다.",
        "answering_rules": [
            "운영 판단이나 승인 판단을 하지 않습니다.",
            "각 질문은 관측 가능한 사실로만 답합니다.",
            "모르면 unknown으로 답합니다.",
        ],
        "field_descriptions": {
            "request_count": "follow-up이 필요한 자산 질문 묶음 개수입니다.",
            "requests": "자산별 추가 질문 요청 목록입니다.",
            "requests[].cve_id": "질문 대상 CVE ID입니다.",
            "requests[].title": "취약점 제목입니다.",
            "requests[].asset_id": "질문 대상 자산 ID입니다.",
            "requests[].asset_context": "현재 자산의 핵심 운영 상태를 압축한 요약입니다.",
            "requests[].security_severity": "위험도 평가 단계가 전달한 자산별 보안 위험도 참고값입니다.",
            "requests[].known_facts": "현재 입력만으로 확인된 핵심 사실 목록입니다.",
            "requests[].patch_summary": "해당 CVE의 정식 조치, 운영 위험, 임시 완화책, 검증 포인트를 압축한 요약입니다.",
            "requests[].missing_information": "최종 판단을 위해 아직 부족한 정보 목록입니다.",
            "requests[].questions": "자산 에이전트가 답해야 하는 질문 목록입니다.",
            "requests[].questions[].id": "질문 식별자입니다.",
            "requests[].questions[].type": "질문 분류입니다.",
            "requests[].questions[].question": "실제로 확인해야 하는 질문 문장입니다.",
            "requests[].questions[].why_needed": "이 질문이 필요한 이유입니다.",
        },
    }


def run_patch_impact_evaluation(
    risk_result: Optional[Any] = None,
    infra_context: Optional[Any] = None,
    operational_payload: Optional[Any] = None,
    bedrock_model: Any = None,
    save_path: Optional[Union[str, Path]] = None,
    additional_request_path: Optional[Union[str, Path]] = None,
) -> JSONDict:
    risk_result = _normalize_json_like(risk_result if risk_result is not None else _load_json_file(DEFAULT_RISK_PATH, []))
    infra_context = _normalize_json_like(infra_context if infra_context is not None else _load_json_file(DEFAULT_INFRA_PATH, {}))
    operational_payload = _normalize_json_like(operational_payload if operational_payload is not None else _load_json_file(DEFAULT_OPERATIONAL_PATH, {}))
    stage_payload = _build_stage1_dataset(risk_result, infra_context, operational_payload)
    raw = _call_llm_json(_stage1_system_prompt(), stage_payload, bedrock_model=bedrock_model)
    records = _coerce_stage1_records(raw, stage_payload, bedrock_model=bedrock_model)
    result = {"records": records}

    save_target = save_path or PATCH_IMPACT_RESULT_PATH
    request_target = additional_request_path or ADDITIONAL_ASSET_REQUEST_PATH
    additional_request = {
        "_meta": _additional_request_meta(),
        "requests": _build_additional_requests(records),
    }
    additional_request["request_count"] = len(additional_request["requests"])
    _save_json_file(save_target, result)
    _save_json_file(request_target, additional_request)
    return {
        "result": result,
        "additional_request": additional_request,
    }


def run_patch_followup(requests: Any = None, infra_context: Any = None, region: str = "ap-northeast-2", infra_matching_runtime_arn: Any = None, save_path: Any = None) -> JSONDict:
    try:
        from patch_runtime.followup_actions import run_patch_followup_conversation
    except ModuleNotFoundError:
        from followup_actions import run_patch_followup_conversation  # type: ignore

    if requests is None:
        requests = _load_json_file(ADDITIONAL_ASSET_REQUEST_PATH, {"requests": []})
    if infra_context is None:
        infra_context = _load_json_file(DEFAULT_INFRA_PATH, {})
    return run_patch_followup_conversation(
        requests=requests,
        infra_context=infra_context,
        region=region,
        infra_matching_runtime_arn=infra_matching_runtime_arn,
        save_path=save_path,
    )


def run_patch_impact_finalization(
    prejudge_result: Optional[Any] = None,
    additional_asset_context: Optional[Any] = None,
    infra_context: Optional[Any] = None,
    region: str = "ap-northeast-2",
    infra_matching_runtime_arn: Any = None,
    allow_followup: bool = True,
    bedrock_model: Any = None,
    save_path: Optional[Union[str, Path]] = None,
    followup_save_path: Optional[Union[str, Path]] = None,
    return_debug: bool = False,
) -> JSONDict:
    try:
        from patch_runtime.finalize_patch import finalize_patch_strategy
    except ModuleNotFoundError:
        from finalize_patch import finalize_patch_strategy  # type: ignore

    if prejudge_result is None:
        prejudge_result = _load_json_file(PATCH_IMPACT_RESULT_PATH, {})
    if additional_asset_context is None:
        additional_asset_context = _load_json_file(DEFAULT_FOLLOWUP_CONTEXT_PATH, {})
    if infra_context is None:
        infra_context = _load_json_file(DEFAULT_INFRA_PATH, {})
    return finalize_patch_strategy(
        prejudge_result=prejudge_result if isinstance(prejudge_result, dict) else {},
        additional_asset_context=additional_asset_context if isinstance(additional_asset_context, dict) else {},
        infra_context=infra_context if isinstance(infra_context, dict) else {},
        region=region,
        infra_matching_runtime_arn=_safe_string(infra_matching_runtime_arn) or None,
        allow_followup=allow_followup,
        bedrock_model=bedrock_model,
        save_path=save_path or FINAL_RESULT_PATH,
        followup_save_path=followup_save_path or DEFAULT_FOLLOWUP_CONTEXT_PATH,
        return_debug=return_debug,
    )


def run_patch_impact_pipeline(
    risk_result: Optional[Any] = None,
    infra_context: Optional[Any] = None,
    operational_payload: Optional[Any] = None,
    additional_asset_context: Optional[Any] = None,
    region: str = "ap-northeast-2",
    infra_matching_runtime_arn: Any = None,
    allow_followup: bool = True,
    bedrock_model: Any = None,
    stage1_save_path: Optional[Union[str, Path]] = None,
    additional_request_path: Optional[Union[str, Path]] = None,
    followup_save_path: Optional[Union[str, Path]] = None,
    final_save_path: Optional[Union[str, Path]] = None,
) -> JSONDict:
    stage_output = run_patch_impact_evaluation(
        risk_result=risk_result,
        infra_context=infra_context,
        operational_payload=operational_payload,
        bedrock_model=bedrock_model,
        save_path=stage1_save_path or PATCH_IMPACT_RESULT_PATH,
        additional_request_path=additional_request_path or ADDITIONAL_ASSET_REQUEST_PATH,
    )
    final_debug = run_patch_impact_finalization(
        prejudge_result=stage_output.get("result"),
        additional_asset_context=additional_asset_context if isinstance(additional_asset_context, dict) else {},
        infra_context=infra_context,
        region=region,
        infra_matching_runtime_arn=infra_matching_runtime_arn,
        allow_followup=allow_followup,
        bedrock_model=bedrock_model,
        save_path=final_save_path or FINAL_RESULT_PATH,
        followup_save_path=followup_save_path or DEFAULT_FOLLOWUP_CONTEXT_PATH,
        return_debug=True,
    )
    return {
        "prejudge_result": stage_output.get("result", {}),
        "additional_request": stage_output.get("additional_request", {"requests": [], "request_count": 0}),
        "followup_stage": final_debug.get("followup_stage", {"responses": [], "response_count": 0}),
        "result": final_debug.get("result", {}),
    }


def load_latest_result(default: Any = None) -> Any:
    if FINAL_RESULT_PATH.exists():
        return _load_json_file(FINAL_RESULT_PATH, default)
    return _load_json_file(PATCH_IMPACT_RESULT_PATH, default)


def handle_agent_request(request: JSONDict) -> JSONDict:
    if not isinstance(request, dict):
        raise ValueError("payload는 JSON object 형태여야 합니다.")
    action = str(request.get("action") or "evaluate_patch_impact").strip().lower()

    if action in {"evaluate_patch_impact", "bootstrap", "init"}:
        stage_output = run_patch_impact_evaluation(
            risk_result=request.get("risk_result"),
            infra_context=request.get("infra_context"),
            operational_payload=request.get("operational_payload"),
            bedrock_model=request.get("bedrock_model_id") or request.get("patch_impact_bedrock_model"),
            save_path=request.get("save_path") or PATCH_IMPACT_RESULT_PATH,
            additional_request_path=request.get("additional_request_path") or ADDITIONAL_ASSET_REQUEST_PATH,
        )
        return {
            "action": action,
            "status": "ok",
            "result": stage_output.get("result", {}),
            "additional_request": stage_output.get("additional_request", {"requests": [], "request_count": 0}),
        }

    if action in {"run_patch_followup", "followup", "ask_asset_agent", "run_followup_conversation", "followup_conversation"}:
        result = run_patch_followup(
            requests=request.get("requests") or request.get("additional_request"),
            infra_context=request.get("infra_context"),
            region=_safe_string(request.get("region"), "ap-northeast-2"),
            infra_matching_runtime_arn=request.get("infra_matching_runtime_arn"),
            save_path=request.get("save_path"),
        )
        return {"action": action, "status": "ok", "result": result}

    if action in {"run_patch_impact_pipeline", "run_patch_impact", "pipeline"}:
        result = run_patch_impact_pipeline(
            risk_result=request.get("risk_result"),
            infra_context=request.get("infra_context"),
            operational_payload=request.get("operational_payload"),
            additional_asset_context=request.get("additional_asset_context"),
            region=_safe_string(request.get("region"), "ap-northeast-2"),
            infra_matching_runtime_arn=request.get("infra_matching_runtime_arn"),
            allow_followup=bool(request.get("allow_followup", True)),
            bedrock_model=request.get("bedrock_model_id") or request.get("patch_impact_bedrock_model"),
            stage1_save_path=request.get("stage1_save_path") or request.get("prejudge_save_path") or PATCH_IMPACT_RESULT_PATH,
            additional_request_path=request.get("additional_request_path") or ADDITIONAL_ASSET_REQUEST_PATH,
            followup_save_path=request.get("followup_save_path") or DEFAULT_FOLLOWUP_CONTEXT_PATH,
            final_save_path=request.get("save_path") or FINAL_RESULT_PATH,
        )
        return {"action": action, "status": "ok", **result}

    if action in {"finalize_patch_impact", "finalize"}:
        result = run_patch_impact_finalization(
            prejudge_result=request.get("prejudge_result"),
            additional_asset_context=request.get("additional_asset_context"),
            infra_context=request.get("infra_context"),
            region=_safe_string(request.get("region"), "ap-northeast-2"),
            infra_matching_runtime_arn=request.get("infra_matching_runtime_arn"),
            allow_followup=bool(request.get("allow_followup", True)),
            bedrock_model=request.get("bedrock_model_id") or request.get("patch_impact_bedrock_model"),
            save_path=request.get("save_path"),
            followup_save_path=request.get("followup_save_path"),
        )
        return {"action": action, "status": "ok", "result": result}

    if action in {"query_patch_impact", "query"}:
        cve_id = _safe_string(request.get("cve_id"))
        asset_id = _safe_string(request.get("asset_id") or request.get("instance_id"))
        latest = load_latest_result(default={"records": []})
        records = _safe_list(latest.get("records")) if isinstance(latest, dict) else []
        filtered: list[dict[str, Any]] = []
        for record in records:
            if cve_id and _safe_string(record.get("cve_id")) != cve_id:
                continue
            if asset_id:
                decisions_key = "asset_decisions" if isinstance(record.get("asset_decisions"), list) else "asset_prejudgements"
                matched = [item for item in _safe_list(record.get(decisions_key)) if isinstance(item, dict) and _safe_string(item.get("asset_id")) == asset_id]
                if not matched:
                    continue
                record = dict(record)
                record[decisions_key] = matched
            filtered.append(record)
        return {"action": action, "status": "ok", "result_count": len(filtered), "records": filtered}

    raise ValueError(f"지원하지 않는 action 입니다: {action}")


def invoke(payload: JSONDict) -> JSONDict:
    return handle_agent_request(payload)
