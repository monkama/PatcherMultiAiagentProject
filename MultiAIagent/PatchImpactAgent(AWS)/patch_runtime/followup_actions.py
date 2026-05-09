from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


AGENT_ROOT = Path(__file__).resolve().parent
RUNTIME_ROOT = Path(os.environ.get("MULTIAI_RUNTIME_ROOT") or AGENT_ROOT.parent.parent)
STAGE2_RESULT_DIR = RUNTIME_ROOT / "OutputResult" / "PatchImAgent" / "stage2_followup"
TRACE_DIR = STAGE2_RESULT_DIR / "deep_conversations"
DEFAULT_FOLLOWUP_REQUEST_PATH = STAGE2_RESULT_DIR / "additional_asset_request.json"
DEFAULT_FOLLOWUP_RESULT_PATH = RUNTIME_ROOT / "OutputResult" / "SwarmAgent" / "additional_asset_response.json"
DEFAULT_INFRA_CONTEXT_PATH = RUNTIME_ROOT / "OutputResult" / "AssetAgent" / "infra_context.json"

INFRA_MATCHING_RUNTIME_ARN_ENV_KEYS = (
    "INFRA_MATCHING_AGENTCORE_ARN",
    "ASSET_MATCHING_AGENTCORE_ARN",
    "ASSET_MATCHING_ARN",
)
QUESTION_TYPES = {
    "dependency_check",
    "shaded_copy_check",
    "config_compatibility",
    "restart_requirement",
    "rollback_check",
    "deployment_binding",
    "patch_followup",
}

_AGENTCORE_CLIENT: Any | None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def _normalize_question_type(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in QUESTION_TYPES else "patch_followup"


def _normalize_confidence(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in {"high", "medium", "low"} else "low"


def _normalize_evidence(value: Any) -> str:
    if isinstance(value, list):
        parts = [str(item).strip() for item in value if str(item).strip()]
        return " | ".join(parts)
    return _safe_string(value)


def _save_json(path: Path, data: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


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


def _agentcore_client(region: str) -> Any:
    global _AGENTCORE_CLIENT
    if _AGENTCORE_CLIENT is None:
        import boto3
        from botocore.config import Config

        _AGENTCORE_CLIENT = boto3.client(
            "bedrock-agentcore",
            region_name=region,
            config=Config(read_timeout=900, connect_timeout=10),
        )
    return _AGENTCORE_CLIENT


def _resolve_infra_matching_runtime_arn(runtime_arn: str | None = None) -> str:
    direct = _safe_string(runtime_arn)
    if direct:
        return direct
    for key in INFRA_MATCHING_RUNTIME_ARN_ENV_KEYS:
        value = _safe_string(os.environ.get(key))
        if value:
            return value
    raise ValueError(
        "infra matching runtime ARN이 필요합니다. "
        "infra_matching_runtime_arn 또는 INFRA_MATCHING_AGENTCORE_ARN 환경변수를 설정하세요."
    )


def _lookup_asset(infra_context: dict[str, Any], asset_id: str) -> dict[str, Any]:
    for asset in _safe_list(infra_context.get("assets")) if isinstance(infra_context, dict) else []:
        if isinstance(asset, dict) and _safe_string(asset.get("asset_id")) == asset_id:
            return asset
    return {}


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


def _normalize_question_items(request: dict[str, Any]) -> list[dict[str, str]]:
    questions = request.get("questions") or request.get("followup_questions") or []
    if not isinstance(questions, list):
        return []
    out: list[dict[str, str]] = []
    for idx, item in enumerate(questions, start=1):
        if isinstance(item, str):
            question = item.strip()
            if question:
                out.append({
                    "id": f"q{idx}",
                    "type": "patch_followup",
                    "question": question,
                    "why_needed": "",
                    "source_missing_information": "",
                })
        elif isinstance(item, dict):
            question = _safe_string(item.get("question"))
            if question:
                out.append({
                    "id": _safe_string(item.get("id"), f"q{idx}"),
                    "type": _normalize_question_type(item.get("type")),
                    "question": question,
                    "why_needed": _safe_string(item.get("why_needed")),
                    "source_missing_information": _safe_string(item.get("source_missing_information")),
                })
    return out


def _followup_prompt() -> str:
    return """당신은 patch impact 판단을 돕는 asset follow-up AI입니다.

목표:
patch_impact_prejudge AI가 생성한 follow-up 질문에 대해, 자산에서 관측 가능한 사실만 수집해 답변합니다.
당신은 위험도 평가, 패치 승인 판단, 운영 조치 판단을 하지 않습니다.
파일, 프로세스, 패키지, 설정, 네트워크, 배포 관련 사실만 확인합니다.

반드시 JSON object 하나만 반환하세요.
마크다운, 설명문, 코드블록을 출력하지 마세요.

출력 스키마:
{
  "cve_id": "",
  "asset_id": "",
  "answers": [
    {
      "id": "",
      "type": "dependency_check | shaded_copy_check | config_compatibility | restart_requirement | rollback_check | deployment_binding | patch_followup",
      "question": "",
      "answer": "yes | no | unknown | 구체 값",
      "evidence": "",
      "observed_values": {},
      "confidence": "high | medium | low"
    }
  ],
  "unknowns": []
}

필드 의미:
- cve_id: 질문 대상 CVE ID입니다.
- asset_id: 질문 대상 자산 ID입니다.
- answers: 질문별 답변 목록입니다.
- answers[].id: 입력 질문의 id를 그대로 유지합니다.
- answers[].type: 입력 질문의 type을 그대로 유지합니다.
- answers[].question: 입력 질문 문장을 그대로 유지합니다.
- answers[].answer: 질문에 대한 답입니다. yes, no, unknown 또는 구체 값을 사용합니다.
- answers[].evidence: 답변의 관측 근거입니다.
- answers[].observed_values: 구조화 가능한 관측값입니다. 없으면 빈 object를 사용합니다.
- answers[].confidence: 답변 신뢰도입니다.
- unknowns: 확인하지 못한 항목 목록입니다.

답변 규칙:
1. 입력된 각 질문마다 answers[] 항목을 하나씩 생성합니다.
2. 입력 질문의 id, type, question은 변경하지 않습니다.
3. 관측 근거가 있으면 answer는 yes, no 또는 구체 값으로 답합니다.
4. 근거가 없거나 확인할 수 없으면 answer는 unknown으로 답합니다.
5. unknown 항목은 unknowns에도 남깁니다.
6. unknown을 no처럼 취급하지 않습니다.
7. 판단하지 말고 관측 사실만 답합니다.
8. 입력에 없는 유지보수 시간, 다운타임, 배포 구조를 만들지 않습니다.
9. 근거 없는 추론으로 yes 또는 no를 만들지 않습니다.

질문 타입별 확인 범위:
- dependency_check: 취약 구성요소의 실제 사용·연결 여부를 확인합니다.
- shaded_copy_check: 숨겨진 내장·재패키징 복사본 여부를 확인합니다.
- config_compatibility: 설정 충돌 또는 기능 변화 가능성을 확인합니다.
- restart_requirement: 조치 적용 시 실행 상태 변경 필요 여부를 확인합니다.
- rollback_check: 실패 시 원복 가능 근거를 확인합니다.
- deployment_binding: 운영 트래픽 또는 배포 경로 연결 여부를 확인합니다.
- patch_followup: 기타 패치 관련 관측 사실을 확인합니다.

질문 타입은 확인 방향을 정하기 위한 분류일 뿐입니다.
타입 설명에 없는 구체 기술, 제품, 파일 형식, 인프라 구성요소를 임의로 추가하지 마세요.
실제 확인 대상은 입력 질문과 제공된 자산 정보에 근거해서만 정합니다.

confidence 기준:
- high: 직접 관측 근거가 명확합니다.
- medium: 일부 직접 근거와 일관된 간접 근거가 있습니다.
- low: 근거가 제한적이거나 확인 범위가 부족합니다.
- 근거가 없으면 answer는 unknown으로 두고 confidence는 low로 둡니다.

금지:
- 보안 위험도나 CVSS를 평가하지 마세요.
- 패치 영향도를 평가하지 마세요.
- 조치 방향을 정하지 마세요.
- 패치 승인 여부를 말하지 마세요.
- 질문에 없는 추가 결론을 만들지 마세요.
- 입력에 없는 사실을 보완해서 쓰지 마세요.
"""


def _request_payload_meta(bundle_meta: dict[str, Any] | None = None) -> dict[str, Any]:
    bundle_meta = bundle_meta if isinstance(bundle_meta, dict) else {}
    answering_rules = bundle_meta.get("answering_rules")
    if not isinstance(answering_rules, list) or not answering_rules:
        answering_rules = [
            "운영 판단이나 승인 판단을 하지 않습니다.",
            "각 질문은 관측 가능한 사실로만 답합니다.",
            "모르면 unknown으로 답합니다.",
        ]
    return {
        "payload_type": "patch_followup_request",
        "payload_purpose": "stage1 1차 패치 영향 판단에서 부족한 사실 정보를 자산 에이전트가 수집하기 위한 개별 질문 요청입니다.",
        "answering_rules": answering_rules,
        "field_descriptions": {
            "cve_id": "질문 대상 CVE ID입니다.",
            "title": "취약점 제목입니다.",
            "asset_id": "질문 대상 자산 ID입니다.",
            "asset_context": "현재 자산의 핵심 운영 상태를 압축한 요약입니다.",
            "security_severity": "위험도 평가 단계가 전달한 자산별 보안 위험도 참고값입니다.",
            "known_facts": "현재 입력만으로 확인된 핵심 사실 목록입니다.",
            "patch_summary": "해당 CVE의 정식 조치, 운영 위험, 임시 완화책, 검증 포인트를 압축한 요약입니다.",
            "missing_information": "최종 판단을 위해 아직 부족한 정보 목록입니다.",
            "question": "현재 확인해야 하는 개별 질문 객체입니다.",
            "question.id": "질문 식별자입니다.",
            "question.type": "질문 분류입니다.",
            "question.question": "실제로 확인해야 하는 질문 문장입니다.",
            "question.why_needed": "이 질문이 필요한 이유입니다.",
            "question.source_missing_information": "이 질문이 주로 해결하려는 missing_information 원문입니다.",
            "asset_info": "현재 자산에서 수집된 관측 가능한 정보 요약입니다. 설정, 프로세스, 패키지, 네트워크 정보를 포함할 수 있습니다.",
        },
    }


def _invoke_infra_matching_query(
    *,
    request: dict[str, Any],
    question: dict[str, str],
    asset_info: dict[str, Any],
    request_meta: dict[str, Any],
    region: str,
    runtime_arn: str,
) -> dict[str, Any]:
    instance_id = _safe_string(request.get("instance_id") or request.get("asset_id"))
    payload = {
        "mode": "query",
        "region": region,
        "instance_id": instance_id,
        "asset_info": asset_info,
        "question": question.get("question"),
    }
    response = _agentcore_client(region).invoke_agent_runtime(
        agentRuntimeArn=runtime_arn,
        runtimeSessionId=str(uuid.uuid4()),
        payload=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
    )
    raw_body = response.get("response") or response.get("body") or b""
    if hasattr(raw_body, "read"):
        raw_body = raw_body.read()
    if isinstance(raw_body, bytes):
        raw_text = raw_body.decode("utf-8", errors="replace")
    else:
        raw_text = str(raw_body or "")
    parsed = _extract_json_blob(raw_text)
    if not isinstance(parsed, dict):
        raise RuntimeError("asset query 응답에서 JSON object를 추출하지 못했습니다.")
    error_text = _safe_string(parsed.get("error"))
    if error_text:
        raise RuntimeError(f"asset query 실패: {error_text}")
    return parsed


def _coerce_single_answer(payload: dict[str, Any], request: dict[str, Any], question: dict[str, str]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise RuntimeError("asset query 응답이 JSON object 형태가 아닙니다.")
    answers = payload.get("answers") if isinstance(payload, dict) else None
    chosen: dict[str, Any] = {}
    if isinstance(answers, list) and answers:
        for item in answers:
            if isinstance(item, dict) and _safe_string(item.get("id")) == question["id"]:
                chosen = item
                break
        if not chosen and isinstance(answers[0], dict):
            chosen = answers[0]
    elif isinstance(payload, dict):
        chosen = payload

    if not chosen:
        raise RuntimeError("asset query 응답에서 answer payload를 찾지 못했습니다.")

    answer = _safe_string(chosen.get("answer"))
    if not answer:
        raise RuntimeError("asset query 응답에 answer 필드가 없습니다.")

    evidence = _normalize_evidence(chosen.get("evidence") or chosen.get("reason"))
    observed = chosen.get("observed_values") if isinstance(chosen.get("observed_values"), dict) else {}
    confidence = _normalize_confidence(chosen.get("confidence"))
    return {
        "id": question["id"],
        "type": _normalize_question_type(question.get("type")),
        "question": question["question"],
        "answer": answer,
        "evidence": evidence,
        "observed_values": observed,
        "confidence": confidence,
    }


def _run_single_followup_request(
    request: dict[str, Any],
    infra_context: dict[str, Any],
    request_meta: dict[str, Any],
    region: str,
    runtime_arn: str,
) -> dict[str, Any]:
    asset_id = _safe_string(request.get("asset_id") or request.get("instance_id"))
    asset = _lookup_asset(infra_context, asset_id)
    asset_info = _compact_asset(asset)
    questions = _normalize_question_items(request)
    answers: list[dict[str, Any]] = []
    unknowns: list[str] = []
    transcript: list[dict[str, Any]] = []

    for question in questions:
        parsed = _invoke_infra_matching_query(
            request=request,
            question=question,
            asset_info=asset_info,
            request_meta=request_meta,
            region=region,
            runtime_arn=runtime_arn,
        )
        answer = _coerce_single_answer(parsed, request, question)
        answers.append(answer)
        if answer["answer"].strip().lower() == "unknown":
            unknowns.append(_safe_string(question.get("source_missing_information")) or question["question"])
        if isinstance(parsed.get("unknowns"), list):
            unknowns.extend([str(item).strip() for item in parsed["unknowns"] if str(item).strip()])
        transcript.append({"question": question, "raw_response": parsed, "normalized_answer": answer})

    return {
        "cve_id": _safe_string(request.get("cve_id")),
        "asset_id": asset_id,
        "answers": answers,
        "unknowns": list(dict.fromkeys(unknowns)),
        "transcript": transcript,
    }


def _empty_followup_result() -> dict[str, Any]:
    return {
        "_meta": {
            "payload_type": "patch_followup_response_bundle",
            "payload_purpose": "asset 에이전트가 추가 질문에 대해 수집한 관측 사실 응답 묶음입니다.",
            "field_descriptions": {
                "responses": "자산별 follow-up 응답 목록입니다.",
                "responses[].cve_id": "응답 대상 CVE ID입니다.",
                "responses[].asset_id": "응답 대상 자산 ID입니다.",
                "responses[].answers": "질문별 응답 목록입니다.",
                "responses[].unknowns": "확인하지 못한 항목 목록입니다.",
                "responses[].transcript": "질문별 원시 응답과 정규화 응답 기록입니다.",
            },
        },
        "responses": [],
    }


def run_inline_followup_requests(
    *,
    requests: Any,
    infra_context: Any = None,
    region: str = "ap-northeast-2",
    infra_matching_runtime_arn: str | None = None,
    bundle_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    request_items = [item for item in _safe_list(requests) if isinstance(item, dict)]
    if not request_items:
        return _empty_followup_result()

    request_meta = _request_payload_meta(bundle_meta)
    infra_context = infra_context if isinstance(infra_context, dict) else {}
    runtime_arn = _resolve_infra_matching_runtime_arn(infra_matching_runtime_arn)
    responses = [
        _run_single_followup_request(request, infra_context, request_meta, region, runtime_arn)
        for request in request_items
    ]
    result = _empty_followup_result()
    result["responses"] = responses
    return result


def run_patch_followup_conversation(
    requests: Any = None,
    infra_context: Any = None,
    region: str = "ap-northeast-2",
    infra_matching_runtime_arn: str | None = None,
    save_path: Any = None,
) -> dict[str, Any]:
    bundle_meta: dict[str, Any] = {}
    if requests is None:
        loaded = _load_json(DEFAULT_FOLLOWUP_REQUEST_PATH, {"requests": []})
        if isinstance(loaded, dict):
            bundle_meta = loaded.get("_meta") if isinstance(loaded.get("_meta"), dict) else {}
            requests = loaded.get("requests", [])
        else:
            requests = []
    if isinstance(requests, dict):
        nested = requests.get("additional_request") if isinstance(requests.get("additional_request"), dict) else requests
        if isinstance(nested, dict):
            bundle_meta = nested.get("_meta") if isinstance(nested.get("_meta"), dict) else bundle_meta
            requests = nested.get("requests") or []
        else:
            requests = []
    requests = [item for item in _safe_list(requests) if isinstance(item, dict)]
    if not requests:
        result = _empty_followup_result()
        target = Path(save_path) if save_path else DEFAULT_FOLLOWUP_RESULT_PATH
        _save_json(target, result)
        TRACE_DIR.mkdir(parents=True, exist_ok=True)
        _save_json(TRACE_DIR / f"followup_trace_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json", result)
        return result

    if infra_context is None:
        infra_context = _load_json(DEFAULT_INFRA_CONTEXT_PATH, {})
    infra_context = infra_context if isinstance(infra_context, dict) else {}
    result = run_inline_followup_requests(
        requests=requests,
        infra_context=infra_context,
        region=region,
        infra_matching_runtime_arn=infra_matching_runtime_arn,
        bundle_meta=bundle_meta,
    )
    target = Path(save_path) if save_path else DEFAULT_FOLLOWUP_RESULT_PATH
    _save_json(target, result)
    TRACE_DIR.mkdir(parents=True, exist_ok=True)
    _save_json(TRACE_DIR / f"followup_trace_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json", result)
    return result


def invoke(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("payload는 JSON object 형태여야 합니다.")
    return run_patch_followup_conversation(
        requests=payload.get("requests") or payload.get("additional_request"),
        infra_context=payload.get("infra_context"),
        region=_safe_string(payload.get("region"), "ap-northeast-2"),
        infra_matching_runtime_arn=payload.get("infra_matching_runtime_arn"),
        save_path=payload.get("save_path"),
    )
