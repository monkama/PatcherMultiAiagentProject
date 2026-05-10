from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

try:
    from patch_runtime.bedrock_json import call_bedrock_text
except ModuleNotFoundError:
    from bedrock_json import call_bedrock_text  # type: ignore

try:
    from patch_runtime.tooling import tool
except ModuleNotFoundError:
    from tooling import tool  # type: ignore

try:
    from strands import Agent
except ImportError:
    Agent = None  # type: ignore[assignment]


AGENT_ROOT = Path(__file__).resolve().parent
RUNTIME_ROOT = Path(os.environ.get("MULTIAI_RUNTIME_ROOT") or AGENT_ROOT.parent.parent)
DEFAULT_SAVE_PATH = RUNTIME_ROOT / "OutputResult" / "PatchImAgent" / "stage3_final" / "patch_impact_final_result.json"
ITERATIVE_TRACE_DIR = RUNTIME_ROOT / "OutputResult" / "PatchImAgent" / "iterative_followup"
DEFAULT_BEDROCK_MODEL = (
    os.environ.get("PATCH_IMPACT_BEDROCK_MODEL")
    or os.environ.get("BEDROCK_MODEL_ID")
    or "global.anthropic.claude-haiku-4-5-20251001-v1:0"
)
MAX_RETRIES = 3
RETRY_DELAY = 5

IMPACT_VALUES = {"none", "low", "medium", "high", "unknown"}
DECISION_VALUES = {"patch_now", "patch_planned", "mitigate_then_patch", "manual_review", "no_action"}
SEVERITY_VALUES = {"critical", "high", "medium", "low", "unknown"}
QUESTION_TYPES = {
    "dependency_check",
    "shaded_copy_check",
    "config_compatibility",
    "restart_requirement",
    "rollback_check",
    "deployment_binding",
    "patch_followup",
}
CONFIDENCE_VALUES = {"high", "medium", "low"}
MAX_ITERATIVE_FOLLOWUPS_PER_ASSET = 8
MAX_ITERATIVE_AGENT_PASSES = 4
_ACTIVE_FOLLOWUP_TOOL_CONTEXT: dict[str, Any] = {}


class AssetDecisionModel(BaseModel):
    asset_id: str = ""
    asset_context: str = ""
    patch_impact: str = "unknown"
    decision: str = "manual_review"
    reason: str = ""
    action: str = ""
    temporary_mitigation: str = ""
    validation: str = ""
    remaining_unknowns: list[str] = Field(default_factory=list)


def _require_strands() -> None:
    if Agent is None:
        raise RuntimeError(
            "strands-agents is required for iterative patch finalization. "
            "Install dependencies and rebuild the runtime."
        )


@tool
def ask_asset_followup(
    question: str,
    question_type: str = "patch_followup",
    why_needed: str = "",
    source_missing_information: str = "",
) -> dict[str, Any]:
    context = _ACTIVE_FOLLOWUP_TOOL_CONTEXT
    normalized_question = _safe_string(question)
    if not context or not normalized_question:
        raise RuntimeError("follow-up tool context unavailable")

    cache_key = normalized_question.lower()
    cached = context["answers_by_question"].get(cache_key)
    if isinstance(cached, dict):
        return cached

    if context["followup_count"] >= context["max_followups"]:
        raise RuntimeError("추가 follow-up 질문 한도에 도달했습니다.")

    try:
        from patch_runtime.followup_actions import run_inline_followup_requests
    except ModuleNotFoundError:
        from followup_actions import run_inline_followup_requests  # type: ignore

    request = {
        "cve_id": context["cve_id"],
        "title": context["title"],
        "asset_id": context["asset_id"],
        "asset_context": context["asset_context"],
        "security_severity": context["security_severity"],
        "known_facts": context["known_facts"],
        "patch_summary": context["patch_summary"],
        "missing_information": context["missing_information"],
        "questions": [
            {
                "id": f"iter_q{context['followup_count'] + 1}",
                "type": _safe_string(question_type, "patch_followup"),
                "question": normalized_question,
                "why_needed": _safe_string(why_needed),
                "source_missing_information": _safe_string(source_missing_information),
            }
        ],
    }
    bundle = run_inline_followup_requests(
        requests=[request],
        infra_context=context.get("infra_context"),
        region=context.get("region", "ap-northeast-2"),
        infra_matching_runtime_arn=context.get("infra_matching_runtime_arn"),
        bundle_meta={"answering_rules": context.get("answering_rules") or []},
    )
    response = _safe_list(bundle.get("responses"))
    response_item = response[0] if response and isinstance(response[0], dict) else {}
    answers = _safe_list(response_item.get("answers"))
    if not answers or not isinstance(answers[0], dict):
        raise RuntimeError("follow-up 응답을 해석하지 못했습니다.")
    answer_item = answers[0]
    normalized_answer = {
        "id": _safe_string(answer_item.get("id")),
        "type": _safe_string(answer_item.get("type"), "patch_followup"),
        "question": _safe_string(answer_item.get("question"), normalized_question),
        "answer": _safe_string(answer_item.get("answer")),
        "evidence": _safe_string(answer_item.get("evidence")),
        "observed_values": answer_item.get("observed_values") if isinstance(answer_item.get("observed_values"), dict) else {},
        "confidence": _safe_string(answer_item.get("confidence"), "low"),
    }
    normalized_question_item = {
        "id": f"iter_q{context['followup_count'] + 1}",
        "type": _safe_string(question_type, "patch_followup"),
        "question": normalized_question,
        "why_needed": _safe_string(why_needed),
        "source_missing_information": _safe_string(source_missing_information),
    }
    normalized_response = {
        "cve_id": context["cve_id"],
        "asset_id": context["asset_id"],
        "answers": [normalized_answer],
        "unknowns": list(
            dict.fromkeys(
                _safe_text_list(response_item.get("unknowns"))
                or (
                    [
                        _safe_string(source_missing_information) or normalized_question
                    ]
                    if _safe_string(normalized_answer.get("answer")).lower() == "unknown"
                    else []
                )
            )
        ),
        "transcript": [
            {
                "question": normalized_question_item,
                "normalized_answer": normalized_answer,
            }
        ],
    }
    context["followup_count"] += 1
    context["responses"].append(normalized_response)
    context.setdefault("tool_events", []).append(normalized_response)
    tool_events_path = context.get("tool_events_path")
    if tool_events_path:
        _append_jsonl(Path(tool_events_path), normalized_response)
    context["answers_by_question"][cache_key] = normalized_answer
    return normalized_answer


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


def _save_json(path: Path, data: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _append_jsonl(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(data, ensure_ascii=False))
        handle.write("\n")


def _load_jsonl(path: Path | str | None) -> list[dict[str, Any]]:
    if not path:
        return []
    target = Path(path)
    if not target.exists():
        return []
    items: list[dict[str, Any]] = []
    try:
        for line in target.read_text(encoding="utf-8").splitlines():
            raw = line.strip()
            if not raw:
                continue
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                items.append(parsed)
    except (OSError, json.JSONDecodeError):
        return []
    return items


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


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
    return normalized if normalized in DECISION_VALUES else ""


def _normalize_security_severity(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in SEVERITY_VALUES else "unknown"


def _normalize_question_type(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in QUESTION_TYPES else "patch_followup"


def _normalize_confidence(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in CONFIDENCE_VALUES else "low"


def _normalize_question_text(value: Any) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _normalize_missing_key(value: Any) -> str:
    return _normalize_question_text(value)


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


def _call_llm_json(instructions: str, payload: dict[str, Any], bedrock_model: Any = None) -> Any:
    text = call_bedrock_text(
        instructions=instructions,
        prompt=json.dumps(payload, ensure_ascii=False, indent=2),
        model_name=str(bedrock_model or "").strip() or DEFAULT_BEDROCK_MODEL,
        max_retries=MAX_RETRIES,
        retry_delay=RETRY_DELAY,
    )
    parsed = _extract_json_blob(text)
    if parsed is None:
        raise ValueError("LLM 응답에서 JSON을 추출하지 못했습니다.")
    return parsed


def _decision_repair_system_prompt() -> str:
    return """당신은 patch_impact_finalizer의 decision repair AI입니다.

목표:
이미 생성된 최종 판단 초안에서 decision 필드가 비었거나 허용 enum이 아니면,
주어진 문맥만 보고 decision 값 하나만 복구합니다.

규칙:
- 출력은 반드시 JSON object 하나만 반환합니다.
- 아래 5개 enum 중 하나만 decision으로 반환합니다.
  - patch_now
  - patch_planned
  - mitigate_then_patch
  - manual_review
  - no_action
- reason, action, patch_impact를 새로 쓰지 마세요.
- 보안 위험도를 재평가하지 마세요.
- 정보가 부족하거나 애매하면 manual_review를 선택하세요.
- 임시 완화 적용 가능성이 확인되지 않았는데 mitigate_then_patch로 올리지 마세요.
- 패치 대상과 적용 경로가 충분히 확인되지 않았는데 patch_planned로 올리지 마세요.
- 영향 대상이 아니거나 이미 조치되어 추가 작업이 필요 없다고 명확하면 no_action을 선택하세요.

출력 스키마:
{
  "decision": "patch_now | patch_planned | mitigate_then_patch | manual_review | no_action"
}
"""


def _iterative_asset_system_prompt() -> str:
    return """당신은 patch_impact_iterative_finalizer AI입니다.

목표:
하나의 CVE와 하나의 자산에 대해 최종 patch_impact, decision, action을 결정합니다.

당신은 보안 위험도 자체를 재평가하지 않습니다.
당신은 stage1 정보 정리와 이미 수집된 follow-up 사실을 먼저 검토하고,
최종 결론에 꼭 필요한 정보가 부족할 때만 ask_asset_followup tool을 호출합니다.

중요:
- 질문은 관측 가능한 사실만 물어야 합니다.
- 같은 질문을 반복하지 마세요.
- missing_information의 서로 다른 항목은 가능한 한 각각 별도 질문으로 확인하세요.
- followup_question_candidates에 source_missing_information이 있으면, 해당 값을 유지한 채 ask_asset_followup에 함께 넘기세요.
- 먼저 현재 정보만으로 tentative decision을 내부적으로 정리하세요.
- 그 tentative decision이 추가 사실 하나로 바뀌거나 더 확정될 수 있을 때만 ask_asset_followup을 호출하세요.
- 한 번의 pass에서는 최대 1개의 follow-up만 호출하세요.
- 아직 follow-up을 전혀 시도하지 않은 상태에서 manual_review로 바로 종료하지 마세요. 다만 현재 정보만으로도 충분히 no_action 또는 명확한 결론이 가능하면 tool 호출 없이 종료할 수 있습니다.
- collected_followup_responses를 검토한 뒤 아직 확인되지 않은 followup_question_candidates가 남아 있으면, 추가 수집이 현재 tentative decision을 실질적으로 바꿀 수 있는 동안만 ask_asset_followup을 이어서 호출하세요.
- 반대로 인스턴스 접근 불가, 동일한 차단 요인 반복, 충분한 확인 불가 근거처럼 더 수집해도 의미가 없다고 판단되면, 남은 항목을 remaining_unknowns에 남기고 종료할 수 있습니다.
- 추가 질문이 더 이상 의미 없거나 충분한 결론을 낼 수 있으면 즉시 종료하고 최종 JSON을 반환하세요.
- remaining_unknowns에는 최종 판단 후에도 남아 있는 미해결 항목만 남기세요.

patch_impact는 운영 영향도입니다.
decision은 최종 조치 방향입니다.
둘은 같은 필드가 아니며, 서로 다른 결론이어도 됩니다.

출력은 반드시 JSON object 하나만 반환하세요.
마크다운, 설명문, 코드블록을 출력하지 마세요.

출력 스키마:
{
  "asset_id": "",
  "asset_context": "",
  "patch_impact": "none | low | medium | high | unknown",
  "decision": "patch_now | patch_planned | mitigate_then_patch | manual_review | no_action",
  "reason": "",
  "action": "",
  "temporary_mitigation": "",
  "validation": "",
  "remaining_unknowns": []
}

판단 규칙:
- patch_impact는 패치/완화 조치 적용이 운영에 주는 영향을 기준으로 판단합니다.
- decision은 운영 영향, 보안 위험도 참고값, 남은 불확실성, 임시 완화 가능성을 함께 보고 판단합니다.
- 정보가 부족하거나 판단이 애매하면 decision은 manual_review를 선택할 수 있습니다.
- 영향 대상이 아니거나 이미 조치되어 추가 작업이 필요 없다고 명확하면 no_action을 선택할 수 있습니다.
- mitigate_then_patch는 임시 완화 조치가 실제로 적용 가능하다는 근거가 있을 때만 선택하세요.
- patch_planned는 패치 대상과 적용 경로(재시작, 재배포, 빌드/배포 경로 등)가 어느 정도 확인됐을 때만 선택하세요.
- follow-up 응답이 주로 확인 불가, 접근 불가, 미확인이라면 섣불리 강한 결론을 내리지 말고 manual_review를 우선하세요.
- reason과 action은 근거 강도에 맞춰 작성하세요. 핵심 정보가 비어 있으면 단정형보다 조건형, 확인 요청형 문장을 우선하세요.

금지:
- 보안 severity나 CVSS를 재계산하지 마세요.
- 입력에 없는 유지보수 시간, 다운타임, 배포 구조를 만들어내지 마세요.
- follow-up 질문 목록을 최종 결과에 다시 적지 마세요.
- decision을 비우지 마세요.
"""


def _seed_followup_context(
    cve_id: str,
    asset_id: str,
    additional_asset_context: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    indexed = _response_index(additional_asset_context)
    response = indexed.get((cve_id, asset_id), {})
    if not isinstance(response, dict) or not response:
        return [], {}
    answers = [item for item in _safe_list(response.get("answers")) if isinstance(item, dict)]
    unknowns = _safe_text_list(response.get("unknowns"))
    transcript = [item for item in _safe_list(response.get("transcript")) if isinstance(item, dict)]
    if not answers and not unknowns and not transcript:
        return [], {}
    by_question: dict[str, dict[str, Any]] = {}
    for item in answers:
        question = _safe_string(item.get("question")).lower()
        if question:
            by_question[question] = item
    return [response], by_question


def _iterative_asset_message(
    *,
    cve_id: str,
    title: str,
    patch_summary: str,
    asset: dict[str, Any],
    collected_responses: list[dict[str, Any]],
) -> str:
    payload = {
        "cve_id": cve_id,
        "title": title,
        "patch_summary": patch_summary,
        "asset": {
            "asset_id": _safe_string(asset.get("asset_id")),
            "asset_context": _safe_string(asset.get("asset_context")),
            "security_severity": _normalize_security_severity(asset.get("security_severity")),
            "known_facts": _safe_text_list(asset.get("known_facts")),
            "missing_information": _safe_text_list(asset.get("missing_information")),
            "followup_question_candidates": [
                item for item in _safe_list(asset.get("followup_questions")) if isinstance(item, dict)
            ],
        },
        "collected_followup_responses": collected_responses,
        "instructions": {
            "tool_usage": "collected_followup_responses와 known_facts만으로 부족할 때만 ask_asset_followup을 호출하세요.",
            "question_granularity": "서로 다른 missing_information 항목은 가능한 한 각각 별도 질문으로 확인하세요.",
        },
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _response_index(additional_asset_context: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    if not isinstance(additional_asset_context, dict):
        return {}
    responses = additional_asset_context.get("responses") or additional_asset_context.get("results") or []
    indexed: dict[tuple[str, str], dict[str, Any]] = {}
    for response in _safe_list(responses):
        if not isinstance(response, dict):
            continue
        cve_id = _safe_string(response.get("cve_id"))
        asset_id = _safe_string(response.get("asset_id") or response.get("instance_id"))
        if cve_id and asset_id:
            indexed[(cve_id, asset_id)] = response
    return indexed


def _unknowns_from_response(response: dict[str, Any]) -> list[str]:
    unknowns = _safe_text_list(response.get("unknowns"))
    for ans in _safe_list(response.get("answers")):
        if not isinstance(ans, dict):
            continue
        if _safe_string(ans.get("answer")).lower() == "unknown":
            unknowns.append(_safe_string(ans.get("question"), "확인되지 않은 follow-up 항목"))
    for turn in _safe_list(response.get("transcript")):
        if not isinstance(turn, dict):
            continue
        normalized_answer = turn.get("normalized_answer") if isinstance(turn.get("normalized_answer"), dict) else {}
        if _safe_string(normalized_answer.get("answer")).lower() != "unknown":
            continue
        question = turn.get("question") if isinstance(turn.get("question"), dict) else {}
        unknowns.append(
            _safe_string(question.get("source_missing_information"))
            or _safe_string(question.get("question"), "확인되지 않은 follow-up 항목")
        )
    return list(dict.fromkeys([item for item in unknowns if item]))


def _evidence_from_response(response: dict[str, Any]) -> str:
    snippets: list[str] = []
    for ans in _safe_list(response.get("answers")):
        if not isinstance(ans, dict):
            continue
        answer = _safe_string(ans.get("answer"))
        evidence = _safe_string(ans.get("evidence"))
        question = _safe_string(ans.get("question"))
        if answer or evidence:
            snippets.append(" / ".join([part for part in (question, answer, evidence) if part]))
    return " | ".join(snippets[:4])


def _fallback_decision() -> str:
    return "manual_review"


def _dedupe_texts(*groups: list[str]) -> list[str]:
    merged: list[str] = []
    for group in groups:
        for item in group:
            text = _safe_string(item)
            if text and text not in merged:
                merged.append(text)
    return merged


def _aggregate_followup_unknowns(responses: list[dict[str, Any]]) -> list[str]:
    merged: list[str] = []
    for response in responses:
        if isinstance(response, dict):
            merged.extend(_unknowns_from_response(response))
    return _dedupe_texts(merged)


def _aggregate_followup_evidence(responses: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for response in responses:
        if not isinstance(response, dict):
            continue
        evidence = _evidence_from_response(response)
        if evidence and evidence not in parts:
            parts.append(evidence)
    return " | ".join(parts[:6])


def _asked_followup_questions(responses: list[dict[str, Any]]) -> set[str]:
    asked: set[str] = set()
    for response in responses:
        if not isinstance(response, dict):
            continue
        for answer in _safe_list(response.get("answers")):
            if not isinstance(answer, dict):
                continue
            normalized = _normalize_question_text(answer.get("question"))
            if normalized:
                asked.add(normalized)
        for turn in _safe_list(response.get("transcript")):
            if not isinstance(turn, dict):
                continue
            question = turn.get("question") if isinstance(turn.get("question"), dict) else {}
            normalized = _normalize_question_text(question.get("question"))
            if normalized:
                asked.add(normalized)
    return asked


def _processed_missing_information(responses: list[dict[str, Any]]) -> set[str]:
    processed: set[str] = set()
    for response in responses:
        if not isinstance(response, dict):
            continue
        for turn in _safe_list(response.get("transcript")):
            if not isinstance(turn, dict):
                continue
            question = turn.get("question") if isinstance(turn.get("question"), dict) else {}
            normalized = _normalize_missing_key(question.get("source_missing_information"))
            if normalized:
                processed.add(normalized)
    return processed


def _remaining_followup_candidates(asset: dict[str, Any], responses: list[dict[str, Any]]) -> list[dict[str, str]]:
    candidates = [item for item in _safe_list(asset.get("followup_questions")) if isinstance(item, dict)]
    if not candidates:
        return []
    asked = _asked_followup_questions(responses)
    processed_missing = _processed_missing_information(responses)
    remaining: list[dict[str, str]] = []
    for item in candidates:
        question = _safe_string(item.get("question"))
        if not question:
            continue
        source_missing_information = _safe_string(item.get("source_missing_information"))
        if source_missing_information and _normalize_missing_key(source_missing_information) in processed_missing:
            continue
        if not source_missing_information and _normalize_question_text(question) in asked:
            continue
        remaining.append({
            "id": _safe_string(item.get("id")),
            "type": _normalize_question_type(item.get("type")),
            "question": question,
            "why_needed": _safe_string(item.get("why_needed")),
            "source_missing_information": source_missing_information,
        })
    return remaining


def _followup_bundle_meta() -> dict[str, Any]:
    return {
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
    }


def _normalize_followup_response_item(response: Any) -> dict[str, Any]:
    if not isinstance(response, dict):
        return {}
    cve_id = _safe_string(response.get("cve_id"))
    asset_id = _safe_string(response.get("asset_id") or response.get("instance_id"))
    answers: list[dict[str, Any]] = []
    for item in _safe_list(response.get("answers")):
        if not isinstance(item, dict):
            continue
        answer = _safe_string(item.get("answer"))
        question = _safe_string(item.get("question"))
        if not answer and not question:
            continue
        answers.append(
            {
                "id": _safe_string(item.get("id")),
                "type": _normalize_question_type(item.get("type")),
                "question": question,
                "answer": answer,
                "evidence": _safe_string(item.get("evidence")),
                "observed_values": item.get("observed_values") if isinstance(item.get("observed_values"), dict) else {},
                "confidence": _normalize_confidence(item.get("confidence")),
            }
        )

    unknowns = _dedupe_texts(_safe_text_list(response.get("unknowns")))
    transcript: list[dict[str, Any]] = []
    for turn in _safe_list(response.get("transcript")):
        if not isinstance(turn, dict):
            continue
        normalized_answer = turn.get("normalized_answer") if isinstance(turn.get("normalized_answer"), dict) else {}
        question_item = turn.get("question") if isinstance(turn.get("question"), dict) else {}
        normalized_question = _safe_string(question_item.get("question") or normalized_answer.get("question"))
        if not normalized_question and not normalized_answer:
            continue
        transcript.append(
            {
                "question": {
                    "id": _safe_string(question_item.get("id")),
                    "type": _normalize_question_type(question_item.get("type") or normalized_answer.get("type")),
                    "question": normalized_question,
                    "why_needed": _safe_string(question_item.get("why_needed")),
                    "source_missing_information": _safe_string(question_item.get("source_missing_information")),
                },
                "normalized_answer": {
                    "id": _safe_string(normalized_answer.get("id")),
                    "type": _normalize_question_type(normalized_answer.get("type")),
                    "question": _safe_string(normalized_answer.get("question"), normalized_question),
                    "answer": _safe_string(normalized_answer.get("answer")),
                    "evidence": _safe_string(normalized_answer.get("evidence")),
                    "observed_values": normalized_answer.get("observed_values")
                    if isinstance(normalized_answer.get("observed_values"), dict)
                    else {},
                    "confidence": _normalize_confidence(normalized_answer.get("confidence")),
                },
            }
        )

    if not cve_id and not asset_id and not answers and not unknowns and not transcript:
        return {}
    return {
        "cve_id": cve_id,
        "asset_id": asset_id,
        "answers": answers,
        "unknowns": unknowns,
        "transcript": transcript,
    }


def _collect_context_followup_responses(context: dict[str, Any]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def _append(response: Any) -> None:
        item = _normalize_followup_response_item(response)
        if not item:
            return
        answers = item.get("answers") if isinstance(item.get("answers"), list) else []
        if answers:
            for answer in answers:
                if not isinstance(answer, dict):
                    continue
                key = (
                    _safe_string(item.get("cve_id")),
                    _safe_string(item.get("asset_id")),
                    _safe_string(answer.get("id") or answer.get("question")),
                )
                if key in seen:
                    return
                seen.add(key)
        else:
            key = (
                _safe_string(item.get("cve_id")),
                _safe_string(item.get("asset_id")),
                "|".join(_safe_text_list(item.get("unknowns"))),
            )
            if key in seen:
                return
            seen.add(key)
        normalized.append(item)

    for response in _safe_list(context.get("responses")):
        _append(response)
    for response in _safe_list(context.get("tool_events")):
        _append(response)
    for response in _load_jsonl(context.get("tool_events_path")):
        _append(response)

    if normalized:
        return normalized

    cve_id = _safe_string(context.get("cve_id"))
    asset_id = _safe_string(context.get("asset_id"))
    for answer in context.get("answers_by_question", {}).values():
        if not isinstance(answer, dict):
            continue
        _append(
            {
                "cve_id": cve_id,
                "asset_id": asset_id,
                "answers": [answer],
                "unknowns": [_safe_string(answer.get("question"))]
                if _safe_string(answer.get("answer")).lower() == "unknown"
                else [],
                "transcript": [
                    {
                        "question": {
                            "id": _safe_string(answer.get("id")),
                            "type": _normalize_question_type(answer.get("type")),
                            "question": _safe_string(answer.get("question")),
                            "why_needed": "",
                            "source_missing_information": "",
                        },
                        "normalized_answer": answer,
                    }
                ],
            }
        )
    return normalized


def _repair_decision_with_llm(
    *,
    cve_id: str,
    asset_id: str,
    security_severity: str,
    patch_impact: str,
    known_facts: list[str],
    remaining_unknowns: list[str],
    temporary_mitigation: str,
    reason: str,
    followup_evidence: str,
    bedrock_model: Any = None,
) -> str:
    payload = {
        "cve_id": cve_id,
        "asset_id": asset_id,
        "security_severity": security_severity,
        "patch_impact": patch_impact,
        "known_facts": known_facts,
        "remaining_unknowns": remaining_unknowns,
        "temporary_mitigation": temporary_mitigation,
        "reason": reason,
        "followup_evidence": followup_evidence,
    }
    try:
        raw = _call_llm_json(_decision_repair_system_prompt(), payload, bedrock_model=bedrock_model)
    except Exception:
        return ""
    if isinstance(raw, dict):
        return _normalize_decision(raw.get("decision"))
    return ""


def _run_iterative_asset_agent(
    *,
    cve_id: str,
    title: str,
    patch_summary: str,
    asset: dict[str, Any],
    additional_asset_context: dict[str, Any],
    infra_context: dict[str, Any] | None,
    region: str,
    infra_matching_runtime_arn: str | None,
    allow_followup: bool = True,
    bedrock_model: Any = None,
) -> tuple[AssetDecisionModel, list[dict[str, Any]]]:
    _require_strands()
    assert Agent is not None

    seeded_responses, answers_by_question = _seed_followup_context(
        cve_id,
        _safe_string(asset.get("asset_id")),
        additional_asset_context,
    )
    tool_events_path = ITERATIVE_TRACE_DIR / f"{uuid.uuid4().hex}.jsonl"
    try:
        tool_events_path.unlink()
    except FileNotFoundError:
        pass
    context = {
        "cve_id": cve_id,
        "title": title,
        "asset_id": _safe_string(asset.get("asset_id")),
        "asset_context": _safe_string(asset.get("asset_context")),
        "security_severity": _normalize_security_severity(asset.get("security_severity")),
        "known_facts": _safe_text_list(asset.get("known_facts")),
        "patch_summary": patch_summary,
        "missing_information": _safe_text_list(asset.get("missing_information")),
        "infra_context": infra_context if isinstance(infra_context, dict) else {},
        "region": region,
        "infra_matching_runtime_arn": infra_matching_runtime_arn,
        "max_followups": MAX_ITERATIVE_FOLLOWUPS_PER_ASSET if allow_followup else 0,
        "followup_count": 0,
        "responses": list(seeded_responses),
        "tool_events": [],
        "tool_events_path": str(tool_events_path),
        "answers_by_question": dict(answers_by_question),
        "answering_rules": [
            "운영 판단이나 승인 판단을 하지 않습니다.",
            "각 질문은 관측 가능한 사실로만 답합니다.",
            "모르면 unknown으로 답합니다.",
        ],
    }

    _ACTIVE_FOLLOWUP_TOOL_CONTEXT.clear()
    _ACTIVE_FOLLOWUP_TOOL_CONTEXT.update(context)
    try:
        def _invoke_iterative_agent(extra_instruction: str = "") -> AssetDecisionModel:
            current_responses = _collect_context_followup_responses(_ACTIVE_FOLLOWUP_TOOL_CONTEXT) or list(seeded_responses)
            remaining_candidates = _remaining_followup_candidates(asset, current_responses)
            current_message = _iterative_asset_message(
                cve_id=cve_id,
                title=title,
                patch_summary=patch_summary,
                asset=asset,
                collected_responses=current_responses,
            )
            agent = Agent(
                system_prompt=_iterative_asset_system_prompt(),
                tools=[ask_asset_followup] if allow_followup else [],
                model=str(bedrock_model or "").strip() or DEFAULT_BEDROCK_MODEL,
            )
            remaining_note = (
                "\n\n아직 확인되지 않은 follow-up 후보:\n"
                + json.dumps(remaining_candidates, ensure_ascii=False, indent=2)
                if remaining_candidates
                else ""
            )
            decision_planning_note = (
                "\n\n먼저 현재 정보와 collected_followup_responses만으로 tentative decision을 내부적으로 정리하세요. "
                "그 tentative decision을 바꾸거나 더 확정하는 데 필요한 핵심 사실이 하나 더 있다면 ask_asset_followup을 최대 1회 호출하세요. "
                "추가 질문이 현재 판단을 실질적으로 바꾸지 못한다면 tool을 호출하지 말고 바로 최종 JSON을 반환하세요."
                if allow_followup
                else ""
            )
            response = agent(
                current_message
                + (
                    "\n\n추가 follow-up tool 호출은 허용되지 않습니다. "
                    "현재 정보와 collected_followup_responses만으로 최종 판단을 내리고, "
                    "남는 빈칸은 remaining_unknowns에 남기세요."
                    if not allow_followup
                    else ""
                )
                + decision_planning_note
                + remaining_note
                + (f"\n\n{extra_instruction}" if extra_instruction else ""),
                structured_output_model=AssetDecisionModel,
            )
            structured_output = getattr(response, "structured_output", response)
            return AssetDecisionModel.model_validate(structured_output)

        model = _invoke_iterative_agent()

        if allow_followup:
            for _ in range(MAX_ITERATIVE_AGENT_PASSES - 1):
                current_responses = _collect_context_followup_responses(_ACTIVE_FOLLOWUP_TOOL_CONTEXT)
                remaining_candidates = _remaining_followup_candidates(asset, current_responses)
                if not remaining_candidates:
                    break
                before_count = int(_ACTIVE_FOLLOWUP_TOOL_CONTEXT.get("followup_count") or 0)
                model = _invoke_iterative_agent(
                    "아직 확인되지 않은 follow-up 후보가 남아 있습니다. "
                    "현재 tentative decision을 기준으로, 추가 사실 하나가 결론을 실질적으로 바꿀 수 있을 때만 "
                    "ask_asset_followup를 최대 1회 다시 호출하세요. "
                    "반대로 더 수집해도 의미가 없거나 현재 결론을 바꾸지 못한다고 판단되면, 남은 항목을 "
                    "remaining_unknowns에 남기고 종료하세요."
                )
                after_count = int(_ACTIVE_FOLLOWUP_TOOL_CONTEXT.get("followup_count") or 0)
                if after_count == before_count:
                    break
        return model, _collect_context_followup_responses(_ACTIVE_FOLLOWUP_TOOL_CONTEXT)
    finally:
        _ACTIVE_FOLLOWUP_TOOL_CONTEXT.clear()


def _normalize_iterative_asset_decision(
    *,
    cve_id: str,
    patch_summary: str,
    asset: dict[str, Any],
    decision_model: AssetDecisionModel,
    responses: list[dict[str, Any]],
    bedrock_model: Any = None,
) -> dict[str, Any]:
    asset_id = _safe_string(decision_model.asset_id or asset.get("asset_id"))
    security_severity = _normalize_security_severity(asset.get("security_severity"))
    known_facts = _safe_text_list(asset.get("known_facts"))
    followup_unknowns = _aggregate_followup_unknowns(responses)
    llm_unknowns = _safe_text_list(decision_model.remaining_unknowns)
    unresolved_candidates = [
        item.get("source_missing_information") or item.get("question", "")
        for item in _remaining_followup_candidates(asset, responses)
    ]
    remaining_unknowns = _dedupe_texts(llm_unknowns, followup_unknowns, unresolved_candidates)
    if not remaining_unknowns and decision_model.decision == "manual_review":
        remaining_unknowns = _safe_text_list(asset.get("missing_information"))

    followup_evidence = _aggregate_followup_evidence(responses)
    reason = _safe_string(decision_model.reason)
    if not reason and known_facts:
        reason = "stage1 핵심 사실: " + "; ".join(known_facts[:4])
    if followup_evidence and followup_evidence not in reason:
        reason = (reason + " follow-up 확인: " + followup_evidence).strip()
    if security_severity != "unknown" and f"보안 위험도 참고={security_severity}" not in reason:
        reason = (reason + f" 보안 위험도 참고={security_severity}.").strip()

    patch_impact = _normalize_impact(decision_model.patch_impact)
    temporary_mitigation = _safe_string(decision_model.temporary_mitigation)
    decision = _normalize_decision(decision_model.decision)
    if not decision:
        repaired_decision = _repair_decision_with_llm(
            cve_id=cve_id,
            asset_id=asset_id,
            security_severity=security_severity,
            patch_impact=patch_impact,
            known_facts=known_facts,
            remaining_unknowns=remaining_unknowns,
            temporary_mitigation=temporary_mitigation,
            reason=reason,
            followup_evidence=followup_evidence,
            bedrock_model=bedrock_model,
        )
        if repaired_decision:
            decision = repaired_decision
        else:
            decision = _fallback_decision()
            if not reason.endswith("(룰)"):
                reason = (reason + " (룰)").strip()

    action = _safe_string(decision_model.action)
    if not action:
        action = "정식 패치 또는 완화 조치를 적용하기 전 남은 불확실성을 확인한 뒤 진행합니다." if remaining_unknowns else "정식 패치를 적용하고 검증합니다."
    validation = _safe_string(decision_model.validation)
    if not validation:
        validation = "패치 또는 완화 조치 후 버전, 설정, 서비스 동작, 로그 상태를 확인합니다."

    return {
        "asset_id": asset_id,
        "asset_context": _safe_string(decision_model.asset_context or asset.get("asset_context")),
        "patch_impact": patch_impact,
        "decision": decision,
        "reason": reason,
        "action": action,
        "temporary_mitigation": temporary_mitigation,
        "validation": validation,
        "remaining_unknowns": remaining_unknowns,
    }


def _build_iterative_final_records(
    *,
    prejudge_result: dict[str, Any],
    additional_asset_context: dict[str, Any],
    infra_context: dict[str, Any] | None,
    region: str,
    infra_matching_runtime_arn: str | None,
    allow_followup: bool = True,
    bedrock_model: Any = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records: list[dict[str, Any]] = []
    all_followup_responses: list[dict[str, Any]] = []
    for pre_record in _safe_list(prejudge_result.get("records")):
        if not isinstance(pre_record, dict):
            continue
        cve_id = _safe_string(pre_record.get("cve_id"))
        title = _safe_string(pre_record.get("title"))
        patch_summary = _safe_string(pre_record.get("patch_summary"))
        decisions: list[dict[str, Any]] = []
        for asset in _safe_list(pre_record.get("asset_prejudgements")):
            if not isinstance(asset, dict):
                continue
            model, responses = _run_iterative_asset_agent(
                cve_id=cve_id,
                title=title,
                patch_summary=patch_summary,
                asset=asset,
                additional_asset_context=additional_asset_context,
                infra_context=infra_context,
                region=region,
                infra_matching_runtime_arn=infra_matching_runtime_arn,
                allow_followup=allow_followup,
                bedrock_model=bedrock_model,
            )
            for response in responses:
                if isinstance(response, dict):
                    all_followup_responses.append(response)
            decisions.append(
                _normalize_iterative_asset_decision(
                    cve_id=cve_id,
                    patch_summary=patch_summary,
                    asset=asset,
                    decision_model=model,
                    responses=responses,
                    bedrock_model=bedrock_model,
                )
            )
        records.append(
            {
                "cve_id": cve_id,
                "title": title,
                "patch_summary": patch_summary,
                "asset_decisions": decisions,
            }
        )
    return (
        records,
        {
            "_meta": _followup_bundle_meta(),
            "generated_at": _utc_now(),
            "response_count": len(all_followup_responses),
            "responses": all_followup_responses,
        },
    )


def _final_result_meta() -> dict[str, Any]:
    return {
        "payload_type": "patch_final_result",
        "payload_purpose": "위험도 결과, 자산 문맥, 운영 영향 정보, follow-up 사실 응답을 종합한 최종 패치 판단 결과입니다.",
        "decision_policy": "최종 판단은 1차 patch 판단 결과와 follow-up 사실 응답을 중심으로, 운영 영향과 남은 불확실성을 함께 고려해 생성됩니다.",
        "interpretation_guide": {
            "patch_impact": "패치나 완화 조치 적용이 운영에 미치는 영향도입니다. 보안 위험도가 아닙니다.",
            "decision": "최종 조치 방향입니다. patch_impact, 자산 상태, 남은 불확실성을 종합해 판단합니다.",
        },
        "decision_value_guide": {
            "patch_now": "운영 영향이 낮아 바로 패치해도 되는 경우",
            "patch_planned": "패치는 필요하지만 계획된 방식으로 적용해야 하는 경우",
            "mitigate_then_patch": "임시 완화를 먼저 적용한 뒤 패치를 진행해야 하는 경우",
            "manual_review": "담당자 검토가 필요한 경우",
            "no_action": "추가 작업이 필요 없는 경우",
        },
        "impact_value_guide": {
            "none": "운영 영향이 사실상 없음",
            "low": "짧은 reload 또는 단순 업데이트 수준",
            "medium": "재시작, 설정 확인, 제한적 서비스 영향 가능",
            "high": "재빌드, 재배포, 핵심 기능 영향, 복잡한 검증 필요",
            "unknown": "현재 정보만으로 신뢰성 있는 판단이 어려움",
        },
        "field_descriptions": {
            "records": "CVE별 최종 패치 판단 목록입니다.",
            "records[].cve_id": "판단 대상 CVE ID입니다.",
            "records[].title": "취약점 제목입니다.",
            "records[].patch_summary": "정식 조치, 운영 위험, 임시 완화책, 검증 포인트를 압축한 요약입니다.",
            "records[].asset_decisions": "자산별 최종 패치 판단 목록입니다.",
            "records[].asset_decisions[].asset_id": "판단 대상 자산 ID입니다.",
            "records[].asset_decisions[].asset_context": "자산의 핵심 운영 상태를 요약한 값입니다.",
            "records[].asset_decisions[].patch_impact": "패치나 완화 조치 적용이 운영에 미치는 영향도입니다.",
            "records[].asset_decisions[].decision": "최종 조치 방향입니다.",
            "records[].asset_decisions[].reason": "patch_impact와 decision을 그렇게 판단한 핵심 근거입니다.",
            "records[].asset_decisions[].action": "운영자가 실제 수행해야 할 주 조치입니다.",
            "records[].asset_decisions[].temporary_mitigation": "정식 패치를 바로 못 할 때 사용할 임시 완화 조치입니다.",
            "records[].asset_decisions[].validation": "패치 또는 완화 후 확인해야 하는 검증 항목입니다.",
            "records[].asset_decisions[].remaining_unknowns": "최종 판단 후에도 남은 불확실성 목록입니다.",
        },
    }


def finalize_patch_strategy(
    prejudge_result: dict[str, Any] | None = None,
    additional_asset_context: dict[str, Any] | None = None,
    infra_context: dict[str, Any] | None = None,
    region: str = "ap-northeast-2",
    infra_matching_runtime_arn: str | None = None,
    allow_followup: bool = True,
    bedrock_model: Any = None,
    save_path: Any = None,
    followup_save_path: Any = None,
    return_debug: bool = False,
) -> dict[str, Any]:
    _require_strands()
    prejudge_result = prejudge_result if isinstance(prejudge_result, dict) else {}
    additional_asset_context = additional_asset_context if isinstance(additional_asset_context, dict) else {}
    infra_context = infra_context if isinstance(infra_context, dict) else {}
    records, followup_bundle = _build_iterative_final_records(
        prejudge_result=prejudge_result,
        additional_asset_context=additional_asset_context,
        infra_context=infra_context,
        region=region,
        infra_matching_runtime_arn=infra_matching_runtime_arn,
        allow_followup=allow_followup,
        bedrock_model=bedrock_model,
    )
    result = {
        "_meta": _final_result_meta(),
        "records": records,
    }
    target = Path(save_path) if save_path else DEFAULT_SAVE_PATH
    _save_json(target, result)
    followup_target = Path(followup_save_path) if followup_save_path else None
    if followup_target is not None:
        _save_json(followup_target, followup_bundle)
    if return_debug:
        return {
            "result": result,
            "followup_stage": followup_bundle,
        }
    return result


def invoke(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("payload는 JSON object 형태여야 합니다.")
    return finalize_patch_strategy(
        prejudge_result=payload.get("prejudge_result"),
        additional_asset_context=payload.get("additional_asset_context"),
        infra_context=payload.get("infra_context"),
        region=_safe_string(payload.get("region"), "ap-northeast-2"),
        infra_matching_runtime_arn=payload.get("infra_matching_runtime_arn"),
        allow_followup=bool(payload.get("allow_followup", True)),
        bedrock_model=payload.get("bedrock_model_id") or payload.get("patch_impact_bedrock_model"),
        save_path=payload.get("save_path"),
        followup_save_path=payload.get("followup_save_path"),
    )
