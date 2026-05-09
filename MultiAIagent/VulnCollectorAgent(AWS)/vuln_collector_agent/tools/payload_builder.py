from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

try:
    from strands import Agent
except ImportError:
    Agent = None

try:
    from .cve_fetcher import fetch_selected_raw_cve_record
    from .cwe_fetcher import fetch_cwe_weakness_summary
    from .evidence_fetcher import fetch_operational_evidence
    from .tooling import tool
except ImportError:
    from tools.cve_fetcher import fetch_selected_raw_cve_record
    from tools.cwe_fetcher import fetch_cwe_weakness_summary
    from tools.evidence_fetcher import fetch_operational_evidence
    from tools.tooling import tool

_BASE_DIR = Path(__file__).parent.parent
_PROMPTS_DIR = _BASE_DIR / "prompts"
_RISK_REFERENCE_PROMPT_PATH = _PROMPTS_DIR / "risk_reference_system_prompt.txt"
_OPERATIONAL_DEPENDENCY_PROMPT_PATH = _PROMPTS_DIR / "operational_dependency_system_prompt.txt"
_DEFAULT_BEDROCK_MODEL = "global.anthropic.claude-haiku-4-5-20251001-v1:0"

_RISK_ASSESSMENT_FIELD_DESCRIPTIONS = {
    "records": "CVE별 취약점 참고 정보 목록입니다. 이 payload는 최종 위험도 평가 결과가 아니라, 위험도 평가 에이전트가 자산 정보와 결합하기 위한 취약점 기준 정보입니다.",
    "records[].cve_id": "CVE 식별자입니다. 취약점과 자산 평가 결과를 연결하는 기본 키입니다.",
    "records[].title": "취약점의 짧은 제목입니다. 사람이 빠르게 이해하기 위한 표시용 요약입니다.",
    "records[].affected": "무엇이 영향을 받는지 설명하는 문자열입니다. 영향받는 제품, 컴포넌트, 버전 범위, 수정 버전, 영향받지 않는 유사 artifact를 포함합니다.",
    "records[].exploit_conditions": "어떤 조건에서 취약점이 악용되는지 설명하는 문자열입니다. 공격자가 제어해야 하는 입력, 필요한 설정, 취약 코드 경로, 네트워크 조건, 악용 성공 시 결과를 포함합니다.",
    "records[].asset_checks": "위험도 평가 에이전트가 자산 수집 결과에서 확인해야 할 체크리스트입니다. 자산 기준 위험도 조정의 핵심 필드입니다.",
    "records[].asset_checks[].id": "체크 항목의 고유 ID입니다. 코드나 에이전트가 안정적으로 참조할 수 있도록 snake_case로 작성합니다.",
    "records[].asset_checks[].question": "자산 기준으로 확인해야 하는 질문입니다. 자산 수집 결과를 보고 yes, no, unknown으로 답할 수 있어야 합니다.",
    "records[].asset_checks[].importance": "이 체크가 위험도 평가에서 어떤 성격을 갖는지 설명하는 문장입니다. 정해진 설명 문장 중 가장 맞는 것을 그대로 사용합니다.",
    "records[].asset_checks[].if_absent": "자산에서 이 조건이 없다고 확인됐을 때 위험도에 어떻게 반영할지 설명하는 문장입니다. 정해진 설명 문장 중 가장 맞는 것을 그대로 사용합니다.",
    "records[].asset_checks[].if_unknown": "자산에서 이 조건을 확인하지 못했을 때 어떻게 처리할지 설명하는 문장입니다. unknown을 no처럼 취급하지 않도록 하기 위한 필드입니다.",
}

_RISK_ASSESSMENT_META = {
    "payload_purpose": "각 CVE에 대해 위험도 평가 에이전트가 자산 정보와 결합할 수 있는 취약점 기준 정보입니다. 최종 위험도 점수나 자산별 판정이 아니라, 영향 범위·악용 조건·자산에서 확인할 체크리스트를 제공합니다.",
    "field_descriptions": _RISK_ASSESSMENT_FIELD_DESCRIPTIONS,
}

_OPERATIONAL_IMPACT_FIELD_DESCRIPTIONS = {
    "records": "CVE별 운영 안전성 및 의존성 검토 결과 목록입니다. 이 payload는 보안 위험도 평가가 아니라, 패치나 완화 조치를 실제 운영 환경에 적용할 때 무엇이 깨질 수 있고 무엇을 확인해야 하는지 정리하는 용도입니다.",
    "records[].cve_id": "CVE 식별자입니다. 취약점 정보, 자산 정보, 운영 조치 결과를 연결하는 기본 키입니다.",
    "records[].title": "취약점의 짧은 제목입니다. 사람이 빠르게 어떤 취약점인지 알아보기 위한 표시용 요약입니다.",
    "records[].primary_remediation": "가장 우선해야 하는 정식 조치입니다. 보통 fixed version으로 업그레이드, 벤더 패치 적용, 취약 컴포넌트 교체 등이 들어갑니다.",
    "records[].operational_risk": "정식 조치를 적용했을 때 운영상 깨질 수 있는 부분을 요약합니다. 서비스 재시작, 런타임 동작 변경, 설정 호환성, 내장 라이브러리 충돌 같은 위험을 설명합니다.",
    "records[].dependency_checks": "패치 전에 확인해야 하는 의존성, 설정, 런타임, 패키징, 코드 경로 체크리스트입니다. 패치를 바로 진행해도 되는지 판단하는 핵심 필드입니다.",
    "records[].dependency_checks[].id": "체크 항목의 고유 ID입니다. snake_case로 작성되며 코드나 에이전트가 안정적으로 참조할 때 사용합니다.",
    "records[].dependency_checks[].question": "운영 또는 코드 관점에서 확인해야 하는 질문입니다. 자산 수집 결과, 설정 파일, 빌드 파일, 런타임 정보, 컨테이너 이미지 결과를 보고 답할 수 있어야 합니다.",
    "records[].dependency_checks[].why_it_matters": "이 체크가 왜 중요한지 설명합니다. 이 조건을 놓치면 어떤 운영 위험이나 누락이 생길 수 있는지 정리합니다.",
    "records[].dependency_checks[].if_problem_found": "체크 결과 문제가 발견됐을 때 어떻게 처리해야 하는지 설명합니다. 예: 호환성 테스트 필요, 재빌드 필요, 벤더 패치 필요, 점진 배포 필요.",
    "records[].dependency_checks[].if_unknown": "해당 체크를 확인하지 못했을 때 어떻게 처리해야 하는지 설명합니다. unknown을 안전하다고 보면 안 되며, 보수적 rollout 또는 수동 검토가 필요할 수 있습니다.",
    "records[].fallback_mitigations": "정식 패치를 즉시 적용할 수 없을 때 사용할 수 있는 임시 완화 조치 목록입니다. 패치의 대체물이 아니라 단기 방어 수단입니다.",
    "records[].fallback_mitigations[].mitigation": "완화 조치 내용입니다. 예: 취약 기능 비활성화, 특정 설정 변경, outbound 차단, 취약 컴포넌트 제거.",
    "records[].fallback_mitigations[].when_to_use": "이 완화 조치를 어떤 상황에서 사용할지 설명합니다. 예: 즉시 업그레이드가 불가능할 때, 재빌드가 지연될 때 등입니다.",
    "records[].fallback_mitigations[].limitations": "완화 조치의 한계입니다. 모든 exploit 경로를 막지 못하거나 설정 누락 시 효과가 떨어지는 점 등을 설명합니다.",
    "records[].fallback_mitigations[].validation": "완화 조치가 실제로 적용됐는지 확인하는 방법입니다. 설정값, 런타임 classpath, 네트워크 정책, 로그 동작 등을 확인하는 기준입니다.",
    "records[].rollout_guidance": "운영 중단을 줄이기 위한 배포 방식입니다. canary, rolling update, maintenance window, rollback plan, 재빌드 필요 여부 등을 포함합니다.",
    "records[].validation_checks": "정식 패치 또는 임시 완화 조치 후 확인해야 하는 검증 항목 목록입니다.",
    "records[].validation_checks[]": "패치 또는 완화 적용 후 실제로 확인해야 하는 개별 검증 항목 한 줄입니다.",
}

_OPERATIONAL_IMPACT_META = {
    "payload_purpose": "각 CVE에 대해 패치나 완화 조치를 운영 환경에 적용할 때 발생할 수 있는 의존성 문제, 운영 위험, 임시 완화책, 배포 가이드, 검증 항목을 정리한 참고 정보입니다.",
    "field_descriptions": _OPERATIONAL_IMPACT_FIELD_DESCRIPTIONS,
}

_IMPORTANCE_SENTENCE_MAP = {
    "required_for_affected": "이 조건이 없으면 해당 자산은 취약점 영향 대상이 아닐 가능성이 큽니다. 제품 존재 여부, 취약 컴포넌트 존재 여부, 영향 버전 여부에 사용합니다.",
    "required_for_exploit": "이 조건이 없으면 취약 버전이 있더라도 실제 악용 가능성이 크게 낮아집니다. 기능 사용 여부, 취약 코드 경로 도달 여부, 공격자 입력 유입 여부 등에 사용합니다.",
    "major_downgrade": "이 조건은 exploit 성립의 필수 조건은 아닐 수 있지만, 있으면 위험도를 높이고 없으면 일부 낮출 수 있는 요소입니다.",
    "do_not_downgrade": "위험도 판단에 참고할 수는 있지만 단독으로 큰 조정을 하면 안 되는 보조 정보입니다.",
}

_IF_ABSENT_SENTENCE_MAP = {
    "not_affected": "이 조건이 없으면 해당 자산은 이 CVE의 영향 대상이 아니라고 볼 수 있습니다.",
    "exploit_not_met": "취약점 영향 대상일 수는 있지만 실제 exploit 조건이 빠져 위험도를 크게 낮출 수 있습니다.",
    "partial_downgrade": "위험도 일부를 낮출 수 있지만 exploit 가능성을 완전히 배제하면 안 됩니다.",
    "no_major_change": "조건이 없더라도 위험도에 큰 변화를 주지 않습니다.",
    "manual_review": "조건 부재가 위험도에 어떤 영향을 주는지 자동 판단하기 어렵기 때문에 수동 검토가 필요합니다.",
}

_IF_UNKNOWN_SENTENCE_MAP = {
    "need_more_asset_data": "정보가 없어서 영향 여부를 확정할 수 없습니다. 추가 자산 수집 또는 수동 확인이 필요합니다.",
    "do_not_downgrade_on_unknown": "불명확하다는 이유만으로 위험도를 낮추면 안 됩니다.",
    "conservative_until_verified": "확인 전까지 영향 가능성이 있다고 보고 보수적으로 평가합니다.",
    "manual_review": "자동 판단하지 말고 사람이 확인해야 합니다.",
}

_DEFAULT_IMPORTANCE = _IMPORTANCE_SENTENCE_MAP["do_not_downgrade"]
_DEFAULT_IF_ABSENT = _IF_ABSENT_SENTENCE_MAP["manual_review"]
_DEFAULT_IF_UNKNOWN = _IF_UNKNOWN_SENTENCE_MAP["need_more_asset_data"]

_RISK_REFERENCE_CACHE: dict[tuple[str, str], "RiskReferenceRecord"] = {}
_OPERATIONAL_DEPENDENCY_CACHE: dict[tuple[str, str], "OperationalDependencyRecord"] = {}


class AssetCheck(BaseModel):
    id: str = "unknown_check"
    question: str = "unknown"
    importance: str = _DEFAULT_IMPORTANCE
    if_absent: str = _DEFAULT_IF_ABSENT
    if_unknown: str = _DEFAULT_IF_UNKNOWN

    @field_validator("id", mode="before")
    @classmethod
    def _normalize_id(cls, value: Any) -> str:
        text = str(value or "").strip().lower()
        if not text:
            return "unknown_check"
        text = re.sub(r"[^a-z0-9]+", "_", text)
        text = re.sub(r"_+", "_", text).strip("_")
        return text or "unknown_check"

    @field_validator("question", mode="before")
    @classmethod
    def _normalize_question(cls, value: Any) -> str:
        text = str(value or "").strip()
        return text or "unknown"

    @field_validator("importance", mode="before")
    @classmethod
    def _normalize_importance(cls, value: Any) -> str:
        text = str(value or "").strip()
        return _IMPORTANCE_SENTENCE_MAP.get(text, text or _DEFAULT_IMPORTANCE)

    @field_validator("if_absent", mode="before")
    @classmethod
    def _normalize_if_absent(cls, value: Any) -> str:
        text = str(value or "").strip()
        return _IF_ABSENT_SENTENCE_MAP.get(text, text or _DEFAULT_IF_ABSENT)

    @field_validator("if_unknown", mode="before")
    @classmethod
    def _normalize_if_unknown(cls, value: Any) -> str:
        text = str(value or "").strip()
        return _IF_UNKNOWN_SENTENCE_MAP.get(text, text or _DEFAULT_IF_UNKNOWN)


class RiskReferenceRecord(BaseModel):
    cve_id: str = "unknown"
    title: str = "unknown"
    affected: str = "unknown"
    exploit_conditions: str = "unknown"
    asset_checks: list[AssetCheck] = Field(default_factory=list)

    @field_validator("cve_id", "title", "affected", "exploit_conditions", mode="before")
    @classmethod
    def _normalize_text_field(cls, value: Any) -> str:
        text = str(value or "").strip()
        return text or "unknown"


class RiskReferencePayload(BaseModel):
    records: list[RiskReferenceRecord] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _coerce_single_record(cls, value: Any) -> Any:
        if isinstance(value, dict) and "records" not in value:
            return {"records": [value]}
        return value


class DependencyCheck(BaseModel):
    id: str = "unknown_check"
    question: str = "unknown"
    why_it_matters: str = "unknown"
    if_problem_found: str = "unknown"
    if_unknown: str = "unknown"

    @field_validator("id", mode="before")
    @classmethod
    def _normalize_id(cls, value: Any) -> str:
        text = str(value or "").strip().lower()
        if not text:
            return "unknown_check"
        text = re.sub(r"[^a-z0-9]+", "_", text)
        text = re.sub(r"_+", "_", text).strip("_")
        return text or "unknown_check"

    @field_validator("question", "why_it_matters", "if_problem_found", "if_unknown", mode="before")
    @classmethod
    def _normalize_text_fields(cls, value: Any) -> str:
        text = str(value or "").strip()
        return text or "unknown"


class FallbackMitigation(BaseModel):
    mitigation: str = "unknown"
    when_to_use: str = "unknown"
    limitations: str = "unknown"
    validation: str = "unknown"

    @field_validator("mitigation", "when_to_use", "limitations", "validation", mode="before")
    @classmethod
    def _normalize_text_fields(cls, value: Any) -> str:
        text = str(value or "").strip()
        return text or "unknown"


class OperationalDependencyRecord(BaseModel):
    cve_id: str = "unknown"
    title: str = "unknown"
    primary_remediation: str = "unknown"
    operational_risk: str = "unknown"
    dependency_checks: list[DependencyCheck] = Field(default_factory=list)
    fallback_mitigations: list[FallbackMitigation] = Field(default_factory=list)
    rollout_guidance: str = "unknown"
    validation_checks: list[str] = Field(default_factory=list)

    @field_validator("cve_id", "title", "primary_remediation", "operational_risk", "rollout_guidance", mode="before")
    @classmethod
    def _normalize_text_fields(cls, value: Any) -> str:
        text = str(value or "").strip()
        return text or "unknown"

    @field_validator("validation_checks", mode="before")
    @classmethod
    def _normalize_validation_checks(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            text = value.strip()
            return [text] if text else []
        if isinstance(value, list):
            normalized: list[str] = []
            for item in value:
                text = str(item or "").strip()
                if text and text not in normalized:
                    normalized.append(text)
            return normalized
        text = str(value).strip()
        return [text] if text else []


class OperationalDependencyPayload(BaseModel):
    records: list[OperationalDependencyRecord] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _coerce_single_record(cls, value: Any) -> Any:
        if isinstance(value, dict) and "records" not in value:
            return {"records": [value]}
        return value


def _bedrock_model_id() -> str:
    return (os.getenv("BEDROCK_MODEL_ID") or _DEFAULT_BEDROCK_MODEL).strip()


def _load_risk_reference_prompt() -> str:
    return _RISK_REFERENCE_PROMPT_PATH.read_text(encoding="utf-8").strip()


def _load_operational_dependency_prompt() -> str:
    return _OPERATIONAL_DEPENDENCY_PROMPT_PATH.read_text(encoding="utf-8").strip()


def _require_strands() -> None:
    if Agent is None:
        raise RuntimeError(
            "strands-agents is required for vulnerability payload generation. "
            "Install it and rebuild the runtime before running this agent."
        )


def _agent_tools(evidence_mode: str) -> list[Any]:
    tools: list[Any] = [
        fetch_selected_raw_cve_record,
        fetch_cwe_weakness_summary,
    ]
    if evidence_mode != "off":
        tools.append(fetch_operational_evidence)
    return tools


def _risk_agent_message(cve_id: str) -> str:
    return f"CVE {cve_id}에 대한 risk reference payload를 작성하세요."


def _operational_agent_message(cve_id: str) -> str:
    return f"CVE {cve_id}에 대한 operational dependency payload를 작성하세요."


def _evidence_mode_message(evidence_mode: str) -> str:
    if evidence_mode == "off":
        return (
            "추가 evidence tool은 사용하지 마세요. "
            "raw CVE와 CWE만으로 부족한 내용은 unknown으로 남기세요."
        )
    if evidence_mode == "on":
        return (
            "fetch_operational_evidence(cve_id)를 반드시 활용해 NVD context, KEV, "
            "patch/reference를 확인한 뒤 결과를 작성하세요."
        )
    return (
        "raw CVE와 CWE만으로 부족하면 fetch_operational_evidence(cve_id)를 호출하세요. "
        "근거가 충분하지 않으면 unknown으로 남기세요."
    )


def _run_structured_agent(
    *,
    system_prompt: str,
    message: str,
    structured_output_model: type[BaseModel],
    evidence_mode: str,
) -> BaseModel:
    _require_strands()
    assert Agent is not None

    agent = Agent(
        system_prompt=system_prompt,
        tools=_agent_tools(evidence_mode),
        model=_bedrock_model_id(),
    )
    response = agent(
        f"{message}\n\n{_evidence_mode_message(evidence_mode)}",
        structured_output_model=structured_output_model,
    )
    structured_output = getattr(response, "structured_output", response)
    return structured_output_model.model_validate(structured_output)


def _normalize_risk_reference_record(cve_id: str, *, evidence_mode: str) -> RiskReferenceRecord:
    cache_key = (cve_id, evidence_mode)
    cached = _RISK_REFERENCE_CACHE.get(cache_key)
    if cached is not None:
        return cached

    structured_output = _run_structured_agent(
        system_prompt=_load_risk_reference_prompt(),
        message=_risk_agent_message(cve_id),
        structured_output_model=RiskReferencePayload,
        evidence_mode=evidence_mode,
    )
    normalized = structured_output.records[0] if structured_output.records else RiskReferenceRecord()
    normalized = normalized.model_copy(
        update={
            "cve_id": normalized.cve_id if normalized.cve_id != "unknown" else cve_id,
        }
    )
    _RISK_REFERENCE_CACHE[cache_key] = normalized
    return normalized


def _normalize_operational_dependency_record(
    cve_id: str,
    *,
    evidence_mode: str,
) -> OperationalDependencyRecord:
    cache_key = (cve_id, evidence_mode)
    cached = _OPERATIONAL_DEPENDENCY_CACHE.get(cache_key)
    if cached is not None:
        return cached

    structured_output = _run_structured_agent(
        system_prompt=_load_operational_dependency_prompt(),
        message=_operational_agent_message(cve_id),
        structured_output_model=OperationalDependencyPayload,
        evidence_mode=evidence_mode,
    )
    normalized = structured_output.records[0] if structured_output.records else OperationalDependencyRecord()
    normalized = normalized.model_copy(
        update={
            "cve_id": normalized.cve_id if normalized.cve_id != "unknown" else cve_id,
        }
    )
    _OPERATIONAL_DEPENDENCY_CACHE[cache_key] = normalized
    return normalized


def _extract_cve_ids_from_dataset(dataset: dict) -> list[str]:
    cve_ids: list[str] = []
    for record in dataset.get("records", []) if isinstance(dataset, dict) else []:
        if not isinstance(record, dict):
            continue
        cve_id = str(record.get("cve_id") or "").strip()
        if cve_id and cve_id not in cve_ids:
            cve_ids.append(cve_id)
    return cve_ids


@tool
def build_risk_assessment_payloads(dataset: dict, evidence_mode: str = "auto") -> dict:
    records = []

    for cve_id in _extract_cve_ids_from_dataset(dataset):
        normalized = _normalize_risk_reference_record(cve_id, evidence_mode=evidence_mode)
        records.append(
            {
                "cve_id": normalized.cve_id,
                "title": normalized.title,
                "affected": normalized.affected,
                "exploit_conditions": normalized.exploit_conditions,
                "asset_checks": [check.model_dump() for check in normalized.asset_checks],
            }
        )

    return {
        "_meta": _RISK_ASSESSMENT_META,
        "record_count": len(records),
        "records": records,
    }


@tool
def build_risk_assessment_payloads_from_cve_ids(
    cve_ids: list[str],
    evidence_mode: str = "auto",
) -> dict:
    records = []

    for cve_id in cve_ids:
        normalized = _normalize_risk_reference_record(str(cve_id).strip(), evidence_mode=evidence_mode)
        records.append(
            {
                "cve_id": normalized.cve_id,
                "title": normalized.title,
                "affected": normalized.affected,
                "exploit_conditions": normalized.exploit_conditions,
                "asset_checks": [check.model_dump() for check in normalized.asset_checks],
            }
        )

    return {
        "_meta": _RISK_ASSESSMENT_META,
        "record_count": len(records),
        "records": records,
    }


@tool
def build_operational_impact_payloads(dataset: dict, evidence_mode: str = "auto") -> dict:
    records = []

    for cve_id in _extract_cve_ids_from_dataset(dataset):
        normalized = _normalize_operational_dependency_record(cve_id, evidence_mode=evidence_mode)
        records.append(
            {
                "cve_id": normalized.cve_id,
                "title": normalized.title,
                "primary_remediation": normalized.primary_remediation,
                "operational_risk": normalized.operational_risk,
                "dependency_checks": [check.model_dump() for check in normalized.dependency_checks],
                "fallback_mitigations": [mitigation.model_dump() for mitigation in normalized.fallback_mitigations],
                "rollout_guidance": normalized.rollout_guidance,
                "validation_checks": normalized.validation_checks,
            }
        )

    return {
        "_meta": _OPERATIONAL_IMPACT_META,
        "record_count": len(records),
        "records": records,
    }


@tool
def build_operational_impact_payloads_from_cve_ids(
    cve_ids: list[str],
    evidence_mode: str = "auto",
) -> dict:
    records = []

    for cve_id in cve_ids:
        normalized = _normalize_operational_dependency_record(str(cve_id).strip(), evidence_mode=evidence_mode)
        records.append(
            {
                "cve_id": normalized.cve_id,
                "title": normalized.title,
                "primary_remediation": normalized.primary_remediation,
                "operational_risk": normalized.operational_risk,
                "dependency_checks": [check.model_dump() for check in normalized.dependency_checks],
                "fallback_mitigations": [mitigation.model_dump() for mitigation in normalized.fallback_mitigations],
                "rollout_guidance": normalized.rollout_guidance,
                "validation_checks": normalized.validation_checks,
            }
        )

    return {
        "_meta": _OPERATIONAL_IMPACT_META,
        "record_count": len(records),
        "records": records,
    }
