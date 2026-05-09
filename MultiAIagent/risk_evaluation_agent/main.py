"""위험도 평가 에이전트 — AgentCore Runtime entrypoint.

호출 페이로드 스키마:
    {
      "vulnerability_payload": { "records": [...] },   # 필수, risk_assessment_payloads.json 형식
      "infra_context":         { "assets": [...], ... },# 선택, 이미 수집된 자산 데이터
      "vpc_id":                "vpc-...",                # 선택, infra_context 없을 때 자산매칭 자동 호출용
      "cve_payload":           { "records": [...] },    # 선택, 자산매칭에 넘길 CVE 페이로드 (없으면 vulnerability_payload 재사용)
      "region":                "ap-northeast-2",         # 선택, 자산매칭 호출 리전
      "asset_matching_arn":    "arn:...",                # 선택, 환경변수 ASSET_MATCHING_ARN 으로도 지정 가능
      "metadata":              {...},                    # 선택, 자산매칭 호출 시 부가 메타데이터
      "prompt":                "..."                     # 선택, 기본 프롬프트 override
    }

응답: 정제된 위험도 평가 JSON 배열 문자열.
"""
import json
import os
import re

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from pydantic import BaseModel, Field
from typing import List, Optional

import risk_assessment_refiner
import infra_context_refiner

from bedrock_agentcore import BedrockAgentCoreApp
from strands import Agent, tool

# ---------------------------------------------------------------------------
# 설정
# ---------------------------------------------------------------------------

BEDROCK_MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID",
    "global.anthropic.claude-sonnet-4-6",
)
DEFAULT_REGION = os.environ.get("DEFAULT_REGION", "ap-northeast-2")
ASSET_MATCHING_ARN_ENV = "ASSET_MATCHING_ARN"

app = BedrockAgentCoreApp()

# 현재 invoke 의 컨텍스트 (도구 함수에서 참조)
_runtime_state: dict = {
    "infra_context": None,
    "asset_matching_arn": None,
    "region": DEFAULT_REGION,
    "final_report": None,
    "query_log": [],   # swarm 호출 기록
}

# boto3 client 캐시
_boto3_clients: dict = {}


def _client(service: str, region: str):
    key = (service, region)
    if key not in _boto3_clients:
        # bedrock-agentcore 호출은 SSM 수집까지 포함해 수 분 걸릴 수 있어 타임아웃을 넉넉히 설정
        cfg = Config(read_timeout=600, connect_timeout=10) if service == "bedrock-agentcore" else None
        _boto3_clients[key] = boto3.client(service, region_name=region, config=cfg)
    return _boto3_clients[key]


# ---------------------------------------------------------------------------
# 데이터 규격
# ---------------------------------------------------------------------------

class ImpactedAsset(BaseModel):
    instance_id: str = Field(description="AWS EC2 인스턴스 ID")
    base_cvss: Optional[float] = Field(default=None, description="CVE 기본 CVSS 점수")
    calculated_risk: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW 중 하나")
    exposure_level: str = Field(description="Public 또는 Internal")
    mitigations_found: List[str] = Field(default_factory=list, description="적용된 완화 조치 목록")
    risk_adjustment_reason: str = Field(description="기본 CVSS 대비 위험도 조정 근거")
    remediation: str = Field(description="보안 권고 조치 사항")


class FinalReport(BaseModel):
    cve_id: str = Field(description="분석 대상 취약점 번호")
    title: str = Field(description="취약점 명칭")
    impacted_assets: List[ImpactedAsset] = Field(description="영향을 받는 자산 리스트")


# ---------------------------------------------------------------------------
# 자산매칭 에이전트 호출 헬퍼
# ---------------------------------------------------------------------------

def _invoke_asset_matching(payload: dict) -> dict:
    """asset_matching_agent (AgentCore Runtime) 호출."""
    arn = _runtime_state.get("asset_matching_arn")
    if not arn:
        raise RuntimeError(
            f"자산매칭 ARN 미설정. payload.asset_matching_arn 또는 환경변수 {ASSET_MATCHING_ARN_ENV} 필요."
        )
    region = _runtime_state.get("region", DEFAULT_REGION)
    client = _client("bedrock-agentcore", region)
    try:
        resp = client.invoke_agent_runtime(
            agentRuntimeArn=arn,
            payload=json.dumps(payload).encode("utf-8"),
        )
    except ClientError as e:
        raise RuntimeError(f"asset_matching invoke 실패: {e}")

    raw = resp["response"].read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"error": f"asset_matching 응답 파싱 실패: {raw[:200]!r}"}


# ---------------------------------------------------------------------------
# 도구
# ---------------------------------------------------------------------------

@tool
def query_asset_details(instance_id: str, question: str) -> str:
    """
    특정 EC2 인스턴스에 대해 자산 매칭 에이전트에게 추가 조사를 요청한다.
    위험도 평가에 필요한 사실이 프롬프트에 없으면 이 도구로 실시간 추가 조사를 수행한다.
    특히 CVE별 패치/완화 적용 여부, 취약 컴포넌트의 실제 설치/실행 여부,
    공격 전제조건 충족 여부, 관련 설정 파일/프로세스/포트 근거를 확인할 때 사용한다.

    Args:
        instance_id: 조사 대상 EC2 인스턴스 ID (예: i-0123abcd).
        question: 자산 매칭 에이전트에게 보낼 구체적 질문
                  (예: "이 CVE가 영향을 주는 컴포넌트가 실제 설치/실행 중인지,
                  패치 또는 완화 설정이 적용됐는지, 공격 전제조건이 이 자산에서
                  충족되는지 명령 출력 근거와 함께 확인해 달라.").

    Returns:
        자산 매칭 에이전트의 답변 텍스트 (answer + confidence + evidence).
    """
    log_entry = {"instance_id": instance_id, "question": question}
    _runtime_state["query_log"].append(log_entry)

    infra = _runtime_state.get("infra_context") or {}
    assets = infra.get("assets") if isinstance(infra, dict) else None
    if not assets:
        return "[ERROR] infra_context 없음 — 자산 매칭 결과를 먼저 받아야 합니다."

    asset = next((a for a in assets if a.get("asset_id") == instance_id), None)
    if asset is None:
        ids = ", ".join(a.get("asset_id", "") for a in assets)
        return f"[ERROR] {instance_id} 자산 미존재. 가능한 ID: {ids}"

    try:
        body = _invoke_asset_matching({
            "mode": "query",
            "asset_info": asset,
            "instance_id": instance_id,
            "question": question,
            "region": _runtime_state.get("region", DEFAULT_REGION),
        })
    except Exception as exc:  # noqa: BLE001
        error = f"{type(exc).__name__}: {exc}"
        log_entry.update({"error": error, "confidence": "none"})
        return f"[ERROR] asset_matching query failed: {error}"

    if not isinstance(body, dict):
        log_entry.update({"error": "asset_matching response was not a JSON object", "confidence": "none"})
        return f"[ERROR] asset_matching 응답이 JSON object가 아닙니다: {str(body)[:200]}"

    if "error" in body:
        log_entry.update({"error": body["error"], "confidence": "none"})
        return f"[ERROR] {body['error']}"
    answer = body.get("answer", "")
    confidence = body.get("confidence", "")
    evidence = body.get("evidence", [])
    # 결과를 query_log 에 기록
    log_entry.update({"answer": answer[:200], "confidence": confidence})
    return (
        f"[answer]     {answer}\n"
        f"[confidence] {confidence}\n"
        f"[evidence]   {json.dumps(evidence, ensure_ascii=False)}"
    )


@tool
def finalize_report(report: FinalReport):
    """위험도 평가가 완전히 끝났을 때 최종 리포트를 저장한다."""
    if hasattr(report, "model_dump"):
        data = report.model_dump()
    elif hasattr(report, "dict"):
        data = report.dict()
    else:
        data = dict(report)
    _runtime_state["final_report"] = data
    with open("risk_evaluation_result.json", "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return "FINAL_COMPLETE"


# ---------------------------------------------------------------------------
# 페이로드 검증
# ---------------------------------------------------------------------------

def _ensure_infra_context(payload: dict) -> dict:
    """payload 에서 infra_context 를 추출한다. 없으면 에러 — 오케스트레이터가 제공해야 함."""
    infra = payload.get("infra_context")
    if isinstance(infra, dict) and infra.get("assets"):
        return infra
    raise RuntimeError(
        "infra_context 가 없습니다. 오케스트레이터가 asset_matching 결과를 전달해야 합니다."
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

@app.entrypoint
def invoke(payload):
    payload = payload or {}

    # 1) 런타임 상태 초기화
    _runtime_state["region"] = payload.get("region") or DEFAULT_REGION
    _runtime_state["asset_matching_arn"] = (
        payload.get("asset_matching_arn") or os.environ.get(ASSET_MATCHING_ARN_ENV)
    )

    # 2) 입력 데이터 확보
    vuln_payload = payload.get("vulnerability_payload") or payload.get("cve_payload")
    if not vuln_payload:
        return {"error": "vulnerability_payload (또는 cve_payload) 가 필요합니다."}

    try:
        infra_context = _ensure_infra_context(payload)
    except RuntimeError as e:
        return {"error": str(e)}

    _runtime_state["infra_context"] = infra_context

    # 3) refiner 로 정제 (dict 직접 전달)
    vuln_list = risk_assessment_refiner.get_refined_vulnerability(vuln_payload)
    asset_info = infra_context_refiner.get_refined_asset_report(infra_context)

    # 4) Agent 가 부족한 사실을 직접 판단해 query_asset_details 를 호출하도록 로그만 초기화한다.
    _runtime_state["query_log"] = []

    # 5) 프롬프트 구성
    user_message = f"""
다음 취약점과 자산 목록을 분석하여 누락 없이 전수 위험도 리포트를 작성하십시오.

[참조 데이터]
- 취약점 목록   : {json.dumps(vuln_list, ensure_ascii=False)}
- 자산 목록     : {json.dumps(asset_info, ensure_ascii=False)}

# STEP 1 — 취약 자산 식별
각 CVE 가 영향을 미치는 소프트웨어를 자산 목록의 installed_software 와 대조하여 취약 인스턴스를 찾으십시오.

# STEP 2 — 부족한 런타임 사실 확인
자산 목록은 후보 식별용 요약입니다. 패치/완화 적용 여부, 취약 컴포넌트의 실제 실행 여부,
권한, 네트워크 노출, 인증/사용자입력/프로토콜/설정 활성화 같은 공격 전제조건은 이 요약만으로 확정하지 마십시오.

각 CVE의 description, domain, risk_signals, CWE, common_consequences, analyst_summary를 읽고
해당 취약점의 실제 악용 가능성을 판단하는 데 필요한 런타임 확인 항목을 먼저 정하십시오.

최종 JSON을 작성하기 전에, impacted_assets 에 포함할 모든 CVE-자산 조합에 대해
반드시 query_asset_details(instance_id, question) 도구를 최소 1회 호출해 asset_matching_agent 에 확인하십시오.
도구를 호출하지 않은 자산은 impacted_assets 에 포함하지 마십시오.

각 도구 호출은 최소한 아래 공통 사실을 확인해야 합니다.
- CVE별 패치, 완화 조치, 우회 조치가 실제로 적용되어 있는지
- 취약 소프트웨어/컴포넌트가 실제 설치되어 있고 실행 또는 사용 중인지
- 취약 컴포넌트 또는 관련 프로세스가 높은 권한(root/administrator 등)으로 실행 중인지
- CVSS와 risk_signals가 요구하는 공격 경로(네트워크, 로컬, 인증, 사용자 상호작용, 입력 도달성 등)가 이 자산에서 충족되는지
- 판단 근거가 된 설정 파일, 프로세스, 포트, 패키지/라이브러리, 명령 출력이 무엇인지

CVE 특성에 따라 필요한 추가 확인 항목이 있으면 질문에 포함하십시오.
- deserialization / injection / RCE: 외부 입력이 취약 라이브러리나 sink까지 도달하는지
- authentication bypass / privilege escalation: 인증 경계, 실행 사용자, 권한 상승 경로가 실제로 존재하는지
- memory corruption / parser bug: 취약 프로토콜, parser, resolver, codec, module이 활성화되어 있는지
- path traversal / file read-write: 사용자 입력이 파일 경로 또는 파일 API로 전달되는지
- DoS: 취약 서비스가 운영 트래픽 경로에 있고 재시작/장애 영향이 큰지

도구 질문은 한 인스턴스에 대해 가능한 한 통합해서 묻되, CVE와 확인할 항목을 구체적으로 적으십시오.
도구 호출이 실패하면 실패 사실을 risk_adjustment_reason 에 기록하고, 해당 조건은 추측하지 말고 unknown 또는 보수적 판단으로 남기십시오.
risk_adjustment_reason 에는 반드시 asset agent 응답의 answer/confidence/evidence 중 실제 확인된 내용을 반영하십시오.

mitigation 적용 여부 해석:
- "적용됨" / "yes" / "설정 확인됨" → mitigations_found 에 기록, risk 2단계 하향
- "미적용" / "no" / "확인 안됨"   → mitigations_found = [], risk 유지

root_process 해석:
- "root 실행" / "yes"   → risk 유지 또는 상향
- "non-root" / "no"     → risk 1단계 하향

exposure 해석:
- "공인 IP" / "public"  → exposure_level = "Public"
- "내부망" / "private"  → exposure_level = "Internal", risk 1단계 하향 가능

# STEP 3 — 최종 위험도 결정 규칙
| 조건                                         | 조정           |
|----------------------------------------------|----------------|
| mitigation 적용됨                            | -2단계         |
| non-root 실행                                | -1단계         |
| 내부망(Internal)                             | -1단계         |
| mitigation 미적용 + root + 인터넷 노출       | 기준점 유지    |
단계 순서: CRITICAL → HIGH → MEDIUM → LOW

# OUTPUT FORMAT (STRICT JSON ARRAY ONLY)
[
  {{
    "cve_id": "CVE-XXXX-XXXXX",
    "title": "취약점 명칭",
    "impacted_assets": [
      {{
        "instance_id": "i-xxxxxxxxxxxxxxxxx",
        "base_cvss": 10.0,
        "calculated_risk": "CRITICAL | HIGH | MEDIUM | LOW",
        "exposure_level": "Public | Internal",
        "mitigations_found": ["적용된 완화조치 목록, 없으면 빈 배열"],
        "risk_adjustment_reason": "asset agent 확인 결과: mitigation 미적용 + root 실행 + Public 노출로 CRITICAL 유지. evidence: ...",
        "remediation": "권고 조치"
      }}
    ]
  }}
]

RESPONSE MUST BE A SINGLE JSON ARRAY ONLY. NO TEXT OUTSIDE THE JSON. NO LINE BREAKS INSIDE VALUES.
"""

    # 6) Agent 실행 (도구: query_asset_details — 추가 조사용)
    _runtime_state["final_report"] = None

    system_prompt = (
        "당신은 CVE 취약점 지식을 보유한 보안 위험도 평가 전문가입니다. "
        "입력의 CVE 정보로 취약점별 공격 전제조건을 먼저 파악하고, 자산 목록은 후보 식별용 요약으로만 사용하십시오. "
        "패치/완화 적용, 취약 컴포넌트의 실제 실행/사용 여부, 권한, 노출, 입력 도달성, 설정 활성화 같은 "
        "런타임 사실은 프롬프트의 요약만으로 확정하지 마십시오. "
        "최종 impacted_assets 에 포함할 모든 CVE-자산 조합은 반드시 query_asset_details 도구로 "
        "asset_matching_agent 에 확인한 뒤 판단하십시오. 질문은 특정 CVE 유형에 필요한 확인 항목을 스스로 정해 작성하십시오. "
        "도구를 호출하지 않은 자산은 최종 결과에 포함하지 마십시오. "
        "도구 응답의 answer, confidence, evidence 를 risk_adjustment_reason 에 반영하고, "
        "도구 실패 시에는 추측하지 말고 실패와 불확실성을 기록하십시오."
    )
    agent = Agent(
        model=BEDROCK_MODEL_ID,
        system_prompt=system_prompt,
        tools=[query_asset_details],
    )
    result = agent(user_message)

    query_log = _runtime_state.get("query_log", [])

    # 6) 결과 파싱 — finalize_report 호출 결과 우선, 없으면 텍스트에서 파싱
    if _runtime_state["final_report"] is not None:
        out = _runtime_state["final_report"]
        if isinstance(out, list):
            out = {"risk_report": out, "swarm_queries": query_log}
        return json.dumps(out, indent=4, ensure_ascii=False)

    # 텍스트 응답에서 JSON 추출 시도
    try:
        content_blocks = result.message.get("content", [])
        raw_text = ""
        for block in content_blocks:
            if isinstance(block, dict) and block.get("type") == "text":
                raw_text = block.get("text", "").strip()
                break
        if not raw_text:
            raw_text = str(result).strip()
    except Exception:
        raw_text = str(result).strip()

    if "```" in raw_text:
        parts = raw_text.split("```")
        for part in parts:
            part = part.lstrip("json").strip()
            if part.startswith("[") or part.startswith("{"):
                raw_text = part
                break

    try:
        final_data = json.loads(raw_text)
        return json.dumps({"risk_report": final_data, "swarm_queries": query_log}, indent=4, ensure_ascii=False)
    except Exception:
        try:
            clean_text = re.sub(r"\s+", " ", raw_text)
            fixed_data = json.loads(clean_text)
            return json.dumps({"risk_report": fixed_data, "swarm_queries": query_log}, indent=4, ensure_ascii=False)
        except Exception:
            return f"JSON 파싱 실패. 원본 데이터: {raw_text[:500]}"


if __name__ == "__main__":
    app.run()
