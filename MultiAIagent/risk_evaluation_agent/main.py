import json
import os
import re

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from typing import Optional

from bedrock_agentcore import BedrockAgentCoreApp
from strands import Agent, tool
from strands.models.openai import OpenAIModel

# ---------------------------------------------------------------------------
# 설정
# ---------------------------------------------------------------------------

OPENAI_MODEL_ID = os.environ.get("OPENAI_MODEL") or os.environ.get("OPENAI_MODEL_ID") or "gpt-4.1-mini"
OPENAI_BASE_URL = str(os.environ.get("OPENAI_BASE_URL") or "").strip()
DEFAULT_REGION = os.environ.get("DEFAULT_REGION", "ap-northeast-2")
ASSET_MATCHING_ARN_ENV = "ASSET_MATCHING_ARN"

app = BedrockAgentCoreApp()

# 현재 invoke 의 컨텍스트 (도구 함수에서 참조)
_runtime_state: dict = {
    "infra_context": None,
    "asset_matching_arn": None,
    "region": DEFAULT_REGION,
    "query_log": [],   # swarm 호출 기록
}

# boto3 client 캐시
_boto3_clients: dict = {}


def _build_openai_model() -> OpenAIModel:
    api_key = str(os.environ.get("OPENAI_API_KEY") or "").strip()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY 환경변수가 필요합니다.")

    client_args = {"api_key": api_key}
    if OPENAI_BASE_URL:
        client_args["base_url"] = OPENAI_BASE_URL

    return OpenAIModel(
        client_args=client_args,
        model_id=OPENAI_MODEL_ID,
        params={"temperature": 0},
    )


def _client(service: str, region: str):
    key = (service, region)
    if key not in _boto3_clients:
        # bedrock-agentcore 호출은 SSM 수집까지 포함해 수 분 걸릴 수 있어 타임아웃을 넉넉히 설정
        cfg = Config(read_timeout=600, connect_timeout=10) if service == "bedrock-agentcore" else None
        _boto3_clients[key] = boto3.client(service, region_name=region, config=cfg)
    return _boto3_clients[key]


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


def _ensure_vulnerability_payload(payload: dict) -> dict:
    vuln = payload.get("vulnerability_payload") or payload.get("cve_payload")
    if isinstance(vuln, dict) and isinstance(vuln.get("records"), list):
        return vuln
    raise RuntimeError("vulnerability_payload (또는 cve_payload) 가 필요합니다.")


def _risk_system_prompt() -> str:
    return """
당신은 누구인가:
- 당신은 보안 위험도 평가 전문가입니다.
- 목적은 각 CVE가 각 자산에 실제로 어느 정도 위험한지를 판단하는 것입니다.
- 이 단계는 패치 전략, 완화 전략, 운영 변경 계획을 세우는 단계가 아닙니다.

Available evidence / 초기 사용 가능한 근거:
- risk_assessment_payloads
- infra_context

입력 데이터 의미:
- risk assessment payload context: CVE별로 영향을 받는 소프트웨어 컴포넌트, 공격 전제조건, 자산에서 확인해야 할 사실들을 담고 있습니다.
- risk assessment payload context의 records[].cvss.score 는 취약점 기준 base CVSS 점수입니다.
- infra_context: 각 자산에 설치된 소프트웨어, 네트워크 노출 정보, 보안 설정 정보 등을 담고 있습니다.


Your task / 해야 할 일:
- 먼저 risk assessment payload context와 infra_context전체를 읽고, 각 자산별로 어떤 CVE가 영향을 줄 수 있는지 후보 자산을 식별하십시오.
각 CVE의 affected, exploit_conditions, asset_checks를 기준으로 후보 자산으로부터 어떤 부분이 확인돼야 하는지 고려해보세요.
- 만약 주어진 입력 자료들만으로 위험도 판단에 필요한 근거가 충분하지 않다면, query_asset_details 도구를 사용해서 추가 조사를 수행하십시오.
- 질문은 설정 파일, 실행 인자, 프로세스, 포트, 로그 경로, 입력 도달성, 네트워크 경로처럼 직접 확인 가능한 사실만 다루십시오.
- 질문을 할때는 asset_checks 참고하여 질문해도 좋으나 그렇지 않더라도 위험도 판단에 필요한 근거가 부족하다고 생각되면 적극적으로 질문하십시오.
- 그리고 질문시에는 구체적으로 어떤 사실을 확인하려는지, 왜 그 사실이 위험도 판단에 중요한지를 설명하는 것을 권장드립니다.
- 추가 조사를 통해 확인된 근거는 risk_adjustment_reason에 명확히 기록
- 여러 사실을 한 번에 묻지 말고, 답변이 모호해질 수 있으면 질문을 더 잘게 나누십시오.
- 질문할때 한국어 번역어만 쓰지 말고, 보안 고유 표현은 원어/표현식도 함께 써라


Risk evaluation principles / 위험도 판단 원칙:
- base_cvss는 입력 payload의 cvss.score 가 있으면 그대로 사용하고, 없으면 null 로 두십시오.
- calculated_risk는 CRITICAL, HIGH, MEDIUM, LOW 중 하나만 사용하십시오.
- exposure_level은 Public 또는 Internal 중 하나만 사용하십시오.
- Public 판단에는 public_ip, metadata.network_exposure, metadata.subnet_route_type, metadata.internet_route_via_igw 를 함께 보십시오.
- Internal 자산이어도 metadata.internet_egress_via_nat 가 true 이거나 다른 outbound 경로가 확인되면 외부 endpoint와의 통신 가능성을 낮게 보지 마십시오.
- root 실행, 공인 노출, 공격자 제어 입력 도달성, 취약 설정 활성화, 외부 outbound 가능성은 위험 유지 또는 상향 근거입니다.
- Internal 이라는 이유만으로 기계적으로 위험을 낮추지 마십시오.
- 다른 공격 우회 루트 또는 병렬 악용 경로가 존재하면 위험도를 성급히 낮추지 말고 유지하십시오.
- risk_adjustment_reason에는 실제 확인된 근거만 쓰십시오. 
- 확인되지 않은 핵심 사실은 확인 불가 또는 unknown 으로 남기고, 그 불확실성을 risk_adjustment_reason에 적으십시오.

Output schema / 출력 스키마:
[
  {
    "cve_id": "CVE-XXXX-XXXXX",
    "title": "취약점 명칭",
    "impacted_assets": [
      {
        "instance_id": "i-xxxxxxxxxxxxxxxxx",
        "base_cvss": 10.0,
        "calculated_risk": "CRITICAL | HIGH | MEDIUM | LOW",
        "exposure_level": "Public | Internal",
        "risk_adjustment_reason": "실제 확인된 근거 기반 설명"
      }
    ]
  }
]

"""


def _risk_user_message(vuln_payload: dict, infra_context: dict, override_prompt: str = "") -> str:
    base = (
        "다음 두 개의 원본 JSON context를 그대로 읽고 위험도 평가를 수행하십시오.\n"
        "refined 요약을 상정하지 말고 원본 구조를 직접 참조하십시오.\n"
        "먼저 CVE별 후보 자산을 식별하고, 그다음 해당 후보 자산에 대해서만 위험도를 계산하십시오.\n\n"
        "[risk assessment payload context]\n"
        f"{json.dumps(vuln_payload, ensure_ascii=False, indent=2)}\n\n"
        "[infrastructure context]\n"
        f"{json.dumps(infra_context, ensure_ascii=False, indent=2)}\n"
    )
    if override_prompt.strip():
        base += f"\n[additional operator instruction]\n{override_prompt.strip()}\n"
    return base


def _extract_agent_text(result) -> str:
    try:
        content_blocks = result.message.get("content", [])
        for block in content_blocks:
            if isinstance(block, dict) and block.get("type") == "text":
                return str(block.get("text", "")).strip()
    except Exception:
        pass
    return str(result).strip()


def _normalize_risk_report_output(data):
    """최종 반환 스키마를 최소 필드로 고정한다."""
    if not isinstance(data, list):
        return data

    normalized = []
    for record in data:
        if not isinstance(record, dict):
            continue

        record_cve_id = str(record.get("cve_id") or "").strip()
        record_title = str(record.get("title") or "").strip()

        impacted_assets = []
        for asset in record.get("impacted_assets", []) or []:
            if not isinstance(asset, dict):
                continue
            asset_cve_id = str(asset.get("cve_id") or "").strip()
            asset_title = str(asset.get("title") or "").strip()
            if not record_cve_id and asset_cve_id:
                record_cve_id = asset_cve_id
            if not record_title and asset_title:
                record_title = asset_title
            impacted_assets.append({
                "instance_id": asset.get("instance_id", ""),
                "base_cvss": asset.get("base_cvss"),
                "calculated_risk": asset.get("calculated_risk", ""),
                "exposure_level": asset.get("exposure_level", ""),
                "risk_adjustment_reason": asset.get("risk_adjustment_reason", ""),
            })

        normalized.append({
            "cve_id": record_cve_id,
            "title": record_title,
            "impacted_assets": impacted_assets,
        })

    return normalized


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
    _runtime_state["query_log"] = []

    # 2) 입력 데이터 확보
    try:
        vuln_payload = _ensure_vulnerability_payload(payload)
        infra_context = _ensure_infra_context(payload)
    except RuntimeError as e:
        return {"error": str(e)}

    _runtime_state["infra_context"] = infra_context

    # 3) patch impact 스타일: system prompt + user message
    system_prompt = _risk_system_prompt()
    user_message = _risk_user_message(
        vuln_payload=vuln_payload,
        infra_context=infra_context,
        override_prompt=str(payload.get("prompt") or ""),
    )

    # 4) Agent 실행
    agent = Agent(
        model=_build_openai_model(),
        system_prompt=system_prompt,
        tools=[query_asset_details],
    )
    result = agent(user_message)

    query_log = _runtime_state.get("query_log", [])

    # 5) 텍스트 응답에서 JSON 추출 시도
    raw_text = _extract_agent_text(result)

    if "```" in raw_text:
        parts = raw_text.split("```")
        for part in parts:
            part = part.lstrip("json").strip()
            if part.startswith("[") or part.startswith("{"):
                raw_text = part
                break

    try:
        final_data = json.loads(raw_text)
        final_data = _normalize_risk_report_output(final_data)
        return json.dumps({"risk_report": final_data, "swarm_queries": query_log}, indent=4, ensure_ascii=False)
    except Exception:
        try:
            clean_text = re.sub(r"\s+", " ", raw_text)
            fixed_data = json.loads(clean_text)
            fixed_data = _normalize_risk_report_output(fixed_data)
            return json.dumps({"risk_report": fixed_data, "swarm_queries": query_log}, indent=4, ensure_ascii=False)
        except Exception:
            return f"JSON 파싱 실패. 원본 데이터: {raw_text[:500]}"


if __name__ == "__main__":
    app.run()
