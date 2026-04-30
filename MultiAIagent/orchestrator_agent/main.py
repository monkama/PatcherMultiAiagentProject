"""오케스트레이터 에이전트 — AgentCore Runtime entrypoint.

전체 파이프라인 관리:
  Step 0: vuln_collector_agent  → cve_payload + asset_matching_payload
  Step 1: asset_matching_agent  → VPC 탐색 + EC2 수집 → infra_context
  Step 2: risk_evaluation_agent → CVE + infra_context → 위험도 리포트

호출 페이로드 스키마:
    {
      "stack_name": "megathon",      # 선택, 기본값 megathon
      "region":     "ap-northeast-2" # 선택
    }
"""
import json
import os

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from bedrock_agentcore import BedrockAgentCoreApp

# ---------------------------------------------------------------------------
# 설정
# ---------------------------------------------------------------------------

DEFAULT_REGION     = os.environ.get("DEFAULT_REGION", "ap-northeast-2")
DEFAULT_STACK_NAME = os.environ.get("CF_STACK_NAME", "megathon")

VULN_COLLECTOR_ARN = os.environ.get("VULN_COLLECTOR_ARN")
ASSET_MATCHING_ARN = os.environ.get("ASSET_MATCHING_ARN")
RISK_EVAL_ARN      = os.environ.get("RISK_EVAL_ARN")

app = BedrockAgentCoreApp()

# ---------------------------------------------------------------------------
# 클라이언트 헬퍼
# ---------------------------------------------------------------------------

_clients: dict = {}

def _client(service: str, region: str):
    key = (service, region)
    if key not in _clients:
        cfg = Config(read_timeout=600, connect_timeout=10) if service == "bedrock-agentcore" else None
        _clients[key] = boto3.client(service, region_name=region, config=cfg)
    return _clients[key]


# ---------------------------------------------------------------------------
# 에이전트 호출 헬퍼
# ---------------------------------------------------------------------------

def _invoke(arn: str, payload: dict, region: str) -> dict:
    """AgentCore 런타임 호출 후 JSON 파싱해서 반환."""
    client = _client("bedrock-agentcore", region)
    try:
        resp = client.invoke_agent_runtime(
            agentRuntimeArn=arn,
            payload=json.dumps(payload).encode("utf-8"),
        )
    except ClientError as e:
        raise RuntimeError(f"AgentCore 호출 실패 ({arn.split('/')[-1]}): {e}")

    raw = resp["response"].read()
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, str):
            parsed = json.loads(parsed)
        return parsed
    except json.JSONDecodeError:
        return {"raw": raw.decode("utf-8", errors="replace")}


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

@app.entrypoint
def invoke(payload):
    payload = payload or {}
    region     = payload.get("region", DEFAULT_REGION)
    stack_name = payload.get("stack_name", DEFAULT_STACK_NAME)

    if not ASSET_MATCHING_ARN or not RISK_EVAL_ARN:
        return {"error": "환경변수 ASSET_MATCHING_ARN, RISK_EVAL_ARN 이 설정되지 않았습니다."}

    cve_payload            = payload.get("cve_payload") or payload.get("vulnerability_payload")
    asset_matching_payload = payload.get("asset_matching_payload")

    # ── Step 0. vuln_collector_agent ──────────────────────────────────────
    if VULN_COLLECTOR_ARN and not cve_payload:
        print("[Orchestrator] Step 0: vuln_collector_agent 호출")
        try:
            vc_result = _invoke(VULN_COLLECTOR_ARN, {}, region)
        except RuntimeError as e:
            return {"error": str(e)}
        if "error" in vc_result:
            return {"error": f"vuln_collector 실패: {vc_result['error']}"}
        cve_payload            = vc_result.get("cve_payload")
        asset_matching_payload = vc_result.get("asset_matching_payload")
        print(f"[Orchestrator] CVE payload 수신: {len((cve_payload or {}).get('records', []))}건")
        print(f"[Orchestrator] asset_matching payload 수신: {len((asset_matching_payload or {}).get('records', []))}건")

    if not cve_payload:
        return {"error": "cve_payload 가 필요합니다. VULN_COLLECTOR_ARN 을 설정하거나 payload 에 직접 전달하세요."}
    if not asset_matching_payload:
        return {"error": "asset_matching_payload 가 필요합니다. VULN_COLLECTOR_ARN 을 설정하거나 payload 에 직접 전달하세요."}

    # ── Step 1. asset_matching — VPC 탐색 + EC2 수집 ─────────────────────
    print(f"[Orchestrator] Step 1: asset_matching 호출 (stack={stack_name})")
    am_payload = {
        "mode":        "auto_discover",
        "cve_payload":  asset_matching_payload,
        "stack_name":   stack_name,
        "region":       region,
        "metadata": {
            "environment":          "production",
            "business_criticality": "high",
        },
    }
    try:
        am_result = _invoke(ASSET_MATCHING_ARN, am_payload, region)
    except RuntimeError as e:
        return {"error": str(e)}

    if "error" in am_result:
        return {"error": f"asset_matching 실패: {am_result['error']}"}

    infra_context = am_result.get("infra_context") or am_result
    print(f"[Orchestrator] infra_context 수신: 자산 {len(infra_context.get('assets', []))}개")

    # ── Step 2. risk_eval ─────────────────────────────────────────────────
    print("[Orchestrator] Step 2: risk_eval 호출")
    re_payload = {
        "vulnerability_payload": cve_payload,
        "infra_context":         infra_context,
        "asset_matching_arn":    ASSET_MATCHING_ARN,
        "region":                region,
    }
    try:
        re_result = _invoke(RISK_EVAL_ARN, re_payload, region)
    except RuntimeError as e:
        return {"error": str(e)}

    print("[Orchestrator] 파이프라인 완료")

    return {
        "vpc_id":        infra_context.get("vpc_id", ""),
        "infra_context": infra_context,
        "risk_report":   re_result,
    }


if __name__ == "__main__":
    app.run()
