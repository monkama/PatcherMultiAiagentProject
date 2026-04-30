"""취약점 수집 에이전트 — AgentCore Runtime entrypoint.

미리 수집된 CVE 데이터를 두 가지 포맷으로 반환합니다.
  - cve_payload            : risk_assessment_payloads.json (위험도 평가용, CVSS 상세 포함)
  - asset_matching_payload : asset_matching_payload.json  (자산 매칭용, product_name/cpe_criteria 포함)

실무 수집 코드(main.py)는 별도 실행 가능하나 에이전트 호출 시에는 사용되지 않습니다.

호출 페이로드 스키마:
    {}  # 입력 불필요

응답:
    {
      "cve_payload":            <risk_assessment_payloads.json 형식의 dict>,
      "asset_matching_payload": <asset_matching_payload.json 형식의 dict>
    }
"""
import json
from pathlib import Path

from bedrock_agentcore import BedrockAgentCoreApp

AGENT_ROOT = Path(__file__).resolve().parent
CVE_PAYLOAD_PATH            = AGENT_ROOT / "data" / "risk_assessment_payloads.json"
ASSET_MATCHING_PAYLOAD_PATH = AGENT_ROOT / "data" / "asset_matching_payload.json"

app = BedrockAgentCoreApp()


@app.entrypoint
def invoke(payload):
    try:
        with open(CVE_PAYLOAD_PATH, encoding="utf-8") as f:
            cve_payload = json.load(f)
    except FileNotFoundError:
        return {"error": f"CVE 페이로드 파일 없음: {CVE_PAYLOAD_PATH}"}

    try:
        with open(ASSET_MATCHING_PAYLOAD_PATH, encoding="utf-8") as f:
            asset_matching_payload = json.load(f)
    except FileNotFoundError:
        return {"error": f"자산 매칭 페이로드 파일 없음: {ASSET_MATCHING_PAYLOAD_PATH}"}

    return {
        "cve_payload":            cve_payload,
        "asset_matching_payload": asset_matching_payload,
    }


if __name__ == "__main__":
    app.run()
