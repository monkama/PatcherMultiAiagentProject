from __future__ import annotations

import os

from bedrock_agentcore.runtime import BedrockAgentCoreApp

from vuln_collector_agent.main import run_vulnerability_collection

app = BedrockAgentCoreApp()


def _normalize_cve_ids(value: object) -> list[str] | None:
    if isinstance(value, str):
        items = [part.strip().upper() for part in value.split(",")]
        normalized = [item for item in items if item]
        return normalized or None
    if isinstance(value, list):
        normalized = [str(item).strip().upper() for item in value if str(item).strip()]
        return normalized or None
    return None


@app.entrypoint
def invoke(payload: dict | None) -> dict:
    payload = payload or {}

    opencve_api_key = str(payload.get("OPENCVE_API_KEY") or "").strip()
    bedrock_model_id = str(payload.get("BEDROCK_MODEL_ID") or "").strip()
    region = str(payload.get("region") or payload.get("AWS_REGION") or payload.get("AWS_DEFAULT_REGION") or "").strip()
    cve_ids = _normalize_cve_ids(payload.get("cve_ids") or payload.get("CVE_IDS") or payload.get("cve_id"))

    if opencve_api_key:
        os.environ["OPENCVE_API_KEY"] = opencve_api_key
    if bedrock_model_id:
        os.environ["BEDROCK_MODEL_ID"] = bedrock_model_id
    if region:
        os.environ["AWS_REGION"] = region
        os.environ["AWS_DEFAULT_REGION"] = region

    result = run_vulnerability_collection(
        cve_ids=cve_ids,
        save_outputs=False,
    )

    return {
        "cve_ids": cve_ids or ((result.get("raw_dataset") or {}).get("cve_ids") if isinstance(result.get("raw_dataset"), dict) else []),
        "raw_dataset": result.get("raw_dataset", {}),
        "risk_assessment_payload": result.get("risk_assessment_payload", {}),
        "operational_impact_payload": result.get("operational_impact_payload", {}),
        "asset_matching_payload": result.get("asset_matching_payload", {}),
    }


if __name__ == "__main__":
    app.run()
