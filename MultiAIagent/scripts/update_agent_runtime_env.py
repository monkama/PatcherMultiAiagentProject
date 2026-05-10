#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ENV_PATH = ROOT / ".env"

AGENT_ENV_MAP = {
    "orchestrator": "ORCHESTRATOR_AGENTCORE_ARN",
    "vuln": "VULN_COLLECTOR_AGENTCORE_ARN",
    "vuln_collector": "VULN_COLLECTOR_AGENTCORE_ARN",
    "infra": "INFRA_MATCHING_AGENTCORE_ARN",
    "asset": "INFRA_MATCHING_AGENTCORE_ARN",
    "asset_matching": "INFRA_MATCHING_AGENTCORE_ARN",
    "risk": "RISK_EVAL_AGENTCORE_ARN",
    "risk_evaluation": "RISK_EVAL_AGENTCORE_ARN",
    "patch_impact": "PATCH_IMPACT_AGENTCORE_ARN",
    "patchimpact": "PATCH_IMPACT_AGENTCORE_ARN",
    "patch_exec": "PATCH_EXECUTION_AGENTCORE_ARN",
    "patchexec": "PATCH_EXECUTION_AGENTCORE_ARN",
    "patch_execution": "PATCH_EXECUTION_AGENTCORE_ARN",
}

ARN_RE = re.compile(
    r"^arn:aws:bedrock-agentcore:(?P<region>[^:]+):(?P<account>\d{12}):runtime/(?P<runtime>.+)$"
)


def _normalize_agent(agent: str) -> str:
    key = agent.strip().lower().replace("-", "_").replace(" ", "_")
    if key not in AGENT_ENV_MAP:
        raise SystemExit(f"지원하지 않는 agent 이름입니다: {agent}")
    return key


def _load_env_lines() -> list[str]:
    if not ENV_PATH.exists():
        return []
    return ENV_PATH.read_text(encoding="utf-8").splitlines()


def _upsert(lines: list[str], key: str, value: str) -> list[str]:
    new_line = f'{key}="{value}"'
    prefix = f"{key}="
    replaced = False
    updated: list[str] = []
    for line in lines:
        if line.strip().startswith(prefix):
            updated.append(new_line)
            replaced = True
        else:
            updated.append(line)
    if not replaced:
        updated.append(new_line)
    return updated


def main() -> None:
    parser = argparse.ArgumentParser(description="AgentCore runtime ARN을 .env에 반영합니다.")
    parser.add_argument("--agent", required=True, help="orchestrator, vuln, infra, risk, patch_impact, patch_exec")
    parser.add_argument("--arn", required=True, help="AgentCore runtime ARN")
    args = parser.parse_args()

    agent_key = _normalize_agent(args.agent)
    match = ARN_RE.match(args.arn.strip())
    if not match:
        raise SystemExit("유효한 AgentCore runtime ARN 형식이 아닙니다.")

    env_key = AGENT_ENV_MAP[agent_key]
    lines = _load_env_lines()
    lines = _upsert(lines, env_key, args.arn.strip())
    lines = _upsert(lines, "AWS_ACCOUNT_ID", match.group("account"))
    lines = _upsert(lines, "AWS_DEFAULT_REGION", match.group("region"))
    ENV_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"updated {env_key}")
    print(f"updated AWS_ACCOUNT_ID={match.group('account')}")
    print(f"updated AWS_DEFAULT_REGION={match.group('region')}")


if __name__ == "__main__":
    main()
