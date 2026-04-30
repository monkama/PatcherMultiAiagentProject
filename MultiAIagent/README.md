# MultiAIagent — Patcher 취약점 위험도 평가 파이프라인

AWS Bedrock AgentCore Runtime 위에서 4개의 에이전트가 협력하여 CVE 취약점을 인프라 자산과 매핑하고 위험도를 자동으로 평가하는 멀티에이전트 시스템입니다.

---

## 전체 파이프라인

```
[Orchestrator]
      │
      ├── Step 0 ──▶ [vuln_collector_agent]
      │                    │
      │              ┌─────┴──────────────────┐
      │              │ cve_payload            │ (CVSS 상세, risk_eval용)
      │              │ asset_matching_payload │ (product/CPE, 자산매칭용)
      │              └─────┬──────────────────┘
      │
      ├── Step 1 ──▶ [Infra_matchingAgent]
      │                    │  asset_matching_payload 수신
      │                    │  → CloudFormation 태그로 VPC 탐색
      │                    │  → EC2 인스턴스 목록 수집
      │                    │  → installed_software / 네트워크 정보 구성
      │                    │
      │               infra_context 반환
      │
      └── Step 2 ──▶ [risk_evaluation_agent]
                          │  cve_payload + infra_context 수신
                          │  → 취약 소프트웨어 보유 tier 선별
                          │  → tier 대표 인스턴스에 combined query (1회/tier)
                          │  → 사전 수집 증거를 프롬프트에 주입
                          │  → Claude Sonnet으로 위험도 분석
                          │
                     risk_report 반환
```

---

## 에이전트 상세

### 1. vuln_collector_agent

**역할**: 미리 수집된 CVE 데이터를 두 가지 포맷으로 반환합니다.

| 출력                      | 파일                                    | 목적                                    |
|---------------------------|-----------------------------------------|-----------------------------------------|
| `cve_payload`             | `data/risk_assessment_payloads.json`    | risk_eval용 (CVSS 점수, 설명 포함)      |
| `asset_matching_payload`  | `data/asset_matching_payload.json`      | 자산매칭용 (product_name, cpe_criteria) |

**입력 페이로드**: `{}` (입력 없음)

**호출 예시**:
```json
{}
```

**응답**:
```json
{
  "cve_payload": { "records": [...] },
  "asset_matching_payload": { "records": [...] }
}
```

---

### 2. Infra_matchingAgent (asset_matching_agent)

**역할**: EC2 인프라 자산을 수집하고 CVE-자산 매핑 쿼리에 응답합니다.

**지원 모드**:

| mode | 설명 |
|------|------|
| `collect` | 단일 인스턴스 정보 수집 |
| `auto_discover` | VPC 내 전체 EC2 자동 탐색 |
| `query` | 기 수집된 자산에 대해 자연어 질의 |

**auto_discover 페이로드**:
```json
{
  "mode": "auto_discover",
  "cve_payload": { "records": [...] },
  "stack_name": "megathon",
  "region": "ap-northeast-2",
  "metadata": {
    "environment": "production",
    "business_criticality": "high"
  }
}
```

> `stack_name`을 주면 CloudFormation 태그(`aws:cloudformation:stack-name`, `aws:cloudformation:logical-id=VPC`)로 VPC를 자동 탐색합니다. `vpc_id`를 직접 지정할 수도 있습니다.

**query 페이로드**:
```json
{
  "mode": "query",
  "asset_info": { ... },
  "instance_id": "i-<INSTANCE_ID>",
  "question": "nginx가 root 권한으로 실행 중입니까?"
}
```

**응답**:
```json
{
  "answer": "...",
  "evidence": [...],
  "confidence": "high"
}
```

---

### 3. risk_evaluation_agent

**역할**: CVE + 인프라 자산 정보를 바탕으로 CRITICAL/HIGH/MEDIUM/LOW 위험도를 산정합니다.

**핵심 설계 — Pre-fetch 아키텍처**:

- LLM이 추론하기 전에 Python이 먼저 asset_matching 에이전트를 직접 호출하여 실측 증거를 수집합니다.
- 수집된 증거를 프롬프트에 주입하여 LLM이 추론 대신 실제 데이터를 기반으로 판단합니다.

**쿼리 최적화**:

- 취약 소프트웨어가 없는 tier는 쿼리를 완전히 스킵합니다.
- tier당 1회 combined query (mitigation 적용 여부 + root 실행 여부 + 공인 IP 여부를 단일 질문으로 묶음).
- 예시: nginx(web tier) + log4j(app tier) → 총 2회 쿼리, db tier는 스킵.

**위험도 조정 규칙**:

| 조건 | 조정 |
|------|------|
| mitigation 적용됨 | -2단계 |
| non-root 실행 | -1단계 |
| 내부망(Internal) | -1단계 |
| mitigation 미적용 + root + 인터넷 노출 | 기준점 유지 |

단계 순서: `CRITICAL → HIGH → MEDIUM → LOW`

**입력 페이로드**:
```json
{
  "vulnerability_payload": { "records": [...] },
  "infra_context": { "assets": [...], "vpc_id": "vpc-..." },
  "asset_matching_arn": "arn:aws:bedrock-agentcore:...",
  "region": "ap-northeast-2"
}
```

**응답**:
```json
{
  "risk_report": [
    {
      "cve_id": "CVE-2021-44228",
      "title": "Log4Shell",
      "impacted_assets": [
        {
          "instance_id": "i-<INSTANCE_ID>",
          "base_cvss": 10.0,
          "calculated_risk": "HIGH",
          "exposure_level": "Public",
          "mitigations_found": [],
          "risk_adjustment_reason": "mitigation 미적용, non-root 실행으로 1단계 하향",
          "remediation": "log4j 2.15.0 이상으로 업그레이드"
        }
      ]
    }
  ],
  "swarm_queries": 2
}
```

---

### 4. orchestrator_agent

**역할**: 전체 파이프라인을 순서대로 조율합니다. 각 에이전트를 순차 호출하고 결과를 연결합니다.

**입력 페이로드**:
```json
{
  "stack_name": "megathon",
  "region": "ap-northeast-2"
}
```

> `cve_payload` / `asset_matching_payload`를 직접 전달하면 Step 0(vuln_collector) 호출을 건너뜁니다.

**응답**:
```json
{
  "vpc_id": "vpc-<VPC_ID>",
  "infra_context": { ... },
  "risk_report": { ... }
}
```

**필수 환경변수**:

| 변수 | 설명 |
|------|------|
| `ASSET_MATCHING_ARN` | Infra_matchingAgent AgentCore ARN |
| `RISK_EVAL_ARN` | risk_evaluation_agent AgentCore ARN |
| `VULN_COLLECTOR_ARN` | vuln_collector_agent AgentCore ARN (선택) |
| `CF_STACK_NAME` | CloudFormation 스택 이름 (기본값: `megathon`) |
| `DEFAULT_REGION` | AWS 리전 (기본값: `ap-northeast-2`) |

---

## 디렉토리 구조

```
MultiAIagent/
├── README.md                          # 이 파일
├── vuln_collector_agent/
│   ├── runtime_app.py                 # AgentCore entrypoint
│   ├── main.py                        # 독립 실행용 수집 스크립트
│   ├── requirements.txt
│   └── data/
│       ├── risk_assessment_payloads.json   # risk_eval용 CVE 데이터
│       ├── asset_matching_payload.json     # 자산매칭용 CVE 데이터
│       ├── focused_selected_raw_cves.json  # 원본 CVE 데이터
│       └── operational_impact_payloads.json
├── Infra_matchingAgent/
│   ├── runtime_app.py                 # AgentCore entrypoint
│   ├── agent_extract_asset.py         # EC2 수집 + 쿼리 로직
│   ├── requirements.txt
│   └── README.md
├── risk_evaluation_agent/
│   ├── main.py                        # AgentCore entrypoint (Strands Agent)
│   ├── risk_assessment_refiner.py     # CVE 페이로드 정제
│   ├── infra_context_refiner.py       # 인프라 컨텍스트 정제
│   └── requirements.txt
└── orchestrator_agent/
    ├── main.py                        # AgentCore entrypoint
    └── requirements.txt
```

---

## 배포 방법

### 사전 요구사항

- Python 3.11+
- AWS CLI 설정 (`ap-northeast-2` 리전)
- `bedrock-agentcore-starter-toolkit` 설치
- AgentCore 배포 권한이 있는 IAM 역할

### 각 에이전트 배포

```bash
# 예: vuln_collector_agent
cd vuln_collector_agent
pip install -r requirements.txt
agentcore configure --entrypoint runtime_app.py --name vuln-collector-agent
agentcore deploy
```

각 에이전트 디렉토리에서 동일한 방식으로 배포합니다.

배포 후 각 에이전트의 ARN을 orchestrator_agent의 환경변수에 설정합니다:

```bash
export VULN_COLLECTOR_ARN="arn:aws:bedrock-agentcore:<REGION>:<AWS_ACCOUNT_ID>:runtime/<AGENT_ID>"
export ASSET_MATCHING_ARN="arn:aws:bedrock-agentcore:<REGION>:<AWS_ACCOUNT_ID>:runtime/<AGENT_ID>"
export RISK_EVAL_ARN="arn:aws:bedrock-agentcore:<REGION>:<AWS_ACCOUNT_ID>:runtime/<AGENT_ID>"
```

### E2E 실행

```bash
cd orchestrator_agent
agentcore invoke '{"stack_name": "megathon", "region": "ap-northeast-2"}'
```

---

## 로컬 테스트

각 에이전트를 로컬에서 실행하려면:

```bash
python runtime_app.py
# → localhost:8080/invocations 에서 대기

curl -X POST http://localhost:8080/invocations \
  -H "Content-Type: application/json" \
  -d '{"mode": "auto_discover", "stack_name": "megathon"}'
```

---

## IAM 권한 요구사항

각 에이전트의 Runtime IAM Role에 필요한 권한:

**vuln_collector_agent**: 권한 불필요 (정적 파일만 반환)

**Infra_matchingAgent**:

- `ec2:DescribeVpcs`
- `ec2:DescribeInstances`
- `ec2:DescribeSubnets`
- `ec2:DescribeSecurityGroups`
- `ssm:SendCommand`, `ssm:GetCommandInvocation`
- `bedrock:InvokeModel`

**risk_evaluation_agent**:

- `bedrock:InvokeModel`
- `bedrock-agentcore:InvokeAgentRuntime` (asset_matching_agent 호출용)

**orchestrator_agent**:

- `bedrock-agentcore:InvokeAgentRuntime` (모든 하위 에이전트 호출용)

---

## 설계 결정 사항

### 페이로드 포맷 분리

vuln_collector가 두 가지 다른 포맷의 CVE 데이터를 반환합니다:

- **asset_matching_payload**: `product_name`, `cpe_criteria` 중심 (소프트웨어 탐색에 최적화)
- **cve_payload**: CVSS 점수, 설명, 심각도 포함 (위험도 분석에 최적화)

### Pre-fetch 아키텍처

LLM이 실행되기 전에 Python 코드가 직접 asset_matching 에이전트를 호출하여 증거를 수집합니다. 이 방식은:

- LLM의 추론/환각을 방지합니다.
- 실제 인스턴스 데이터를 프롬프트에 주입합니다.
- 쿼리 횟수를 tier당 1회로 줄입니다.

### VPC 자동 탐색

CloudFormation 스택 태그(`aws:cloudformation:stack-name`, `aws:cloudformation:logical-id=VPC`)를 사용하여 VPC ID 없이 스택 이름만으로 인프라를 탐색합니다.

### 민감 정보 관리

ARN, 계정 ID, 인스턴스 ID 등 모든 민감 정보는 환경변수로만 관리합니다. `.bedrock_agentcore.yaml` 파일은 `.gitignore`에 의해 Git에서 제외됩니다.

---

## 대상 CVE

현재 데이터셋에 포함된 취약점:

| CVE ID | 소프트웨어 | CVSS | 설명 |
| --- | --- | --- | --- |
| CVE-2021-44228 | Apache Log4j 2 | 10.0 (Critical) | Log4Shell — JNDI 인젝션으로 원격 코드 실행 |
| CVE-2021-23017 | nginx | 7.7 (High) | DNS resolver 1-byte 메모리 오버라이트 |
