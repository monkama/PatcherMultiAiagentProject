# MultiAIagent — 취약점 자동 위험도 평가 파이프라인

AWS 인프라의 CVE 취약점을 자동 수집하고, 실제 자산 런타임 상태를 실측해 CVSS 기반 위험도를 정밀 조정하는 Multi-Agent 보안 자동화 파이프라인입니다.

**기술 스택**: AWS Bedrock AgentCore Runtime · Strands Agent SDK · AWS EC2 / SSM / CloudFormation

---

## 전체 파이프라인 구조

팀원이 새 로컬 환경에서 실행할 때 필요한 `.env`, `.venv`, 배포 CLI 준비 절차는 [docs/team_setup.md](docs/team_setup.md)를 기준으로 맞춥니다.

현재 기본 흐름은 아래와 같습니다.

```text
vuln_collector -> asset_matching -> risk_evaluation -> patch_impact
```
사용자 호출: { "stack_name": "megathon" }
        │
        ▼
┌─────────────────────────────────────────┐
│           orchestrator_agent            │
│         파이프라인 총괄 / 라우팅         │
└─────────────────────────────────────────┘
        │
        │ Step 0
        ▼
┌─────────────────────────────────────────┐
│         vuln_collector_agent            │
│                                         │
│  data/risk_assessment_payloads.json     │──→ cve_payload (risk_eval 용)
│  data/asset_matching_payload.json       │──→ asset_matching_payload (자산매칭 용)
└─────────────────────────────────────────┘
        │
        │ Step 1  (asset_matching_payload 전달)
        ▼
┌─────────────────────────────────────────┐
│         asset_matching_agent            │
│                                         │
│  1. stack_name → CloudFormation 태그로  │
│     VPC ID 자동 탐색                    │
│  2. VPC 내 EC2 인스턴스 전수 수집       │
│  3. SSM으로 소프트웨어·네트워크·보안    │
│     컨텍스트 조회                       │
│                                         │
│  반환: infra_context                    │
└─────────────────────────────────────────┘
        │
        │ Step 2  (cve_payload + infra_context 전달)
        ▼
┌─────────────────────────────────────────┐
│        risk_evaluation_agent            │
│                                         │
│  1. CVE별 영향 후보 자산 식별          │
│  2. query_asset_details tool로          │
│     asset_matching_agent에 직접 질의    │
│  3. mitigation / root 권한 / 네트워크   │
│     노출 확인 후 CVSS 조정              │
│                                         │
│  반환: 위험도 리포트                    │
└─────────────────────────────────────────┘
```

---

## 디렉터리 구조

```
MultiAIagent/
├── orchestrator_agent/
│   ├── main.py                       # 파이프라인 총괄 entrypoint
│   ├── requirements.txt
│   └── .bedrock_agentcore.yaml
│
├── vuln_collector_agent/
│   ├── runtime_app.py                # AgentCore entrypoint
│   ├── main.py                       # 실무용 수집 로직 (현재 미사용)
│   ├── data/
│   │   ├── risk_assessment_payloads.json    # risk_eval 용 CVE 페이로드
│   │   ├── asset_matching_payload.json      # asset_matching 용 CVE 페이로드
│   │   ├── focused_selected_raw_cves.json   # 원본 CVE 원천 데이터
│   │   └── operational_impact_payloads.json
│   ├── tools/
│   │   ├── cve_fetcher.py            # OpenCVE API 조회
│   │   ├── cwe_fetcher.py            # MITRE CWE 조회
│   │   ├── evidence_fetcher.py       # NVD·어드바이저리 근거 수집
│   │   ├── payload_builder.py        # Strands + OpenAI로 최종 payload 생성
│   │   └── output_writer.py          # JSON 파일 저장
│   ├── prompts/                      # LLM 단계별 시스템 프롬프트
│   ├── requirements.txt
│   └── .bedrock_agentcore.yaml
│
├── Infra_matchingAgent/
│   ├── runtime_app.py                # AgentCore entrypoint, 3가지 모드
│   ├── agent_extract_asset.py        # EC2 수집·SSM 조회·LLM 질의 핵심 로직
│   ├── requirements.txt
│   └── .bedrock_agentcore.yaml
│
└── risk_evaluation_agent/
    ├── main.py                       # AgentCore entrypoint, pre-fetch 아키텍처
    ├── risk_assessment_refiner.py    # CVE 페이로드 정제
    ├── infra_context_refiner.py      # 자산 데이터 정제 (security_context 의도적 제외)
    ├── requirements.txt
    └── .bedrock_agentcore.yaml
```

---

## 에이전트 상세

### 1. vuln_collector_agent

**역할**: CVE 데이터를 두 가지 포맷으로 반환

취약점 수집의 진입점입니다. 실무에서는 `main.py`의 OpenCVE/OpenAI 파이프라인으로 실시간 수집하지만, 현재 데모에서는 미리 수집된 고정 데이터를 반환합니다. 중요한 점은 포맷이 두 종류라는 것으로, 각각 다운스트림 에이전트가 필요로 하는 구조가 다릅니다.

**두 페이로드 포맷 차이**:

| 구분 | 파일 | 수신처 | 주요 필드 |
|------|------|--------|-----------|
| `cve_payload` | `risk_assessment_payloads.json` | risk_evaluation_agent | `cvss.score`, `severity`, `vector_details` |
| `asset_matching_payload` | `asset_matching_payload.json` | asset_matching_agent | `product_name`, `affected_version_range`, `cpe_criteria` |

**반환 구조**:
```json
{
  "cve_payload": {
    "records": [
      {
        "cve_id": "CVE-2021-44228",
        "title": "Apache Log4j2 JNDI ...",
        "cvss": { "score": 10.0, "vector_details": { ... } },
        "severity": "critical",
        "security_domain": "remote-code-execution"
      }
    ]
  },
  "asset_matching_payload": {
    "records": [
      {
        "cve_id": "CVE-2021-44228",
        "product_name": "apache-log4j",
        "affected_version_range": [">=2.0.1 <2.3.1", ">=2.13.0 <2.15.0"],
        "fixed_version": "2.15.0",
        "cpe_criteria": ["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"]
      }
    ]
  }
}
```

**실무 수집 흐름** (`main.py`, 현재 미사용):
```
OpenCVE → CWE 결합 → LLM evidence gate 판단
  → (필요시) NVD·KEV 추가 근거 수집
  → (필요시) vendor advisory 상세 수집
  → Strands + OpenAI로 최종 payload 2종 생성
```

**ARN**: `arn:aws:bedrock-agentcore:<REGION>:<AWS_ACCOUNT_ID>:runtime/vuln_collector_agent-<AGENT_ID>`

---

### 2. asset_matching_agent (Infra_matchingAgent)

**역할**: CVE 페이로드 기반으로 AWS 인프라 자산 수집 및 추가 질의 응답

VPC 내 EC2 인스턴스를 자동 탐색하고, AWS SSM으로 각 인스턴스에 PEM 키 없이 접근해 소프트웨어·네트워크·보안 컨텍스트를 실측 수집합니다. 위험도 평가 에이전트가 추가 정보를 요청할 때 query 모드로 재호출됩니다.

**3가지 모드**:

| mode | 호출자 | 입력 | 출력 |
|------|--------|------|------|
| `auto_discover` | orchestrator | `stack_name` + `cve_payload` | `infra_context` (전체 자산) |
| `collect` | 직접 호출 | `instance_id` + `cve_payload` | `asset_info` (단일 인스턴스) |
| `query` | risk_evaluation_agent | `asset_info` + `question` | `answer` + `evidence` + `confidence` |

**VPC 자동 탐색 로직**:

CloudFormation 스택 태그를 사용해 `stack_name`만으로 VPC를 탐색합니다. 오케스트레이터는 VPC ID를 알 필요가 없습니다.

```python
ec2.describe_vpcs(Filters=[
    {"Name": "tag:aws:cloudformation:stack-name", "Values": [stack_name]},
    {"Name": "tag:aws:cloudformation:logical-id",  "Values": ["VPC"]},
    {"Name": "state", "Values": ["available"]},
])
```

**infra_context 출력 구조**:
```json
{
  "vpc_id": "vpc-<VPC_ID>",
  "region": "ap-northeast-2",
  "collected_at": "2026-05-01T00:00:00+00:00",
  "assets": [
    {
      "asset_id": "i-<INSTANCE_ID>",
      "hostname": "ip-10-0-x-x.ap-northeast-2.compute.internal",
      "tier": "web",
      "private_ip": "10.0.x.x",
      "public_ip": "x.x.x.x",
      "network_context": {
        "listening_ports": [22, 80],
        "is_internet_facing": true
      },
      "security_context": {
        "running_as_root": ["nginx"],
        "imds_v2_enforced": true
      },
      "installed_software": [
        {
          "product": "nginx",
          "version": "1.20.0",
          "cpe": "cpe:2.3:a:nginx:nginx:1.20.0:..."
        }
      ]
    }
  ],
  "reachability": [
    { "from": "web", "to": "app", "ports": [8080] },
    { "from": "app", "to": "db",  "ports": [3306] }
  ]
}
```

**티어 판정 우선순위**: EC2 태그(`Tier`, `Role`) → `Name` 패턴 → `unknown`

**서브넷 노출도 판정**: 라우트 테이블의 `0.0.0.0/0` 대상이 IGW → `public`, NAT → `private`, 없음 → `isolated`

**안전 장치**:
- `rm`, `kill`, `reboot` 등 파괴적 명령어 정규식 차단
- tool 응답 2000자 truncation
- 최대 40턴 제한
- Bedrock ThrottlingException 지수 백오프 재시도

**ARN**: `arn:aws:bedrock-agentcore:<REGION>:<AWS_ACCOUNT_ID>:runtime/asset_matching_agent-<AGENT_ID>`

---

### 3. risk_evaluation_agent

**역할**: CVE + infra_context를 받아 실제 인스턴스 상태를 검증하고 CVSS 점수를 조정해 최종 위험도 리포트 생성

위험도를 단순히 CVSS 원본 점수로 출력하지 않고, 실제 인프라의 mitigation 적용 여부·프로세스 실행 권한·네트워크 노출을 실측해 점수를 조정합니다.

**핵심 아키텍처 — pre-fetch 방식**:

LLM에게 "부족하면 도구를 써라"고 맡기면 CVE 학습 지식만으로 추론해버려 실제 조사를 하지 않습니다. 대신 Python이 LLM 실행 전에 직접 asset_matching에 질의하고, 실측 데이터를 프롬프트에 주입합니다. LLM은 조정 규칙 적용만 담당합니다.

**`_prefetch_evidence()` 동작**:

```
tier별 대표 인스턴스 1개 선정 (web, app, db)
    │
    ├── installed_software × _CVE_AFFECTED_SOFTWARE 대조
    │       nginx  →  CVE-2021-23017  →  web tier 조사 대상
    │       log4j  →  CVE-2021-44228  →  app tier 조사 대상
    │       db tier → 해당 소프트웨어 없음 → 스킵
    │
    └── 관련 tier에 combined query 1회 전송:
            [1] CVE별 mitigation 적용 여부
            [2] 취약 프로세스가 root(UID 0) 실행 중인가?
            [3] public IP / public subnet 위치인가?

결과: 2회 호출 (web 1회 + app 1회)
```

**위험도 조정 규칙**:

| 조건 | 조정 | 예시 |
|------|------|------|
| mitigation 적용 확인 | -2단계 | `log4j2.formatMsgNoLookups=true` 설정 확인 시 |
| non-root 실행 확인 | -1단계 | nginx worker가 nobody 계정으로 실행 시 |
| Internal 네트워크 | -1단계 | private subnet, public IP 없음 |
| 위 조건 없음 | 기준 유지 | mitigation 미적용 + root + 인터넷 노출 |

단계 순서: `CRITICAL → HIGH → MEDIUM → LOW`

**infra_context_refiner 설계 의도**:

`infra_context_refiner.py`는 `security_context`와 `network_context`를 의도적으로 제외하고 LLM에 전달합니다. LLM이 이미 있는 데이터로 추론하지 않고, 반드시 asset_matching에 실측 질의를 하도록 유도하기 위한 설계입니다.

**위험도 리포트 출력 구조**:
```json
[
  {
    "cve_id": "CVE-2021-44228",
    "title": "Apache Log4j2 JNDI ...",
    "impacted_assets": [
      {
        "instance_id": "i-<INSTANCE_ID>",
        "base_cvss": 10.0,
        "calculated_risk": "HIGH",
        "exposure_level": "Internal",
        "mitigations_found": [],
        "risk_adjustment_reason": "mitigation 미적용 + java root 실행 + Internal(-1단계) → CRITICAL→HIGH",
        "remediation": "log4j를 2.17.1 이상으로 즉시 업그레이드..."
      }
    ]
  }
]
```

**ARN**: `arn:aws:bedrock-agentcore:<REGION>:<AWS_ACCOUNT_ID>:runtime/risk_evaluation_agent-<AGENT_ID>`

---

### 4. orchestrator_agent

**역할**: 4개 에이전트를 순서대로 호출해 전체 파이프라인을 관리

각 에이전트의 입출력 포맷을 알고 페이로드를 올바른 에이전트에 라우팅합니다.

**페이로드 흐름**:

```python
# Step 0 — vuln_collector 호출 (입력 없음)
vc_result = invoke(VULN_COLLECTOR_ARN, {})
cve_payload            = vc_result["cve_payload"]            # risk_eval 용
asset_matching_payload = vc_result["asset_matching_payload"] # asset_matching 용

# Step 1 — asset_matching 호출 (asset_matching_payload 전달)
am_result = invoke(ASSET_MATCHING_ARN, {
    "mode":       "auto_discover",
    "cve_payload": asset_matching_payload,   # product_name/cpe 포맷
    "stack_name": "megathon",                # vpc_id 불필요, 에이전트가 직접 탐색
    "region":     region,
    "metadata": {
        "environment": "production",
        "business_criticality": "high",
    },
})
infra_context = am_result["infra_context"]

# Step 2 — risk_eval 호출 (cve_payload + infra_context 전달)
re_result = invoke(RISK_EVAL_ARN, {
    "vulnerability_payload": cve_payload,    # CVSS 상세 포맷
    "infra_context":         infra_context,
    "asset_matching_arn":    ASSET_MATCHING_ARN,
    "region":                region,
})
```

**ARN**: `arn:aws:bedrock-agentcore:<REGION>:<AWS_ACCOUNT_ID>:runtime/orchestrator_agent-<AGENT_ID>`

---

## 데모 인프라 구성 (3-Tier)

```
                  Internet
                     │
        ┌────────────▼────────────┐
        │   Public Subnet         │
        │   Web-01, Web-02        │  nginx 1.20.0  (CVE-2021-23017 취약)
        └────────────┬────────────┘
                     │ :8080
        ┌────────────▼────────────┐
        │   Private Subnet (NAT)  │
        │   App-01, App-02        │  log4j 2.14.1  (CVE-2021-44228 취약)
        └────────────┬────────────┘
                     │ :3306
        ┌────────────▼────────────┐
        │   Private Subnet        │
        │   DB                    │  MySQL (취약 소프트웨어 없음)
        └─────────────────────────┘
```

---

## 호출 방법

### E2E 파이프라인 실행

```python
import json, boto3
from botocore.config import Config

client = boto3.client(
    "bedrock-agentcore",
    region_name="ap-northeast-2",
    config=Config(read_timeout=600, connect_timeout=10),
)

resp = client.invoke_agent_runtime(
    agentRuntimeArn="arn:aws:bedrock-agentcore:<REGION>:<AWS_ACCOUNT_ID>:runtime/orchestrator_agent-<AGENT_ID>",
    payload=json.dumps({
        "stack_name": "megathon",
        "region": "ap-northeast-2",
    }).encode(),
)

result = json.loads(resp["response"].read())
print(json.dumps(result["risk_report"], indent=2, ensure_ascii=False))
```

### 에이전트 개별 호출

**vuln_collector** (입력 없음):
```bash
agentcore invoke '{}'
```

**asset_matching** (auto_discover 모드):
```bash
agentcore invoke '{
  "mode": "auto_discover",
  "cve_payload": { "records": [...] },
  "stack_name": "megathon"
}'
```

**asset_matching** (query 모드 — risk_eval이 재질의 시):
```bash
agentcore invoke '{
  "mode": "query",
  "asset_info": { ... },
  "question": "log4j JndiLookup mitigation 적용 여부?"
}'
```

---

## 배포 가이드

### 사전 준비

```bash
# Python venv 생성 및 의존성 설치
python3 -m venv .venv
source .venv/bin/activate
pip install bedrock-agentcore-starter-toolkit bedrock-agentcore boto3

# uv 설치 (direct_code_deploy 필수)
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.local/bin/env
```

### 에이전트 배포 순서

의존 관계가 없으므로 병렬 배포 가능합니다.

```bash
# vuln_collector_agent
cd vuln_collector_agent
source .venv/bin/activate && PATH="$HOME/.local/bin:$PATH" agentcore deploy

# Infra_matchingAgent
cd Infra_matchingAgent
source .venv/bin/activate && PATH="$HOME/.local/bin:$PATH" agentcore deploy

# risk_evaluation_agent
cd risk_evaluation_agent
source .venv/bin/activate && PATH="$HOME/.local/bin:$PATH" agentcore deploy

# orchestrator_agent (마지막에 배포, 나머지 ARN이 확정된 후)
cd orchestrator_agent
source .venv/bin/activate && PATH="$HOME/.local/bin:$PATH" agentcore deploy
```

### 로그 확인

```bash
aws logs tail /aws/bedrock-agentcore/runtimes/<AGENT_ID>-DEFAULT \
  --log-stream-name-prefix "YYYY/MM/DD/[runtime-logs" --since 1h
```

---

## IAM 역할 구성

### orchestrator_agent — `OrchestratorAgentCoreRole`

```json
{
  "Action": [
    "bedrock-agentcore:InvokeAgentRuntime",
    "bedrock:InvokeModel",
    "bedrock:Converse"
  ]
}
```

### asset_matching_agent — `AssetMatchingAgentCoreRole`

```json
{
  "Action": [
    "bedrock:InvokeModel",
    "bedrock:Converse",
    "ssm:SendCommand",
    "ssm:GetCommandInvocation",
    "ssm:ListCommandInvocations",
    "ec2:DescribeInstances",
    "ec2:DescribeVpcs",
    "ec2:DescribeSubnets",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeRouteTables"
  ]
}
```

### risk_evaluation_agent — `RiskEvaluationAgentCoreRole`

```json
{
  "Action": [
    "bedrock:InvokeModel",
    "bedrock:Converse",
    "bedrock-agentcore:InvokeAgentRuntime"
  ]
}
```

### EC2 인스턴스 측

각 EC2에 `AmazonSSMManagedInstanceCore` 정책이 연결된 Instance Profile 필요.  
데모 인프라: `<YOUR_STACK_NAME>-SSMInstanceProfile-<PROFILE_ID>`

---

## 검증된 E2E 테스트 결과

**입력**: `{ "stack_name": "megathon" }`

**asset_matching 호출 횟수 (swarm_queries)**: 2회
- web tier 대표 인스턴스 (nginx CVE) → 1회
- app tier 대표 인스턴스 (log4j CVE) → 1회
- db tier → 해당 소프트웨어 없음 → 스킵

**최종 위험도**:

| CVE | 소프트웨어 | base CVSS | 조정 결과 | 조정 근거 |
|-----|-----------|-----------|-----------|-----------|
| CVE-2021-23017 | nginx 1.20.0 | 7.7 (HIGH) | **HIGH** | resolver 활성화(mitigation 미적용) + nginx master root + Public IP → 기준 유지 |
| CVE-2021-44228 | log4j 2.14.1 | 10.0 (CRITICAL) | **HIGH** | JndiLookup 존재(mitigation 미적용) + java root 실행 + Internal(-1단계) → CRITICAL→HIGH |

---

## 주요 설계 결정

### 두 CVE 페이로드 포맷 분리

vuln_collector는 `cve_payload`(CVSS 상세)와 `asset_matching_payload`(product_name/cpe)를 별도로 반환합니다. asset_matching은 어떤 소프트웨어를 찾아야 하는지(product_name, cpe_criteria)가 필요하고, risk_eval은 점수를 조정하기 위한 base CVSS와 severity가 필요합니다. 하나의 포맷으로 합치면 두 에이전트 모두 불필요한 필드를 처리해야 합니다.

### VPC 탐색 책임 분리

VPC 탐색 로직은 orchestrator가 아닌 asset_matching이 담당합니다. orchestrator는 `stack_name`만 알면 되고, "스택에서 VPC를 어떻게 찾는가"는 asset_matching의 내부 관심사입니다.

### pre-fetch 아키텍처

LLM에게 "부족하면 도구를 써라"는 방식은 LLM이 CVE 사전 지식으로 추론해버려 실제 조사를 생략합니다. Python이 LLM 실행 전에 직접 질의하고 결과를 프롬프트에 주입하는 방식이 더 신뢰할 수 있는 근거를 보장합니다.

### infra_context_refiner의 의도적 필드 제외

`security_context`와 `network_context`를 LLM에게 주지 않는 이유는, 이 데이터가 있으면 LLM이 "이미 알고 있다"고 판단해 asset_matching에 재질의하지 않기 때문입니다. 핵심 판단 데이터는 반드시 실측 질의를 통해 가져오도록 설계했습니다.

### tier당 1회 combined query

mitigation, root 권한, 네트워크 노출을 각각 별도 질의하면 tier × 4 = 12회 호출이 발생합니다. 세 가지를 하나의 질문으로 묶고, 취약 소프트웨어가 없는 tier를 스킵해 2회로 줄였습니다.

---

## 팀원 실행 가이드

### 방법 A — 이미 배포된 에이전트 사용 (가장 빠름)

팀원에게 `orchestrator_agent` ARN 하나만 받아서 바로 호출할 수 있습니다.

#### 1. 의존성 설치

```bash
cd orchestrator_agent
python3 -m venv .venv
source .venv/bin/activate
pip install boto3
```

#### 2. AWS 자격증명 설정

```bash
aws configure
# 또는
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=ap-northeast-2
```

> 필요한 IAM 권한: `bedrock-agentcore:InvokeAgentRuntime`

#### 3. 파이프라인 실행

```python
import json, boto3
from botocore.config import Config

# 팀원에게 받은 ARN으로 교체
ORCHESTRATOR_ARN = "arn:aws:bedrock-agentcore:<REGION>:<AWS_ACCOUNT_ID>:runtime/orchestrator_agent-<AGENT_ID>"

client = boto3.client(
    "bedrock-agentcore",
    region_name="ap-northeast-2",
    config=Config(read_timeout=600, connect_timeout=10),
)

resp = client.invoke_agent_runtime(
    agentRuntimeArn=ORCHESTRATOR_ARN,
    payload=json.dumps({
        "stack_name": "megathon",
        "region": "ap-northeast-2",
    }).encode(),
)

result = json.loads(resp["response"].read())
print(json.dumps(result["risk_report"], indent=2, ensure_ascii=False))
```

---

### 방법 B — 본인 AWS 계정에 직접 배포

공유받은 ARN 대신 본인 계정에 에이전트를 직접 배포하는 방법입니다.

#### 1. 사전 준비

```bash
# uv 설치 (direct_code_deploy 필수)
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.local/bin/env

# agentcore CLI 설치
pip install bedrock-agentcore-starter-toolkit
```

#### 2. 각 에이전트 폴더에 `.bedrock_agentcore.yaml` 생성

`.bedrock_agentcore.yaml`은 보안상 git에 포함되지 않습니다. 각 에이전트 폴더에서 아래 명령어를 실행하면 본인 계정 기준으로 자동 생성됩니다.

```bash
cd vuln_collector_agent && agentcore configure --name vuln_collector_agent --entrypoint runtime_app.py
cd Infra_matchingAgent  && agentcore configure --name asset_matching_agent  --entrypoint runtime_app.py
cd risk_evaluation_agent && agentcore configure --name risk_evaluation_agent --entrypoint main.py
cd orchestrator_agent   && agentcore configure --name orchestrator_agent    --entrypoint main.py
```

#### 3. IAM 역할 준비

각 에이전트에 필요한 IAM 역할을 생성하고 `.bedrock_agentcore.yaml`의 `execution_role`에 ARN을 입력합니다. 필요한 권한은 위 [IAM 역할 구성](#iam-역할-구성) 섹션을 참고하세요.

#### 4. 에이전트 순서대로 배포

```bash
# 1~3번은 순서 무관, 병렬 가능
cd vuln_collector_agent  && source .venv/bin/activate && PATH="$HOME/.local/bin:$PATH" agentcore deploy
cd Infra_matchingAgent   && source .venv/bin/activate && PATH="$HOME/.local/bin:$PATH" agentcore deploy
cd risk_evaluation_agent && source .venv/bin/activate && PATH="$HOME/.local/bin:$PATH" agentcore deploy

# orchestrator는 나머지 3개 ARN 확정 후 배포
cd orchestrator_agent && source .venv/bin/activate && PATH="$HOME/.local/bin:$PATH" agentcore deploy
```

#### 5. orchestrator에 나머지 ARN 등록

배포 완료 후 발급된 ARN을 `orchestrator_agent/main.py`의 환경변수 기본값에 입력합니다.

```python
VULN_COLLECTOR_ARN = os.environ.get("VULN_COLLECTOR_ARN", "<배포 후 발급된 ARN>")
ASSET_MATCHING_ARN = os.environ.get("ASSET_MATCHING_ARN", "<배포 후 발급된 ARN>")
RISK_EVAL_ARN      = os.environ.get("RISK_EVAL_ARN",      "<배포 후 발급된 ARN>")
```

또는 환경변수로 주입:

```bash
export VULN_COLLECTOR_ARN=arn:aws:bedrock-agentcore:...
export ASSET_MATCHING_ARN=arn:aws:bedrock-agentcore:...
export RISK_EVAL_ARN=arn:aws:bedrock-agentcore:...
```

#### 6. orchestrator 재배포 후 실행

```bash
cd orchestrator_agent && PATH="$HOME/.local/bin:$PATH" agentcore deploy
agentcore invoke '{"stack_name": "megathon", "region": "ap-northeast-2"}'
```

---

### 공통 주의사항

- 전체 파이프라인 실행 시간은 약 **5~10분**입니다 (SSM 수집 + LLM 호출 포함).
- EC2 인스턴스에 **SSM Agent가 설치**되어 있고 Instance Profile에 `AmazonSSMManagedInstanceCore` 정책이 연결되어 있어야 합니다.
- 리전은 `ap-northeast-2` (서울) 기준입니다. 다른 리전 사용 시 `region` 파라미터와 ARN의 리전을 함께 변경해야 합니다.
- `bedrock-agentcore` boto3 클라이언트는 타임아웃을 넉넉히 설정해야 합니다 (`read_timeout=600`).
