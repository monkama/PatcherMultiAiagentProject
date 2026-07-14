# PatcherAgents

AWS Bedrock AgentCore 위에서 여러 보안 에이전트를 연결해, 취약점 수집부터 자산 조사, 위험도 평가, 패치 전략 판단, 최종 패치 실행까지 이어지는 멀티 에이전트 파이프라인입니다.

현재 저장소의 중심은 `MultiAIagent/` 이고, 실제 로컬 실행은 보통 `MultiAIagent/run_orchestrator_runtime.py`로 시작합니다.

## 현재 파이프라인

현재 기본 흐름은 아래와 같습니다.

```text
vuln_collector -> asset_matching -> risk_evaluation -> patch_impact -> patch_exec
```

각 단계 역할은 이렇습니다.

- `vuln_collector`
  CVE를 수집하고 다음 단계에서 바로 쓸 수 있는 payload를 만듭니다.
- `asset_matching`
  현재 스택/인프라에서 어떤 자산이 영향을 받는지 수집하고, 필요 시 개별 질문에 대한 direct fact를 다시 확인합니다.
- `risk_evaluation`
  취약점과 자산 컨텍스트를 합쳐 위험도를 계산합니다.
- `patch_impact`
  위험도 기반으로 패치 전략을 판단하고, 정보가 부족하면 asset agent에 직접 기술 사실을 물어 최종 조치를 정합니다.
- `patch_exec`
  선택된 조치를 실제 실행 단계로 넘기거나 실행 결과를 정리합니다.

현재 오케스트라는 이 단계를 순서대로 이어주는 얇은 실행 허브입니다.

## 실행 환경과 모델 정책

현재 로컬 실행과 배포 스크립트가 기본으로 참조하는 환경변수 파일은 아래 하나입니다.

- [\.env](/Users/jms/Desktop/project/PacherAgents/.env)

즉 `MultiAIagent/` 내부 별도 `.env`를 두는 전제가 아니라, **프로젝트 루트 `.env`**를 기준으로 맞추는 것이 현재 기준입니다.

최소한 아래 값들은 루트 `.env`에 있어야 합니다.

- `OPENCVE_API_KEY`
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_DEFAULT_REGION`
- 각 AgentCore runtime ARN 관련 변수

중요:

- 현재 멀티 에이전트 실습 경로는 **Amazon Bedrock 기반**으로 맞춰져 있습니다.

## 개념 파이프라인 예시

사용자 호출을 아주 단순화해서 보면 아래처럼 이해할 수 있습니다.

```text
사용자 호출 예시: { "stack_name": "megathon" }
  - mode 생략 시 기본값은 full
  - region 생략 시 기본값은 ap-northeast-2

        │
        ▼
┌─────────────────────────────────────────┐
│           orchestrator_agent            │
│        파이프라인 총괄 / 라우팅          │
└─────────────────────────────────────────┘
        │
        │ Step 0: orchestrator가 vuln 호출
        ▼
┌─────────────────────────────────────────┐
│         vuln_collector_agent            │
│                                         │
│  반환:                                  │
│  - raw_dataset                          │
│  - risk_assessment_payload              │──→ risk 평가용
│  - operational_impact_payload           │──→ patch 판단용
│  - asset_matching_payload               │──→ 자산 수집용
└─────────────────────────────────────────┘
        │
        │ Step 1: orchestrator가
        │         asset_matching_payload를 받아
        │         asset stage 입력으로 전달
        ▼
┌─────────────────────────────────────────┐
│         infra_matching_agent            │
│                                         │
│  1. stack_name 기준으로 인프라 대상 탐색 │
│  2. EC2 / 네트워크 / 보안 정보 수집      │
│  3. SSM으로 소프트웨어/설정 정보 조회    │
│                                         │
│  반환: infra_context                    │
└─────────────────────────────────────────┘
        │
        │ Step 2: orchestrator가
        │         risk_assessment_payload + infra_context를 묶어
        │         risk stage 입력으로 전달
        ▼
┌─────────────────────────────────────────┐
│        risk_evaluation_agent            │
│                                         │
│  1. 취약점 payload와 자산 컨텍스트 결합  │
│  2. 운영/노출/권한 조건 반영             │
│  3. 위험도 산정                         │
│                                         │
│  반환: risk_result                      │
└─────────────────────────────────────────┘
        │
        │ Step 3: orchestrator가
        │         operational_payload + infra_context + risk_result를 묶어
        │         patch stage 입력으로 전달
        ▼
┌─────────────────────────────────────────┐
│         patch_impact_agent              │
│                                         │
│  1. risk를 시작점으로 기본 patch 전략 수립│
│  2. infra + operational로 필드 직접 채움 │
│  3. 부족한 direct fact만 asset에 질문    │
│  4. 최종 patch strategy 결과 생성       │
│                                         │
│  반환: patch_strategy_result            │
└─────────────────────────────────────────┘
        │
        │ Step 4: orchestrator가
        │         patch strategy 결과를 patch execution에 전달
        ▼
┌─────────────────────────────────────────┐
│          patch_exec_agent               │
│                                         │
│  1. 선택된 조치 기준 실행 단계 구성      │
│  2. 실행 또는 실행 계획 정리             │
│                                         │
│  반환: patch_execution_result           │
└─────────────────────────────────────────┘
```

## 단계별 입력 / 산출물

| 단계 | 호출 대상 | 오케스트라 입력 | 대표 산출물 | 다음 단계로 넘기는 값 |
| --- | --- | --- | --- | --- |
| vuln | `vuln_collector_agent` | 별도 단계 입력 없음 | `raw_result`, `risk_assessment_payload`, `operational_impact_payload`, `asset_matching_payload` | asset, risk, patch |
| asset | `infra_matching_agent` | `stack_name`, `region`, `asset_matching_payload` | `infra_context` | risk, patch |
| risk | `risk_evaluation_agent` | `region`, `infra_context`, `risk_assessment_payload` | `risk_result` | patch |
| patch | `patch_impact_agent` | `region`, `infra_context`, `risk_result`, `operational_payload` | `patch_strategy_result` | patch_exec, 최종 응답 |
| patch_exec | `patch_exec_agent` | `patch_strategy_result` 또는 patch execution payload | `patch_execution_result` | 최종 응답 |

표에서 자주 나오는 값은 아래처럼 이해하면 됩니다.

- `raw_result`: vuln 단계의 원본 취약점 수집 결과입니다.
- `risk_assessment_payload`: risk 단계가 바로 읽을 수 있게 정리한 취약점 payload입니다.
- `operational_payload`: patch 단계가 정식 패치, 임시 완화, 검증 항목을 판단할 때 참고하는 patch 전략 힌트 payload입니다.
- `asset_matching_payload`: asset 단계가 어떤 자산을 볼지 판단할 때 쓰는 기준 payload입니다.
- `infra_context`: 실제 인프라, 인스턴스, 소프트웨어, 네트워크 정보를 모아둔 컨텍스트입니다.
- `risk_result`: risk 단계가 계산한 위험도 평가 결과입니다.
- `patch_strategy_result`: patch 단계의 최종 판단 결과입니다.
- `patch_execution_result`: patch 실행 단계의 결과 또는 실행 계획입니다.

## 에이전트별 역할과 전달 데이터

| 에이전트 | 핵심 역할 | 주로 받는 데이터 | 주로 넘기는 데이터 |
| --- | --- | --- | --- |
| `vuln_collector_agent` | 취약점 원본 수집 + 후속 단계용 payload 생성 | `stack_name`, `region`, 외부 취약점 데이터셋 | `risk_assessment_payload`, `operational_impact_payload`, `asset_matching_payload` |
| `infra_matching_agent` | 자산/인프라 수집, 소프트웨어/설정/네트워크 사실 확인 | `stack_name`, `asset_matching_payload`, 개별 `question` + `asset_info` | `infra_context`, direct fact 응답 |
| `risk_evaluation_agent` | 취약점과 자산 컨텍스트를 합쳐 위험도 계산 | `risk_assessment_payload`, `infra_context` | `risk_result` |
| `patch_impact_agent` | 위험도 기반 patch 전략 판단, 부족한 direct fact만 asset에 질문 | `risk_result`, `infra_context`, `operational_payload`, 기존 asset fact 응답 | `patch_strategy_result`, `PatchToAsset` 대화 로그 |
| `patch_exec_agent` | 선택된 조치의 실제 실행 | `patch_strategy_result` 또는 patch execution payload | 실행 결과, 검증 결과 |
| `orchestrator_agent` | 각 AgentCore runtime 호출, 단계 연결, 결과 저장 | `mode`, `region`, 각 단계 입력 payload | `pipeline_result`, 단계 wrapper 결과 |

Patch 단계에서 특히 중요한 전달 관계는 아래처럼 이해하면 됩니다.

- `risk_result`
  patch 전략의 시작점입니다. 위험도가 높을수록 `apply_patch_now` 또는 `apply_mitigation_now` 쪽으로 기울 수 있습니다.
- `infra_context`
  현재 자산의 설치 소프트웨어, 네트워크 노출, 실행 상태, 설정 흔적 같은 직접 사실의 기본 근거입니다.
- `operational_payload`
  정식 패치 방법, 가능한 완화책, validation 체크리스트를 주는 참고 payload입니다.
- `PatchToAsset` direct fact query
  위 3개만으로 특정 필드를 채우기 부족할 때만 patch가 asset에 질문합니다.
  이 질문은 운영 정책이 아니라 직접 관측 가능한 기술 사실 확인에만 사용합니다.

## 저장소 구조

```text
PacherAgents/
├── MultiAIagent/
│   ├── OchestratorAgent(AWS)/
│   ├── VulnCollectorAgent(AWS)/
│   ├── Infra_matchingAgent(AWS)/
│   ├── Risk_evaluation_agent(AWS)/
│   ├── PatchStrategyAgent(AWS)/
│   ├── PatchExecAgent(AWS)/
│   ├── OchestraResult/
│   ├── Conversationlog/
│   ├── scripts/
│   └── run_orchestrator_runtime.py
├── InfraSubjectTo Vulnerability Inspection/
├── image/
└── README.md
```

### 주요 폴더

- `MultiAIagent/`
  실제 멀티 에이전트 구현, 런타임 소스, 실행기, 결과 저장 폴더가 들어 있습니다.
- `InfraSubjectTo Vulnerability Inspection/`
  실습용 인프라 템플릿과 점검 대상 코드/리소스를 두는 영역입니다.
- `image/`
  구조도 등 문서용 이미지 리소스입니다.

## 주요 런타임 소스

### `OchestratorAgent(AWS)`

오케스트라 runtime 소스입니다.

주요 파일:

- `main.py`
  AgentCore entrypoint
- `orchestrator_pipeline.py`
  실행 모드 분기와 전체 흐름 제어
- `pipeline_stages.py`
  vuln / asset / risk / patch / patch_exec 각 단계 실행 함수
- `runtime_agents.py`
  다른 AgentCore runtime ARN 호출 레이어

현재 성격:

- 얇은 순차 파이프라인
- `full`, `vuln_only`, `asset_only`, `risk_only`, `patch_only`, `test`, `patch_exec_only` 지원
- 앞 단계 결과를 다음 단계로 넘기는 역할 담당

### `VulnCollectorAgent(AWS)`

취약점 수집 runtime 소스입니다.

주요 파일:

- `runtime_app.py`
- `vuln_collector_agent/`

현재 역할:

- CVE raw 결과 생성
- `risk_assessment_payloads.json`
- `operational_impact_payloads.json`
- `asset_matching_payload.json`

즉 뒤 단계가 바로 쓸 수 있는 취약점 payload를 만드는 역할입니다.

### `PatchStrategyAgent(AWS)`

패치 전략 판단 runtime 소스입니다.

중요:

- 현재 patch는 ZIP runtime이 아니라 container runtime 기준으로 운용합니다.
- 예전 `pre/followup/final` 외부 단계 분할이 아니라, `patch_actions.py` 한 파일 중심의 단일 planner 구조입니다.

주요 파일:

- `runtime_app.py`
  patch runtime 진입점
- `patch_runtime/patch_actions.py`
  patch 전략 planner 본체
- `container_server.py`
  AgentCore container runtime용 HTTP wrapper
- `Dockerfile`
  container 이미지 정의
- `build_and_push_container.sh`
  ECR build/push
- `deploy_container_runtime.sh`
  AgentCore container runtime update

현재 patch는 `patch_actions.py` 한 파일 안에서 아래를 모두 처리합니다.

- `risk_result`, `infra_context`, `operational_payload`를 직접 읽음
- 최종 출력 스키마의 각 필드를 직접 채우려 함
- 기존 자료만으로 부족한 필드가 있으면 `query_asset_fact` tool로 asset runtime에 직접 기술 사실 질문
- 응답을 반영해 최종 `patch_strategy_result` 생성

즉 지금 실제 에이전트 간 direct fact 대화에 제일 가까운 구간은 `patch -> asset` 질문입니다.

### `PatchExecAgent(AWS)`

패치 실행 runtime 소스입니다.

현재 역할:

- `patch_strategy_result`를 읽고 실행 단계 판단
- 실제 명령 실행 또는 실행 계획 정리
- patch execution 결과 산출

## `run_orchestrator_runtime.py`

경로:

- `MultiAIagent/run_orchestrator_runtime.py`

이 스크립트는 로컬에서 오케스트라 runtime을 호출하는 실행기입니다.

역할:

- 실행 모드 선택
- 필요한 JSON 입력 자동 탐색
- 오케스트라 runtime 1차 호출
- 실행 결과를 `OchestraResult`에 저장
- patch -> asset direct fact 질문이 있으면 `Conversationlog/PatchToAsset`에도 저장

### 실행 원리

호출 구조는 항상 아래와 같습니다.

```text
로컬 실행기
-> 오케스트라 runtime
-> 오케스트라가 하위 runtime들 호출
```

즉 `vuln_only`, `asset_only`, `risk_only`, `patch_only`, `full`, `test`, `patch_exec_only` 모두 기본 원리는 같습니다.

차이는 오케스트라가 내부에서 어디까지 호출하느냐입니다.

- `vuln_only`
  vuln runtime만 호출
- `asset_only`
  asset runtime만 호출
- `risk_only`
  risk runtime만 호출
- `patch_only`
  patch runtime만 호출
- `full`
  vuln -> asset -> risk -> patch -> patch_exec 전체 호출
- `test`
  `test_inputs`와 `stop_stage` 기준으로 필요한 단계까지만 호출
- `patch_exec_only`
  patch execution runtime만 호출

### `.env` 탐색 방식

실행기는 아래 순서로 `.env`를 찾습니다.

1. `MultiAIagent/.env`
2. `PacherAgents/.env`

즉 `MultiAIagent` 폴더 안에 `.env`가 있으면 그걸 우선 사용하고, 없으면 상위 루트 `.env`를 사용합니다.

### 필요한 로컬 환경

최소 기준:

- Python 3.13 권장
- `boto3`
- `python-dotenv`

처음 세팅 예시는 아래 정도면 충분합니다.

```bash
cd /Users/jms/Desktop/project/PacherAgents
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install boto3 python-dotenv
```

### 필요한 `.env`

로컬 실행기와 각 runtime 호출 기준으로 아래 값들을 준비하는 것이 좋습니다.

필수:

```env
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=ap-northeast-2

ORCHESTRATOR_AGENTCORE_ARN=arn:aws:bedrock-agentcore:ap-northeast-2:...:runtime/orchestrator_agent-...
INFRA_MATCHING_AGENTCORE_ARN=arn:aws:bedrock-agentcore:ap-northeast-2:...:runtime/asset_matching_agent-...
VULN_COLLECTOR_AGENTCORE_ARN=arn:aws:bedrock-agentcore:ap-northeast-2:...:runtime/vuln_collector_agent-...
RISK_EVAL_AGENTCORE_ARN=arn:aws:bedrock-agentcore:ap-northeast-2:...:runtime/risk_evaluation_agent-...
PATCH_IMPACT_AGENTCORE_ARN=arn:aws:bedrock-agentcore:ap-northeast-2:...:runtime/patch_impact_container-...
PATCH_EXECUTION_AGENTCORE_ARN=arn:aws:bedrock-agentcore:ap-northeast-2:...:runtime/patch_exec_agent-...
```

선택:

```env
BEDROCK_MODEL_ID=global.anthropic.claude-haiku-4-5-20251001-v1:0
PATCH_IMPACT_BEDROCK_MODEL=global.anthropic.claude-haiku-4-5-20251001-v1:0

PATCH_MAX_FOLLOWUPS_PER_RECORD=8
PATCH_MAX_RECORD_WALL_TIME_SECONDS=240
PATCH_MAX_TOTAL_WALL_TIME_SECONDS=900
```

참고:

- `PATCH_EXECUTION_ARN`은 `PATCH_EXECUTION_AGENTCORE_ARN`의 alias로도 읽습니다.
- `BEDROCK_MODEL_ID`는 공통 기본값이고, `PATCH_IMPACT_BEDROCK_MODEL`이 있으면 patch runtime에서 우선 사용합니다.
- patch 질문 제한은 기본값이 이미 들어 있으므로 필요할 때만 override 하면 됩니다.

### 실행 명령

예시:

```bash
"/Users/jms/Desktop/project/PacherAgents/.venv/bin/python3" \
  "/Users/jms/Desktop/project/PacherAgents/MultiAIagent/run_orchestrator_runtime.py"
```

### 사용 방법

실행 후 기본 규칙은 간단합니다.

- 대괄호 `[ ]` 안의 값은 기본값
- 기본값 그대로 쓰려면 엔터
- JSON 파일 경로도 기본 후보가 뜨면 엔터

실행기 안에서 고를 수 있는 모드는 아래입니다.

1. `full`
2. `vuln_only`
3. `asset_only`
4. `risk_only`
5. `patch_only`
6. `patch_exec_only`
7. `test`

### 모드별 입력

#### `full`

보통 추가 파일 입력 없이 시작합니다.
앞 단계 결과를 동적으로 이어받아 다음 단계로 넘깁니다.

#### `vuln_only`

별도 JSON 입력 없이 실행 가능

#### `asset_only`

필요 입력:

- `asset_matching_payload.json`

#### `risk_only`

필요 입력:

- `infra_context.json`
- `risk_assessment_payloads.json`

#### `patch_only`

필요 입력:

- `infra_context.json`
- `risk_evaluation_result.json`
- `operational_impact_payloads.json`

참고:

- patch는 더 이상 `pre/followup/final` 외부 단계를 나누지 않습니다.
- `patch_impact_agent`가 위 3개 입력을 한 번에 읽고, 부족한 direct technical fact만 asset agent에 직접 질문합니다.
- 최종 산출물은 `patch_strategy_result.json` 하나를 기준으로 보면 됩니다.

#### `patch_exec_only`

필요 입력:

- `patch_strategy_result.json`

#### `test`

특정 단계까지만 확인할 때 씁니다.

예:

- `stop_stage = patch`
  patch 단계까지 확인
- `stop_stage = patch_execution`
  patch execution 단계까지 확인

중요:

- `test_inputs`로 직접 넣은 값은 우선 사용
- 부족한 값은 필요한 앞단 결과로 보충

## 결과 저장 위치

실행 결과는 기본적으로 `MultiAIagent/OchestraResult` 아래에 저장됩니다.

구조:

```text
OchestraResult/
├── orchestrator_agent/latest/
├── vuln_collector_agent/latest/
├── asset_matching_agent/latest/
├── risk_evaluation_agent/latest/
├── patch_impact_agent/latest/
└── patch_execution_agent/latest/
```

원칙:

- `latest/`: 가장 최근 결과
- `<run_tag>/`: 실행 단위 보관본

중요:

- 현재 patch 단계에서 사람이 최종 판단을 볼 때는 `patch_strategy_result.json` 하나를 보면 됩니다.
- `patch_strategy_context`나 `asset_fact_trace`는 디버그 용도이며, 결과 해석의 1차 기준은 아닙니다.

## `Conversationlog/PatchToAsset`

경로:

- `MultiAIagent/Conversationlog/PatchToAsset`

이 폴더는 patch -> asset direct fact 대화 로그 저장소입니다.

생성 조건:

- `patch_only` 또는 `full` 실행 중
- patch planner가 어떤 필드를 채우기에 근거가 부족하다고 판단해 asset에 직접 질문한 경우

저장 구조:

```text
Conversationlog/PatchToAsset/
├── latest.json
└── <run_tag>/
    ├── conversation_log.json
    ├── CVE-...__i-....json
    └── ...
```

주요 필드 예시:

- 최상위:
  - `run_tag`
  - `generated_at`
  - `response_count`
  - `conversations`
- `conversations[]` 내부:
  - `request_id`
  - `cve_id`
  - `instance_id`
  - `source_agent`
  - `target_agent`
  - `transcript`
  - `final_answer`

중요:

- 지금 patch -> asset 대화는 예전처럼 `question_bundle` 중심이 아니라,
  실제 direct fact 질문과 그 응답을 `transcript`에 남기는 구조입니다.
- 즉 transcript를 보면 patch가 어떤 필드를 채우기 위해 어떤 direct technical question을 보냈는지 확인할 수 있습니다.

## 결과 해석

patch 최종 결론은 `patch_strategy_result.json`의 아래 필드를 우선 보면 됩니다.

- `selected_action`
- `decision`
- `reason_summary`

예:

- `selected_action = apply_patch_now`
  지금 바로 정식 패치 적용
- `selected_action = apply_patch_planned`
  계획된 시점에 패치 적용
- `selected_action = apply_mitigation_now`
  지금은 임시 완화 조치 먼저 적용
- `selected_action = human_review`
  사람 검토 필요

## 배포/빌드 방식

### ZIP runtime

- `MultiAIagent/OchestratorAgent(AWS)`
- `MultiAIagent/VulnCollectorAgent(AWS)`
- `MultiAIagent/Infra_matchingAgent(AWS)`
- `MultiAIagent/Risk_evaluation_agent(AWS)`
- `MultiAIagent/PatchExecAgent(AWS)`

보통 각 폴더의 `build_package.sh`로 `dist/deployment_package.zip`을 만듭니다.

### Container runtime

- `MultiAIagent/PatchStrategyAgent(AWS)`

이쪽은 ECR + AgentCore container runtime 기준입니다.

주요 스크립트:

- `build_and_push_container.sh`
- `deploy_container_runtime.sh`

## 현재 기준으로 기억하면 좋은 것

- 오케스트라는 현재 얇은 순차 파이프라인입니다.
- patch는 container runtime 기준으로 봅니다.
- 실행은 보통 `MultiAIagent/run_orchestrator_runtime.py`로 합니다.
- 최근 결과는 `MultiAIagent/OchestraResult`를 봅니다.
- patch -> asset 대화는 `MultiAIagent/Conversationlog/PatchToAsset`를 봅니다.
- patch 최종 결론은 `patch_strategy_result.json`의 `selected_action`, `decision`, `reason_summary`를 우선 보면 됩니다.
