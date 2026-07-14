# Patcher Multi AI Agent Frontend

데모용으로 구축한 프론트엔드입니다. 기존 Python/AWS AgentCore 파이프라인 코드는 안정 버전으로 유지하고, 프론트는 실행 설정, 결과 리포트, 개발자용 JSON 흐름 확인을 담당합니다.

## 주요 화면

### Workflow

메인 실행 화면입니다.

- 실행 모드, Stack, Region, CVE ID를 설정합니다.
- `실행 시작` 버튼으로 로컬 `.venv` Python 실행기를 통해 AWS AgentCore 오케스트레이터를 호출합니다.
- 실행 중에는 워크플로우 단계 상태에 맞춰 진행 상황이 표시됩니다.
- 완료되면 버튼이 `실행 완료`로 바뀌고, 최신 `OchestraResult` 결과를 화면에 반영합니다.
- `full`, `patch_exec_only`, `test + patch_execution`처럼 실제 변경 가능성이 있는 모드는 버튼 클릭 후 **안전 확인 팝업**을 거친 뒤 실행됩니다.

### Result

일반 사용자용 결과 화면입니다.

- 에이전트 실행 흐름을 타임라인 형태로 보여줍니다.
- 각 단계마다 받은 정보, 핵심 판단, 주요 결과, 다음 전달 내용을 사용자 친화적으로 요약합니다.
- `latest 결과 불러오기`를 누르면 최신 결과를 다시 읽고, 생성 시각을 함께 표시합니다.

예시:

```text
OchestraResult 최신 파일을 불러왔습니다. 이것은 2026-05-14 23:42:44에 생성된 파일입니다.
```

### Dev

개발자용 원본 데이터 확인 화면입니다.

- 맨 위에 `오케스트레이션 AGENT`가 전체 에이전트를 조율하는 흐름을 표시합니다.
- 각 에이전트가 받은 파일과 내보낸 파일을 토글 형태로 확인할 수 있습니다.
- 화면 하단에는 `Stage responses` 대신 **대화 내역** 섹션이 표시되며, `Conversationlog`에 저장된 follow-up 질의·응답을 모아 확인할 수 있습니다.
- 취약점 수집 에이전트의 출력은 다음 관계가 보이도록 정리됩니다.

```text
focused_selected_raw_cves.json
        ↓
asset_matching_payload.json
risk_assessment_payloads.json
operational_impact_payloads.json
```

## 실행 모드

| 모드 | 설명 |
| --- | --- |
| `Vuln` | 취약점 수집 에이전트만 실행합니다. |
| `Asset` | 기존 latest 취약점 payload를 사용해 자산 매칭만 실행합니다. |
| `Risk` | 기존 latest 자산·취약점 payload를 사용해 위험 평가만 실행합니다. |
| `Patch` | 기존 latest 위험 평가·운영 영향 결과를 사용해 패치 전략만 실행합니다. |
| `Exec 전` | `vuln -> asset -> risk -> patch`까지 실행하고, 실제 patch execution은 실행하지 않습니다. |
| `Exec` | 실제 patch execution까지 포함될 수 있으며, 실행 전 안전 확인 팝업이 표시됩니다. |
| `Full` | 전체 실행 모드이며, 실제 patch execution까지 이어질 수 있어 실행 전 안전 확인 팝업이 표시됩니다. |
| `Test` | 중간 단계 주입 테스트용입니다. `patch_execution` 단계까지 포함되면 실행 전 안전 확인 팝업이 표시됩니다. |

데모에서는 보통 `Exec 전`을 사용하면 전체 판단 흐름을 보여주면서 실제 패치 실행은 막을 수 있습니다.

## 사전 요구사항

- Node.js
- pnpm
- Python 가상환경 `.venv`
- AWS 자격 증명
- AWS Bedrock 및 AgentCore 실행 환경

pnpm이 설치되지 않았다면 다음 명령으로 설치할 수 있습니다.

```powershell
npm install -g pnpm
```

## 설치

GitHub Packages에서 원티드 몽타주 패키지를 받기 위해 npm 인증이 필요합니다.

`frontend/.npmrc`에는 아래 Registry 설정이 포함되어 있습니다.

```ini
@wanteddev:registry=https://npm.pkg.github.com/
```

저장소 루트에서 다음 명령을 실행합니다.

```powershell
cd frontend
pnpm install
```

## 개발 서버

`frontend` 디렉터리에서 실행합니다.

```powershell
pnpm dev
```

저장소 루트에 있다면 다음과 같이 실행할 수 있습니다.

```powershell
cd frontend
pnpm dev
```

기본 주소:

```text
http://localhost:5173
```

`vite.config.ts`가 변경되면 Vite가 자동으로 개발 서버 재시작을 시도합니다. 실행 API 동작이 이상하면 개발 서버를 종료한 뒤 다시 실행합니다.

## 빌드와 검사

`frontend` 디렉터리에서 실행합니다.

```powershell
pnpm lint
pnpm build
```

## AWS 실행 조건

프론트의 실행 버튼은 Vite 개발 서버의 로컬 API를 통해 다음 파일을 호출합니다.

```text
MultiAIagent/run_orchestrator_runtime.py
```

필수 조건:

- 프로젝트 루트에 `.venv`가 있어야 합니다.
- `.venv`에 `boto3`, `python-dotenv`, `bedrock-agentcore`가 설치되어 있어야 합니다.
- 프로젝트 루트 `.env`에 AWS 인증정보, Bedrock 모델 설정, 오케스트레이터 Runtime ARN이 있어야 합니다.
- 실제 `.env` 파일은 Git에 커밋하지 않습니다.

환경변수 예시:

```env
AWS_DEFAULT_REGION=<AWS_REGION>
ORCHESTRATOR_AGENTCORE_ARN=arn:aws:bedrock-agentcore:<AWS_REGION>:<AWS_ACCOUNT_ID>:runtime/<ORCHESTRATOR_AGENT_ID>
AWS_ACCESS_KEY_ID=<AWS_ACCESS_KEY_ID>
AWS_SECRET_ACCESS_KEY=<AWS_SECRET_ACCESS_KEY>
OPENCVE_API_KEY=<OPENCVE_API_KEY>
BEDROCK_MODEL_ID=<BEDROCK_MODEL_ID>
```

> 실제 인증정보를 README, 소스코드 또는 Git 커밋에 직접 작성하지 마십시오.

AWS Access Key를 직접 사용하지 않고 IAM Role 또는 AWS CLI Profile을 사용하는 환경에서는 해당 인증 방식에 맞게 구성할 수 있습니다.

오케스트레이터와 각 에이전트는 현재 **Amazon Bedrock 기반**으로 동작합니다. 실행 전에는 사용할 Bedrock 모델에 대한 접근 권한이 준비되어 있어야 합니다.

`ORCHESTRATOR_AGENTCORE_ARN`에 `/runtime-endpoint/DEFAULT`가 붙어 있어도 프론트 실행 API가 Runtime ARN 형태로 자동 보정합니다.

## 결과 파일 위치

실행 결과는 기존 파이프라인 구조대로 아래에 저장됩니다.

```text
MultiAIagent/OchestraResult/
```

주요 파일:

```text
MultiAIagent/OchestraResult/orchestrator_agent/latest/summary.json
MultiAIagent/OchestraResult/orchestrator_agent/latest/response.json
MultiAIagent/OchestraResult/vuln_collector_agent/latest/*.json
MultiAIagent/OchestraResult/asset_matching_agent/latest/*.json
MultiAIagent/OchestraResult/risk_evaluation_agent/latest/*.json
MultiAIagent/OchestraResult/patch_impact_agent/latest/*.json
```

프론트 실행 API의 진단 파일:

```text
MultiAIagent/OchestraResult/frontend_run/latest/run_diagnostic.json
```

실행이 실패하거나 화면 상태가 불명확할 때는 이 파일에서 다음 항목을 먼저 확인합니다.

```text
status
error
stdout
stderr
summary
```

`OchestraResult`와 `Conversationlog`에는 실제 AWS 인프라 정보와 실행 결과가 포함될 수 있으므로 Git에 커밋하지 않습니다.

## 데모 권장 흐름

1. `pnpm dev`로 프론트를 실행합니다.
2. Workflow 화면에서 `Exec 전`을 선택합니다.
3. Stack, Region, CVE ID를 확인합니다.
4. `실행 시작`을 클릭합니다.
5. 워크플로우 단계 점등을 확인합니다.
6. 완료 후 Result 화면에서 사용자용 타임라인을 확인합니다.
7. Dev 화면에서 오케스트레이션 AGENT와 에이전트별 파일 흐름을 확인합니다.

이 흐름은 실제 Patch Execution을 실행하지 않으면서, 취약점 수집부터 패치 전략 생성까지의 전체 판단 과정을 보여주는 데모에 적합합니다.

## 보안 주의사항

이 프로젝트는 보안 자동화 실습 및 데모를 목적으로 합니다.

- 실제 운영 환경에 적용하기 전에 IAM 최소 권한을 구성해야 합니다.
- 실제 AWS 계정 ID, ARN, IP 주소, Instance ID를 저장소에 커밋하지 않습니다.
- `.env`, 실행 로그, AgentCore Session 정보는 공개 저장소에 업로드하지 않습니다.
- `Exec`, `Full` 모드는 실제 서버 변경으로 이어질 수 있으므로 격리된 실습 환경에서만 실행합니다.
- 실습 종료 후 생성된 AWS 리소스와 임시 인증정보를 정리합니다.