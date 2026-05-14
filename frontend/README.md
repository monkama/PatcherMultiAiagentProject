# Patcher Multi AI Agent Frontend

`front` 브랜치에서 데모용으로 구축한 프론트엔드입니다. 기존 Python/AWS AgentCore 파이프라인 코드는 안정 버전으로 유지하고, 프론트는 실행 설정, 결과 리포트, 개발자용 JSON 흐름 확인을 담당합니다.

## 주요 화면

### Workflow

메인 실행 화면입니다.

- 실행 모드, Stack, Region, CVE ID를 설정합니다.
- `실행 시작` 버튼으로 로컬 `.venv` Python 실행기를 통해 AWS AgentCore 오케스트레이터를 호출합니다.
- 실행 중에는 워크플로우 단계가 약 5초 간격으로 순차 점등됩니다.
- 완료되면 버튼이 `실행 완료`로 바뀌고, 최신 `OchestraResult` 결과를 화면에 반영합니다.

안전상 `full`, `patch_exec_only`, `test + patch_execution`은 버튼에서 바로 실행하지 않습니다.

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
- `stage_response.json`은 각 에이전트 카드에서는 숨기고, 화면 하단 `Stage responses` 섹션에 모아 표시합니다.
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
| `Risk` | 기존 latest 자산/취약점 payload를 사용해 위험 평가만 실행합니다. |
| `Patch` | 기존 latest 위험 평가/운영 영향 결과를 사용해 패치 전략만 실행합니다. |
| `Exec 전` | `vuln -> asset -> risk -> patch`까지 실행하고, 실제 patch execution은 실행하지 않습니다. |
| `Exec` | 실제 실행 가능성이 있어 버튼 실행에서 차단됩니다. |
| `Full` | 실제 실행 단계까지 이어질 수 있어 버튼 실행에서 차단됩니다. |
| `Test` | 중간 단계 주입 테스트용입니다. `patch_execution` 단계는 버튼 실행에서 차단됩니다. |

데모에서는 보통 `Exec 전`을 사용하면 전체 판단 흐름을 보여주면서 실제 패치 실행은 막을 수 있습니다.

## 설치

GitHub Packages에서 원티드 몽타주 패키지를 받기 위해 npm 인증이 필요합니다.

`frontend/.npmrc`에는 아래 registry 설정이 포함되어 있습니다.

```ini
@wanteddev:registry=https://npm.pkg.github.com/
```

패키지 설치:

```powershell
cd "C:\Users\MZC01-HYUNGJUN\Documents\New project\PatcherMultiAiagentProject\frontend"
& "C:\Users\MZC01-HYUNGJUN\AppData\Roaming\npm\pnpm.cmd" install
```

## 개발 서버

```powershell
cd "C:\Users\MZC01-HYUNGJUN\Documents\New project\PatcherMultiAiagentProject\frontend"
& "C:\Users\MZC01-HYUNGJUN\AppData\Roaming\npm\pnpm.cmd" dev
```

기본 주소:

```text
http://localhost:5173
```

`vite.config.ts`가 바뀌면 Vite가 자동으로 server restart를 시도합니다. 실행 API 동작이 이상하면 dev server를 한 번 종료한 뒤 다시 실행합니다.

## 빌드와 검사

```powershell
& "C:\Users\MZC01-HYUNGJUN\AppData\Roaming\npm\pnpm.cmd" lint
& "C:\Users\MZC01-HYUNGJUN\AppData\Roaming\npm\pnpm.cmd" build
```

## AWS 실행 조건

프론트의 실행 버튼은 Vite dev server의 로컬 API를 통해 다음 파일을 호출합니다.

```text
MultiAIagent/run_orchestrator_runtime.py
```

필수 조건:

- 프로젝트 루트에 `.venv`가 있어야 합니다.
- `.venv`에 `boto3`, `python-dotenv`, `bedrock-agentcore`가 설치되어 있어야 합니다.
- `MultiAIagent/.env`에 AWS 인증과 오케스트레이터 ARN이 있어야 합니다.

최소 예시:

```env
AWS_DEFAULT_REGION=ap-northeast-2
ORCHESTRATOR_AGENTCORE_ARN=arn:aws:bedrock-agentcore:ap-northeast-2:...:runtime/orchestrator_agent-...
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
```

`ORCHESTRATOR_AGENTCORE_ARN`에 `/runtime-endpoint/DEFAULT`가 붙어 있어도 프론트 실행 API가 runtime ARN 형태로 자동 보정합니다.

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

실행이 실패하거나 화면 상태가 애매할 때는 이 파일에서 `status`, `error`, `stdout`, `stderr`, `summary`를 먼저 확인합니다.

## 데모 권장 흐름

1. `pnpm dev`로 프론트 실행
2. Workflow 화면에서 `Exec 전` 선택
3. Stack, Region, CVE ID 확인
4. `실행 시작` 클릭
5. 워크플로우 단계 점등 확인
6. 완료 후 Result 화면에서 사용자용 타임라인 설명 확인
7. Dev 화면에서 오케스트레이션 AGENT와 에이전트별 파일 흐름 확인

이 흐름은 실제 patch execution을 실행하지 않으면서, 취약점 수집부터 패치 전략 생성까지의 전체 판단 과정을 보여주는 데모에 적합합니다.
