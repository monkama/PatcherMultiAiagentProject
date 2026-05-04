# Team Setup

이 문서는 Git에 올라가지 않는 `.env`, `.venv`, 로컬 CLI 차이 때문에 다음 사람이 실행에 막히지 않도록 하기 위한 최소 체크리스트입니다.

## 원칙

- `.env`는 공유하되 Git에는 올리지 않습니다.
- `.venv` 폴더 자체는 공유하지 않습니다. 각자 로컬에서 재생성합니다.
- 새 환경변수가 필요해지면 실제 값 대신 키 이름만 `MultiAIagent/.env.example`에 추가합니다.
- AgentCore runtime ARN, IAM role, S3 bucket, ECR repository 같은 팀 공용 설정은 문서나 예시 파일에 남깁니다.

## 기본 준비

```bash
cd MultiAIagent
cp .env.example .env
```

`.env`에는 최소 아래 값이 필요합니다.

```text
AWS_DEFAULT_REGION=ap-northeast-2
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
OPENCVE_API_KEY=...
```

`VulnCollectorAgent`를 `update-agent-runtime`으로 직접 업데이트할 때는 `environmentVariables`가 비어지지 않도록 주의합니다. 이 값이 빠지면 실행은 성공해도 CVE 수집 결과가 0건이 됩니다.

## Python 환경

공통 실행기는 `MultiAIagent/.venv`를 사용합니다.

```bash
cd MultiAIagent
python3.14 -m venv .venv
.venv/bin/pip install -U pip
.venv/bin/pip install boto3 python-dotenv
```

AgentCore CLI가 필요하면 현재 프로젝트에서는 risk agent 가상환경의 CLI를 사용하고 있습니다.

```bash
cd MultiAIagent/risk_evaluation_agent
python3.14 -m venv .venv
.venv/bin/pip install -r requirements.txt bedrock-agentcore-starter-toolkit
```

## Agent별 의존성

각 runtime은 자기 폴더의 `requirements.txt`를 기준으로 배포됩니다.

- `Infra_matchingAgent/requirements.txt`
- `risk_evaluation_agent/requirements.txt`
- `VulnCollectorAgent(AWS)/requirements.txt`
- `OchestratorAgent(AWS)/requirements.txt`
- `PatchImpactAgent(AWS)/requirements.txt`

의존성을 바꾸면 해당 파일을 먼저 수정하고, 로컬 `.venv`만 바꾸고 끝내지 않습니다.

## 배포 메모

현재 배포 방식은 섞여 있습니다.

- asset/risk: `.bedrock_agentcore.yaml` 기반 `agentcore deploy`
- vuln/orchestrator: ZIP 생성 후 S3 artifact 업데이트
- patch: Docker buildx로 ECR push 후 container runtime update

patch는 로컬 Docker가 필요합니다.

```bash
cd MultiAIagent/PatchImpactAgent\(AWS\)
./build_and_push_container.sh
./deploy_container_runtime.sh update --runtime-arn arn:aws:bedrock-agentcore:ap-northeast-2:842337469411:runtime/patch_impact_container-qNIi2mCjRa
```

## 실행

```bash
cd MultiAIagent
.venv/bin/python run_orchestrator_runtime.py
```

기본값으로 실행하면 `full` 모드, `ap-northeast-2`, `megathon` stack 기준으로 실행됩니다.
