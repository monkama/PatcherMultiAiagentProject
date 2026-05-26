#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIST_DIR="$ROOT_DIR/dist"
PROJECT_ENV="$ROOT_DIR/../../.env"

load_project_env() {
  if [[ ! -f "$PROJECT_ENV" ]]; then
    return 0
  fi
  eval "$(
    python3.13 - <<'PY' "$PROJECT_ENV"
import shlex
import sys
from pathlib import Path

path = Path(sys.argv[1])
for line in path.read_text(encoding="utf-8").splitlines():
    raw = line.strip()
    if not raw or raw.startswith("#") or "=" not in raw:
        continue
    key, value = raw.split("=", 1)
    key = key.strip()
    value = value.strip()
    if not key:
        continue
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        value = value[1:-1]
    print(f"export {key}={shlex.quote(value)}")
PY
  )"
}

load_project_env

AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-}"
if [[ -z "$AWS_ACCOUNT_ID" ]]; then
  AWS_ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text 2>/dev/null || true)"
fi
if [[ -z "$AWS_ACCOUNT_ID" || "$AWS_ACCOUNT_ID" == "None" ]]; then
  echo "error: AWS_ACCOUNT_ID가 비어 있습니다. .env 에 AWS_ACCOUNT_ID를 넣거나 현재 AWS 자격증명으로 sts 조회가 가능해야 합니다." >&2
  exit 1
fi
ECR_REPOSITORY="${ECR_REPOSITORY:-patch-impact-agent}"
IMAGE_TAG="${IMAGE_TAG:-latest}"

CONTAINER_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPOSITORY}:${IMAGE_TAG}"

echo "[1/4] ECR 저장소 확인"
if ! aws ecr describe-repositories --region "$AWS_REGION" --repository-names "$ECR_REPOSITORY" >/dev/null 2>&1; then
  aws ecr create-repository --region "$AWS_REGION" --repository-name "$ECR_REPOSITORY" >/dev/null
fi

echo "[2/4] ECR 로그인"
aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

echo "[3/4] ARM64 컨테이너 빌드 및 푸시"
docker buildx build \
  --platform linux/arm64 \
  -t "$CONTAINER_URI" \
  --push \
  "$ROOT_DIR"

echo "[4/4] 완료"
mkdir -p "$DIST_DIR"
printf '%s\n' "$CONTAINER_URI" > "$DIST_DIR/container_uri.txt"
echo "CONTAINER_URI=$CONTAINER_URI"
