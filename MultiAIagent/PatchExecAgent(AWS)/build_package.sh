#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$ROOT_DIR/build/deployment_package"
DIST_DIR="$ROOT_DIR/dist"
ZIP_PATH="$DIST_DIR/deployment_package.zip"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR" "$DIST_DIR"

if command -v uv >/dev/null 2>&1; then
  uv pip install \
    --python-platform aarch64-manylinux2014 \
    --python-version 3.12 \
    --target="$BUILD_DIR" \
    --only-binary=:all: \
    -r "$ROOT_DIR/requirements.txt"
elif command -v python3.13 >/dev/null 2>&1; then
  python3.13 -m pip install \
    --platform manylinux2014_aarch64 \
    --python-version 3.12 \
    --implementation cp \
    --only-binary=:all: \
    --target "$BUILD_DIR" \
    -r "$ROOT_DIR/requirements.txt"
else
  echo "uv 또는 python3.13 이 필요합니다."
  exit 1
fi

# 엔트리포인트
cp "$ROOT_DIR/runtime_app.py" "$BUILD_DIR/runtime_app.py"

# patch_exec_agent 패키지
cp -r "$ROOT_DIR/patch_exec_agent" "$BUILD_DIR/patch_exec_agent"

# strands 패키지 (로컬 포함)
cp -r "$ROOT_DIR/strands" "$BUILD_DIR/strands"

# 캐시 정리
find "$BUILD_DIR" -type d -name "__pycache__" -prune -exec rm -rf {} +
find "$BUILD_DIR" -type f -name "*.pyc" -delete
find "$BUILD_DIR" -type f -name ".DS_Store" -delete

rm -f "$ZIP_PATH"
(
  cd "$BUILD_DIR"
  zip -qr "$ZIP_PATH" .
)

echo "완료: $ZIP_PATH"
