#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$ROOT_DIR/build/deployment_package"
DIST_DIR="$ROOT_DIR/dist"
ZIP_PATH="$DIST_DIR/deployment_package.zip"
TARGET_PLATFORM="${TARGET_PLATFORM:-manylinux2014_aarch64}"
TARGET_PYTHON_VERSION="${TARGET_PYTHON_VERSION:-3.13}"

rm -rf "$BUILD_DIR" "$ZIP_PATH"
mkdir -p "$BUILD_DIR" "$DIST_DIR"

if command -v uv >/dev/null 2>&1; then
  uv pip install \
    --python-platform "$TARGET_PLATFORM" \
    --python-version "$TARGET_PYTHON_VERSION" \
    --target "$BUILD_DIR" \
    --only-binary=:all: \
    -r "$ROOT_DIR/requirements.txt"
elif command -v python3.13 >/dev/null 2>&1; then
  python3.13 -m pip install \
    --only-binary=:all: \
    --platform "$TARGET_PLATFORM" \
    --implementation cp \
    --python-version 3.13 \
    --abi cp313 \
    --target "$BUILD_DIR" \
    -r "$ROOT_DIR/requirements.txt"
else
  echo "uv 또는 python3.13 이 필요합니다." >&2
  exit 1
fi

cp "$ROOT_DIR/main.py" "$BUILD_DIR/main.py"
cp "$ROOT_DIR/risk_assessment_refiner.py" "$BUILD_DIR/risk_assessment_refiner.py"
cp "$ROOT_DIR/infra_context_refiner.py" "$BUILD_DIR/infra_context_refiner.py"
cp -R "$ROOT_DIR/strands" "$BUILD_DIR/strands"

find "$BUILD_DIR" -type d -name "__pycache__" -prune -exec rm -rf {} +
find "$BUILD_DIR" -type f -name "*.pyc" -delete
find "$BUILD_DIR" -type f -name ".DS_Store" -delete

rm -f "$ZIP_PATH"
(
  cd "$BUILD_DIR"
  zip -qr "$ZIP_PATH" .
)

echo "Built: $ZIP_PATH"
