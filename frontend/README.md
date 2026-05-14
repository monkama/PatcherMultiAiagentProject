# Patcher Multi AI Agent Frontend

`front` 브랜치에서 분리 구축한 프론트엔드입니다. 기존 Python/AWS AgentCore 파이프라인 코드는 수정하지 않고, 실행 payload 구성과 결과 검토를 위한 UI를 제공합니다.

## 설치

GitHub Packages에서 원티드 몽타주 패키지를 받기 위해 `frontend/.npmrc`에 아래 설정이 포함되어 있습니다.

```ini
@wanteddev:registry=https://npm.pkg.github.com/
```

원티드 몽타주 패키지는 관련 패키지 버전이 서로 일치해야 합니다. 이 프로젝트는 `@wanteddev/wds`와 `@wanteddev/wds-icon`을 함께 설치합니다.

설치:

```bash
pnpm install
```

실행:

```bash
pnpm dev
```

빌드:

```bash
pnpm build
```

## API 연결

현재 저장소에는 HTTP API 서버가 없으므로 UI는 payload를 만들고 JSON을 검토하는 방식으로 동작합니다. 나중에 API가 추가되면 `.env`에 `VITE_API_BASE_URL` 또는 `VITE_API_PROXY_TARGET`을 설정해 연결할 수 있습니다.
