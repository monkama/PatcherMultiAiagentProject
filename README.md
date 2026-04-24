# PacherAgents

PacherAgents는 여러 AI 에이전트가 협업해 실시간으로 취약점 데이터를 수집하고, 위험도를 평가하며, 패치시 대상 인프라의 운영 및 영향도까지 확인하여 안전하게 취약점을 보완해주는 ai 기반 보안 솔루션 시스템입니다.

현재는 취약점 수집용 에이전트 하나가 먼저 들어와 있고, 저장소 구조는 이후 에이전트 추가와 점검 대상 인프라 코드 적재를 염두에 두고 정리되어 있습니다.

전체 AI agent 구조도는 `image/MegatonStructure.drawio` 파일에 정리되어 있습니다.

## 전체 구조도

GitHub README에서는 `.drawio` 원본이 이미지처럼 바로 렌더링되지 않기 때문에, 아래에 같은 내용을 빠르게 파악할 수 있는 Mermaid 요약 구조도를 함께 둡니다.

```mermaid
flowchart LR
  A[자산 수집 agent]
  A1[기본 자산 정보 수집]
  A2[위험도 평가용 추가 자산 정보 수집]
  A3[의존성 및 운영 영향 관련 추가 정보 수집]
  V[취약점 수집 agent]
  V1[소프트웨어 정보에 해당하는 취약점 정보 수집]
  R[위험도 평가 agent]
  R1[1단계: risk_assessment_payloads.json + 기본 자산 정보 전체 기반 평가]
  R2[2단계: 추가 자산 정보 요청 후 위험도 판단]
  R3[3단계: 위험도 정보를 JSON으로 정규화]
  O[의존성 및 운영 영향 평가 후 조치 agent]
  O1[operational_impact_payloads.json 기반 의존성 확인]
  O2[버전 업그레이드 및 보완 조치 적용 후 정상/비정상 신호 반환]

  A --> A1
  A --> A2
  A --> A3
  V --> V1
  R --> R1
  R --> R2
  R --> R3
  O --> O1
  O --> O2

  A1 -->|사용 중인 소프트웨어 정보| V1
  V1 -->|risk_assessment_payloads.json| R1
  A1 -->|기본 자산 정보 전체| R1
  R2 -->|추가 정보 요청| A2
  A2 -->|추가 자산 정보 응답| R2
  O1 -->|추가 정보 요청| A3
  A3 -->|의존성/운영 영향 관련 정보 응답| O1
```

## 저장소 구조

```text
PacherAgents/
  MultiAIagent/
    vuln_collector_agent/
  InfraSubjectTo Vulnerability Inspection/
  image/
    MegatonStructure.drawio
  README.md
```

### `MultiAIagent/`

여기는 여러 역할을 가진 AI 에이전트들을 모아두는 상위 폴더입니다.

- 현재 포함된 에이전트:
  - 취약점 수집 에이전트(vuln_collector_agent)
- 앞으로 추가될 수 있는 예시:
  - 자산 수집 에이전트
  - 위험도 평가 에이전트
  - 운영 및 영향도 점검 후 조치 에이전트

즉, `MultiAIagent/`는 "에이전트 구현체들이 들어가는 영역"이라고 보면 됩니다.

### `InfraSubjectTo Vulnerability Inspection/`

여기는 취약점 점검 대상이 되는 인프라 코드들을 올려두는 폴더입니다.
즉, 이 폴더는 "분석 대상 인프라 자산이 들어가는 영역"입니다.

## 현재 구현된 에이전트

현재는 `MultiAIagent/vuln_collector_agent/`가 먼저 구현되어 있습니다.

이 에이전트는 소수의 고정된 CVE를 수집하고, 후속 분석에 바로 사용할 수 있는 JSON payload를 생성합니다.

상세 설명은 [`MultiAIagent/vuln_collector_agent/README.md`](MultiAIagent/vuln_collector_agent/README.md)에서 볼 수 있습니다.




## 협업 기준

저장소를 확장할 때는 아래 기준을 유지하면 구조가 덜 흔들립니다.

- 새 에이전트는 `MultiAIagent/` 아래에 독립 폴더로 추가
- 점검 대상 코드와 에이전트 코드는 분리 유지
- 에이전트별 입구 문서는 각 폴더 내부 `README.md`에 작성
- 루트 `README.md`는 저장소 전체 구조와 역할 설명 중심으로 유지

## 현재 상태 메모

- 루트는 멀티 에이전트 저장소의 입구 역할을 합니다.
- 실제 구현은 현재 `vuln_collector_agent`부터 시작되어 있습니다.
- 인프라 점검 대상 폴더는 앞으로 실제 IaC 및 운영 코드가 채워질 예정입니다.
