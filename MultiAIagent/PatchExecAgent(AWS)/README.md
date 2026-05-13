# Patch_exec_agent

`Patch_exec_agent`는 취약점 분석 결과를 바탕으로 AWS 환경에서 안전하게 패치를 실행하고, 그 과정을 실시간으로 모니터링할 수 있도록 돕는 자동화 에이전트입니다.

## 동작 프로세스 (Architecture)

본 에이전트는 상황에 따라 **자동 패치 프로세스**와 **관리자 승인 기반 프로세스** 두 가지 파이프라인으로 동작합니다.

```mermaid
graph TD
    %% 스타일 정의
    classDef agent fill:#f9f0ff,stroke:#b180d1,stroke-width:2px;
    classDef aws fill:#ff9900,stroke:#232f3e,stroke-width:2px,color:#fff;
    classDef slack fill:#4A154B,stroke:#E01E5A,stroke-width:2px,color:#fff;
    
    %% 노드 정의
    IA["Patch Impact Agent<br/>(영향도 분석 결과)"]:::agent
    Admin["관리자 (Slack)<br/>승인 버튼 클릭"]:::slack
    API["API Gateway"]:::aws
    Lambda["AWS Lambda<br/>(Agent Wake-up)"]:::aws
    EA{"Patch Exec Agent"}:::agent
    SSM["AWS Systems Manager (SSM)<br/>대상 서버 접속 및 패치"]:::aws
    SlackOut["Slack<br/>(실시간 로그 및 결과 출력)"]:::slack

    %% Flow 1: 자동 패치 흐름
    IA ==>|자동 실행| EA
    
    %% Flow 2: 관리자 승인 흐름
    Admin -.->|Webhook URL 호출| API
    API -.->|Trigger| Lambda
    Lambda -.->|에이전트 실행| EA

    %% 공통 실행 흐름
    EA ==>|명령어 전달| SSM
    SSM ==>|실행 로그 스트리밍| SlackOut
