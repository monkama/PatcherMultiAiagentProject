# Patch_exec_agent

`Patch_exec_agent`는 취약점 분석 결과를 바탕으로 AWS 환경에서 안전하게 패치를 실행하고, 그 과정을 실시간으로 모니터링할 수 있도록 돕는 자동화 에이전트입니다.

## 동작 프로세스 (Architecture)

본 에이전트는 선행 에이전트의 결과물을 바탕으로, 설정에 따라 **자동 패치 프로세스** 또는 **관리자 승인 기반 프로세스**로 나뉘어 동작합니다.

```mermaid
graph LR
    %% 노드 정의 (색상 제거 및 좌우 배치)
    IA([Patch Impact Agent 결과물])
    
    Admin[관리자 슬랙 확인 및 승인]
    API[API Gateway]
    Lambda[AWS Lambda]
    
    EA[Patch Exec Agent]
    SSM[AWS Systems Manager]
    SlackOut([실시간 슬랙 출력])

    %% 흐름 정의
    IA -->|자동 패치 프로세스| EA
    
    IA -->|승인 필요 시 대기| Admin
    Admin -->|Webhook 호출| API
    API -->|Trigger| Lambda
    Lambda -->|Agent Wake-up| EA

    %% 공통 실행 흐름
    EA -->|명령어 전달| SSM
    SSM -->|실행 로그 스트리밍| SlackOut
