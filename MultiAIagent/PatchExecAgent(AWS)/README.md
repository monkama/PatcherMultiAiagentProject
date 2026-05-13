# Patch_exec_agent

`Patch_exec_agent`는 취약점 분석 결과를 바탕으로 AWS 환경에서 안전하게 패치를 실행하고, 그 과정을 실시간으로 모니터링할 수 있도록 돕는 자동화 에이전트입니다.

## 동작 프로세스 (Architecture)

본 에이전트는 선행 에이전트의 분석 직후 대상 서버 정보를 슬랙에 우선 출력하며, 설정에 따라 **자동 패치 프로세스** 또는 **관리자 승인 기반 프로세스**로 나뉘어 동작합니다.

```mermaid
graph LR
    IA([Patch Impact Agent 완료]) --> InitSlack[초기 슬랙 출력: 패치 대상 서버 정보]
    
    InitSlack -->|자동 패치 프로세스| EA[Patch Exec Agent 실행]
    
    InitSlack -->|승인 대기 프로세스| Admin[관리자 확인 및 승인 버튼 클릭]
    Admin -->|Webhook| API[API Gateway]
    API --> Lambda[AWS Lambda]
    Lambda -->|Agent Wake-up| EA
    
    EA --> SSM[SSM 접속 및 패치 실행]
    SSM --> RealTimeSlack[실시간 슬랙 출력: 패치 로그]
    RealTimeSlack --> DoneSlack([패치 완료 슬랙 메시지 출력])
