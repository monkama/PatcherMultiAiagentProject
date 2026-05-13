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

프로세스 상세
초기 슬랙 출력: Patch Impact Agent의 동작이 끝나면, 어떤 서버를 패치할 것인지에 대한 요약 정보가 슬랙에 즉시 출력됩니다.

실행 분기:

자동 패치: 초기 알림 후 즉시 Patch_exec_agent가 실행됩니다.

관리자 승인: 슬랙에 활성화된 승인 버튼을 관리자가 클릭하면, API Gateway와 Lambda를 거쳐 대기 중이던 에이전트가 실행됩니다.

패치 및 실시간 모니터링: 에이전트가 AWS Systems Manager(SSM)를 통해 대상 서버에 패치 명령을 내리며, 실행될 때마다 실시간으로 슬랙에 진행 상황이 출력됩니다.

완료 알림: 모든 패치 작업이 종료되면 최종 패치 완료 메시지가 슬랙에 전송됩니다.
