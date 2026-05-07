import json

def build_agent_mission(user_prompt: str, approval_context: str, impact_assessment_data: dict) -> str:
    return f"""
{user_prompt}
{approval_context}

[참조 데이터]
영향도 분석 결과: 
{json.dumps(impact_assessment_data, ensure_ascii=False)}

[🚨 임무 지침]
너는 보안 패치 실행 계획을 수립하는 AI다. 
분석 결과를 바탕으로 아래 JSON 규격을 채워라. 오직 마크다운(```json) 블록 하나만 출력하라.

[JSON 필드 가이드]
- description: 취약점에 대한 한 줄 설명
- action: 구체적인 기술적 조치 사항
- manual_reason: 수동 승인이 필요한 이유 (Log4j 등)

```json
{{
    "summary": "총 4대의 인스턴스 중, 2대는 자율 패치 스크립트를 생성했고 2대는 승인 대기로 분류했습니다.",
    "patch_plans": [
        {{
            "cve_id": "CVE-2021-44228",
            "product": "Apache Log4j2",
            "description": "Apache Log4j2의 JNDI 기능에서 원격 코드 실행 취약점 (Log4Shell)",
            "action": "기존 취약 JAR 파일을 제거한 후, 안전한 버전(2.17.1 이상)의 JAR 파일을 재배치합니다.",
            "auto_patch_instances": [],
            "manual_approval_instances": ["i-0a9532429e01d003f", "i-0c0758a81884e6056"],
            "manual_reason": "핵심 비즈니스 App 서버의 무단 재시작 방지 및 관리자 검증 필요"
        }},
        {{
            "cve_id": "CVE-2021-23017",
            "product": "F5 NGINX",
            "description": "NGINX의 ngx_resolver_copy() 함수에서 메모리 손상을 유발할 수 있는 Off-by-one 취약점",
            "action": "기존 취약 파일을 강제 제거한 후, 최신 소스를 자율적으로 빌드하여 재설치합니다.",
            "auto_patch_instances": ["i-0c520106fd542c5f4", "i-0eaad4f5cd4a529a5"],
            "manual_approval_instances": [],
            "manual_reason": ""
        }}
    ],
    "patch_executions": [
        {{
            "instance_id": "인스턴스_ID",
            "script": "상세_배시_스크립트"
        }}
    ]
}}
"""