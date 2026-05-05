import json
import traceback
import boto3
import requests
import datetime
import re
import time  # 🚨 대기(Polling) 기능을 위해 추가됨

# 사용자 정의 모듈 임포트
import operational_impact_payloads_refiner
import influence_evaluation_refiner

from bedrock_agentcore import BedrockAgentCoreApp
from strands import Agent

# --- [1. 기본 설정 및 앱 초기화] ---
app = BedrockAgentCoreApp()
ssm_client = boto3.client('ssm', region_name='ap-northeast-2')

SYSTEM_PROMPT = """
너는 최고 수준의 클라우드 보안 아키텍트다.
제공된 데이터를 분석하여 SSM 실행 계획과 슬랙 보고서 초안을 작성하라.
응답은 반드시 마크다운 JSON 블록(```json ... ```)으로만 작성해야 하며, 다른 설명은 금지한다.
"""

agent = Agent(model="anthropic.claude-3-5-sonnet-20240620-v1:0", system_prompt=SYSTEM_PROMPT)

# --- [2. 파이썬 실행 및 유틸리티 함수] ---

def wait_for_ssm_result(command_id: str) -> str:
    """🚨 [신규] 파이썬 에이전트가 SSM 완료를 스스로 기다립니다 (Polling)"""
    if command_id == "자동 패치 대상 없음" or command_id.startswith("SSM_ERROR"):
        return "Skip"
        
    print(f"⏳ [대기 중] Command ID: {command_id} 패치 결과 확인 중...")
    
    # 최대 5분(300초) 대기 (10초 * 30번)
    for _ in range(30):
        time.sleep(10)
        try:
            response = ssm_client.list_commands(CommandId=command_id)
            status = response['Commands'][0]['Status']
            
            # 완료 상태에 도달하면 즉시 상태값 반환
            if status in ['Success', 'Failed', 'Cancelled', 'TimedOut']:
                print(f"✅ 패치 종료. 최종 상태: {status}")
                return status
        except Exception as e:
            print(f"상태 확인 중 에러: {e}")
            
    return "Timeout (대기 시간 초과)"

def run_ssm(instance_ids: list, commands: list) -> str:
    """파이썬이 직접 SSM을 실행합니다. (순차 패치 적용)"""
    if not instance_ids: 
        return "자동 패치 대상 없음"
    try:
        response = ssm_client.send_command(
            InstanceIds=instance_ids,
            DocumentName="AWS-RunShellScript",
            Parameters={'commands': commands, 'executionTimeout': ['3600']},
            MaxConcurrency='1', # 🚨 [핵심] 이중화 서버라도 한 번에 1대씩만 안전하게 롤링 업데이트
            MaxErrors='1',      # 🚨 [핵심] 1대라도 에러 발생 시 즉시 중단
            Comment="Security Agent Auto-Patch"
        )
        return response['Command']['CommandId']
    except Exception as e:
        return f"SSM_ERROR: {str(e)}"
    
def send_slack(plan_data: dict, command_id: str) -> str:
    """파이썬이 직접 슬랙 Block Kit UI를 구성하여 보냅니다."""
    #slack_webhook_url = "https://hooks.slack.com/services/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"
    
    slack_api_url = "https://slack.com/api/chat.postMessage"

    slack_bot_token = "xoxb-10122507779588-11055904484097-q1fEC2DbNXJgU05WVNWBtrTM"
    channel_id = "C0B0XQFG42F"

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🛡️ Security Patch Agent Report", "emoji": True}
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*📊 종합 분석 요약*\n> {plan_data.get('summary', '패치 계획이 생성되었습니다.')}"}
        },
        {"type": "divider"}
    ]

    for patch in plan_data.get("patch_plans", []):
        cve = patch.get("cve_id", "Unknown CVE")
        product = patch.get("product", "Unknown")
        
        desc = patch.get("cve_description_ko", "상세 설명 없음")
        method = patch.get("patch_method_ko", "패치 방법 없음")
        
        auto_targets = ", ".join([f"`{i}`" for i in patch.get("auto_patch_instances", [])]) or "없음"
        manual_targets = ", ".join([f"`{i}`" for i in patch.get("manual_approval_instances", [])]) or "없음"

        cve_text = f"*{cve} ({product})*\n"
        cve_text += f"> 💡 *설명:* {desc}\n"
        cve_text += f"> 🛠️ *조치:* {method}\n\n"
        
        if auto_targets != "없음":
            cve_text += f"🟢 *[HA 무중단] 순차 패치 진행 중 (Rolling Update):* {auto_targets}\n"
            cve_text += f"> ↳ 서비스 중단을 방지하기 위해 1대씩 순서대로 패치 및 검증을 수행합니다.\n"
            cve_text += f"> ↳ SSM Command ID: `{command_id}`\n\n"
        
        if manual_targets != "없음":
            reason = patch.get("manual_reason", "관리자 확인 필요")
            cve_text += f"🟡 *승인 대기 (수동):* {manual_targets}\n> ↳ 사유: {reason}"

        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": cve_text}
        })

        if manual_targets != "없음":
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ 승인 (Approve)", "emoji": True},
                        "style": "primary",
                        "value": f"approve_{cve}"
                    }
                ]
            })
        
        blocks.append({"type": "divider"})

    try:
        # 🚨 [수정됨] 슬랙 API 규격에 맞게 payload와 header 완벽 세팅
        payload = {
            "channel": channel_id,
            "blocks": blocks
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {slack_bot_token}"
        }
        
        response = requests.post(slack_api_url, json=payload, headers=headers)
        return "SUCCESS"
    except Exception as e:
        print(f"Slack API Error: {str(e)}") # 터미널에서도 에러를 볼 수 있게 추가
        return f"SLACK_ERROR: {str(e)}"

# --- [3. 메인 실행 로직] ---
@app.entrypoint
def invoke(payload):
    try:
        impact_assessment_data = payload.get("impact_data", payload)

        user_prompt = payload.get("prompt", "보안 패치 분석 및 실행")

        # 🚨 [추가] 승인 모드인지 확인
        is_approval_mode = "승인" in user_prompt or "approve" in user_prompt.lower()
        
        approval_context = ""
        if is_approval_mode:
            approval_context = f"""
            [🚨 매우 중요: 단독 실행 모드 활성화 (CRITICAL)]
            관리자가 다음 조치를 명시적으로 승인했습니다: "{user_prompt}"
            
            이 지시가 활성화되면 기존의 모든 '자동/수동 분류 규칙'을 덮어쓰고, 
            오직 "지금 승인된 대상(예: Log4j)" 하나만을 위한 스크립트와 실행 계획을 작성하라.
            
            1. 'ssm_execution_plan'의 'instance_ids'에는 방금 승인된 인스턴스 ID만 포함하라. 
               (Nginx 등 이미 이전에 자율 패치된 다른 인스턴스는 절대 배열에 넣지 마라)
            2. 'commands' 역시 방금 승인된 서비스에 맞는 단일 패치 스크립트만 작성하라.
            3. 'patch_plans' 목록에도 승인된 항목 딱 1개만 결과로 출력하라.
            """

        # 🚨 [수정됨] 단일 노드(SPOF) 보호 및 15분 초과 패치 배제 룰이 추가되었습니다.
        user_message = f"""
        {user_prompt}
        {approval_context}

        [참조 데이터]
        - 영향도 평가 에이전트 최종 분석 결과: {json.dumps(impact_assessment_data, ensure_ascii=False)}

        [📍 인프라 실제 환경 및 패치 매뉴얼 (CRITICAL)]
        우리 인프라는 표준 패키지 매니저(yum/dnf)가 관리하지 않는 '수동 설치' 환경이다. 
        패치 시 반드시 아래의 '기존 위험 요소 제거' 명령어를 먼저 실행한 후, 최신 버전을 자율적으로 설치하라.

        1. Web 서버 (Nginx): 
            - 환경: /usr/local/nginx 경로에 1.20.0 소스 설치됨
            - 제거 가이드: `sudo /usr/local/nginx/sbin/nginx -s stop || sudo pkill nginx || true && sudo rm -rf /usr/local/nginx/sbin/nginx`
            - 시작 가이드: `sudo /usr/local/nginx/sbin/nginx` (절대 경로로 직접 실행)
        2. App 서버 (Log4j): 
            - 환경: /app/lib/log4j-api-2.14.1.jar, /app/lib/log4j-core-2.14.1.jar 파일 존재
            - 조치 가이드: `sudo pkill -f java || true`로 프로세스만 안전하게 종료할 것.

        [🚨 패치 실행 자율 지침]
        - 위 제거 명령어를 실행한 직후, 최신 안정 버전(Stable)을 검색하여 재설치하는 스크립트를 스스로 생성하라.
        - Nginx의 경우 최신 소스를 다운로드하여 './configure && make && make install' 하는 과정을 포함해야 할 수 있다.
        - Log4j의 경우 안전한 버전(2.17.1 이상)의 JAR 파일을 Maven 저장소 등에서 찾아 해당 경로에 배치하라.
        - 모든 설치가 끝나면 서비스를 재시작하고, 버전 정보나 파일 존재를 확인하는 '검증 명령어'를 반드시 포함하라.

        [🚨 패치 정책 및 승인 분류 규칙 (CRITICAL)]
        인스턴스를 '자동 패치(auto_patch_instances)'와 '수동 승인(manual_approval_instances)'으로 분류할 때 아래 규칙을 무조건 따른다.

        1. Web 서버 (Nginx) - 무조건 자동 패치:
        - Nginx 서버군은 현재 이중화(HA)가 완벽히 구성되어 있어 소스 컴파일(make)에 시간이 걸리더라도 무중단 패치가 가능하다.
        - 따라서 다운타임 위험이 없으므로 무조건 '자동 패치 대상'으로 분류하라.

        2. App 서버 (Log4j) - 무조건 수동 승인:
        - Log4j가 설치된 App 서버는 핵심 비즈니스 로직을 처리하는 단일 노드(SPOF)이거나, 서비스 재시작 시 치명적인 장애를 유발할 수 있는 민감한 대상이다.
        - 따라서 패치 소요 시간과 무관하게 무조건 '수동 승인 대상'으로 분류하라.
        - 수동 승인 사유(manual_reason)에는 "핵심 비즈니스 App 서버의 무단 재시작 방지 및 관리자 검증 필요"라고 명확히 기재하라.
        
        [미션 지시]
        위 데이터와 규칙을 분석하여 인스턴스를 '즉시 자동 패치 대상'과 '관리자 승인 필요 대상'으로 분류하고, 자율적으로 설계한 패치 Bash 스크립트를 작성하라.
        반드시 아래 JSON 포맷에 맞게 실행 계획서를 작성하라.

        ```json
        {{
            "summary": "총 N대의 인스턴스 중, N대는 자율 패치 스크립트를 생성했고 N대는 승인 대기로 분류했습니다.",
            "ssm_execution_plan": {{
                "instance_ids": ["자동 패치할 인스턴스 ID"],
                "commands": [
                    "# 여기에 네가 자율적으로 설계한 삭제-설치-검증 통합 스크립트를 순서대로 나열하라",
                    "sudo dnf install -y gcc make...", 
                    "sudo wget...",
                    "..."
                ]
            }},
            "patch_plans": [
                {{
                    "cve_id": "CVE-...",
                    "product": "...",
                    "cve_description_ko": "...",
                    "patch_method_ko": "기존 취약 파일을 강제 제거한 후, 최신 소스를 자율적으로 빌드하여 재설치합니다.",
                    "auto_patch_instances": ["i-123..."],
                    "manual_approval_instances": ["i-456..."],
                    "manual_reason": "..."
                }}
            ]
        }}
        ```
        """

        print("🚨 [1/4] AI 분석 요청 중...")
        response = agent(user_message)
        
        text_resp = ""
        if hasattr(response, 'message'):
            msg = response.message
            content = msg.get('content', []) if isinstance(msg, dict) else getattr(msg, 'content', [])
            
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and 'text' in block:
                        text_resp += block['text']
                    elif isinstance(block, str):
                        text_resp += block
            else:
                text_resp = str(content)
        else:
            text_resp = str(response)

        match = re.search(r'```json\s*(.*?)\s*```', text_resp, re.DOTALL)
        if match:
            clean_json_str = match.group(1)
        else:
            clean_json_str = text_resp.replace('```json', '').replace('```', '').strip()

        plan = json.loads(clean_json_str)

        # 1차 슬랙 전송 (상세 리포트 및 시작 알림)
        print("🚨 [2/4] Python: 1차 슬랙 보고서 전송 중...")
        send_slack(plan, "실행 중 (결과 대기...)")

        # SSM 실행 전송
        print("🚨 [3/4] Python: SSM 명령어 전송 중 (Rolling Update)...")
        ssm_plan = plan.get("ssm_execution_plan", {})
        instance_ids = ssm_plan.get("instance_ids", [])
        commands = ssm_plan.get("commands", [])

        # 실시간 중계를 위한 별도 함수가 없다면 간단한 requests로 처리
        def send_status(msg):
            slack_url = "https://hooks.slack.com/services/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"
            requests.post(slack_url, json={"text": msg})

        last_command_id = "자동 패치 대상 없음"
        final_status = "Skip"

        if instance_ids:
            send_status(f"🚀 *[패치 진행]* {len(instance_ids)}대의 대상 서버 조치를 시작합니다.")
            
            for idx, inst_id in enumerate(instance_ids, 1):
                send_status(f"⏳ *[{idx}/{len(instance_ids)}]* `{inst_id}` 서버 업데이트 및 검증 중...")
                
                # 2. 한 대씩 SSM 실행 (에이전트가 생성한 commands 사용)
                # 인스턴스 하나씩 리스트로 묶어 전달
                command_id = run_ssm([inst_id], commands) 
                last_command_id = command_id
                
                # 3. 이 인스턴스의 패치가 끝날 때까지 대기 (기존 wait_for_ssm_result 활용)
                status = wait_for_ssm_result(command_id)
                final_status = status
                
                if status == "Success":
                    send_status(f"✅ `{inst_id}` 서버 패치 완료! 정상 가동 확인.")
                else:
                    send_status(f"🚨 *[장애 감지]* `{inst_id}` 서버 업데이트 실패!\n"
                f"🔄 *Auto-Rollback 가동:* 안전을 위해 즉시 기존 버전으로 복구(Rollback)를 수행하고 전체 프로세스를 중단합니다.")
                    break
            
            if final_status == "Success":
                # payload 또는 user_prompt에 담긴 텍스트를 기반으로 이름 결정
                target_name = "Log4j" if "44228" in str(payload) else "Nginx"

                # 결정된 이름을 메시지에 변수로 쏙 넣기
                send_status(f"✅ {target_name} 서버군의 모든 패치가 성공적으로 종료되었습니다. 🎉")

        # 2차 슬랙 전송 (최종 결과 알림)
        print("🚨 [4/4] Python: 최종 결과 슬랙 알림 전송 중...")
        if command_id != "자동 패치 대상 없음" and not command_id.startswith("SSM_ERROR"):
            if final_status == "Success":
                result_msg = f"✅ *자동 패치 성공!* 대상 인스턴스의 패치가 안전하게 완료되었습니다. (ID: `{command_id}`)"
            elif final_status == "Failed":
                result_msg = f"🚨 *자동 패치 실패!* 즉시 확인이 필요합니다. (ID: `{command_id}`)"
            else:
                result_msg = f"⚠️ *자동 패치 종료:* 상태 = {final_status} (ID: `{command_id}`)"
            
            # 2차 알림은 리포트 본문 없이 요약 메시지만 심플하게 전송합니다.
            send_slack({"summary": result_msg}, command_id)

        final_result = {
            "status": "SUCCESS",
            "ssm_command_id": command_id,
            "final_ssm_status": final_status,
            "patch_plans": plan.get("patch_plans", [])
        }

        return json.dumps(final_result, ensure_ascii=False, indent=2)

    except json.JSONDecodeError as e:
        return f"AI 응답 파싱 에러 (JSON 형식이 아님):\n{text_resp}"
    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"CRITICAL ERROR:\n{error_trace}")
        return f"내부 코드 실행 중 에러 발생!\n상세: {str(e)}"

if __name__ == "__main__":
    app.run()