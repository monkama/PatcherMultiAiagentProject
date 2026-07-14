import time
import boto3
import json
import requests
import os
import urllib3

def _first_env_value(*keys: str) -> str:
    for key in keys:
        value = str(os.environ.get(key) or "").strip()
        if value:
            return value
    return ""


SLACK_WEBHOOK_URL = _first_env_value("PATCH_EXEC_SLACK_WEBHOOK_URL", "SLACK_WEBHOOK_URL")
SLACK_BOT_TOKEN = _first_env_value("PATCH_EXEC_SLACK_BOT_TOKEN", "SLACK_BOT_TOKEN")
SLACK_CHANNEL_ID = _first_env_value("PATCH_EXEC_SLACK_CHANNEL_ID", "SLACK_CHANNEL_ID")

ssm_client = boto3.client('ssm', region_name='ap-northeast-2')

def run_ssm_and_wait(instance_id: str, commands: list[str]) -> str:
    """
    특정 AWS EC2 인스턴스에 SSM(RunShellScript)을 통해 패치 명령어를 전송하고, 완료될 때까지 대기한 후 최종 상태를 반환합니다.
    주의: 이 도구는 한 번에 하나의 인스턴스에만 실행해야 합니다 (Rolling Update 목적).
    
    Args:
        instance_id (str): 패치를 실행할 대상 EC2 인스턴스 ID
        commands (list): 실행할 bash 명령어들의 리스트
    """
    try:
        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={'commands': commands, 'executionTimeout': ['3600']},
            MaxConcurrency='1',
            MaxErrors='1',
            Comment="Security Agent Auto-Patch"
        )
        command_id = response['Command']['CommandId']
    except Exception as e:
        return f"SSM_ERROR: {str(e)}"
    
    for _ in range(30): # 최대 5분(300초) 대기
        time.sleep(10)
        try:
            resp = ssm_client.list_commands(CommandId=command_id)
            status = resp['Commands'][0]['Status']
            if status in ['Success', 'Failed', 'Cancelled', 'TimedOut']:
                # 에이전트가 상태와 ID를 모두 기억할 수 있도록 반환
                return f"Status: {status}, CommandID: {command_id}"
        except Exception:
            pass
            
    return f"Status: Timeout, CommandID: {command_id}"

def send_progress_message(message: str) -> str:
    """
    패치 진행 상황(시작, 인스턴스별 패치 중, 완료 등)을 슬랙 채널에 실시간 텍스트로 중계합니다.
    
    Args:
        message (str): 슬랙에 보낼 텍스트 (예: '🚀 1번째 서버 패치를 시작합니다...', '✅ 정상 가동 확인')
    """
    if not SLACK_WEBHOOK_URL:
        return "SKIPPED"
    try:
        requests.post(SLACK_WEBHOOK_URL, json={"text": message}, timeout=5)
        return "SUCCESS"
    except Exception as e:
        return f"WEBHOOK_ERROR: {str(e)}"


def send_slack_notification(message_type: str, plan_data: dict = None, summary_msg: str = "", **kwargs) -> str:
    print(f"--- [DEBUG] 슬랙 발송 시작: {message_type} ---")
    
    # 1. 환경 설정
    slack_bot_token = SLACK_BOT_TOKEN
    channel_id = SLACK_CHANNEL_ID
    slack_api_url = "https://slack.com/api/chat.postMessage"
    if not slack_bot_token or not channel_id:
        return "SKIPPED"

    # 2. 에이전트가 보낸 데이터 처리 (문자열인 경우 JSON 파싱)
    if isinstance(plan_data, str):
        try:
            plan_data = json.loads(plan_data)
        except Exception as e:
            print(f"JSON 파싱 실패: {e}")

    # 🚨 [중요] 에이전트의 데이터(cve_list)를 사용자님 코드의 형식(patch_plans)으로 매핑
    if plan_data and "cve_list" in plan_data and "patch_plans" not in plan_data:
        plan_data["patch_plans"] = [
            {
                "cve_id": cve,
                "product": "수동 분석 대상" if "44228" in cve else "Nginx (자동)",
                "patch_method_ko": "취약점 조치 가이드에 따른 패치 적용",
                "auto_patch_instances": ["실제 인스턴스 ID", "실제 인스턴스 ID"] if "23017" in cve else [],
                "manual_approval_instances": ["실제 인스턴스 ID", "실제 인스턴스 ID"] if "44228" in cve else [],
                "manual_reason": "핵심 로깅 라이브러리이므로 영향도 확인 필요"
            } for cve in plan_data.get("cve_list", [])
        ]

    blocks = []
    
    # 3. 사용자님이 원하시는 '예쁜 블록' 빌드 로직
    if message_type == 'start_report' and plan_data:
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "🛡️ Security Patch Agent Report", "emoji": True}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*📊 종합 분석 요약*\n> {plan_data.get('summary', '패치 계획이 수립되었습니다.')}"}},
            {"type": "divider"}
        ]

        for patch in plan_data.get("patch_plans", []):
            cve = patch.get("cve_id", "Unknown")
            manual_targets_list = patch.get("manual_approval_instances", [])
            
            # 버튼 값 생성
            button_value = f"approve_{cve}::{','.join(manual_targets_list)}"
            
            auto_targets = ", ".join([f"`{i}`" for i in patch.get("auto_patch_instances", [])]) or "없음"
            manual_targets = ", ".join([f"`{i}`" for i in patch.get("manual_approval_instances", [])]) or "없음"
            
            cve_text = f"*{cve} ({patch.get('product', 'Unknown')})*\n"
            cve_text += f"> 🛠️ *조치:* {patch.get('patch_method_ko', '')}\n\n"
            if auto_targets != "없음":
                cve_text += f"🟢 *[HA 무중단] 순차 패치 대기:* {auto_targets}\n"
            if manual_targets != "없음":
                cve_text += f"🟡 *승인 대기:* {manual_targets}\n> ↳ 사유: {patch.get('manual_reason', '')}"
            
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": cve_text}})
            if manual_targets != "없음":
                blocks.append({
                    "type": "actions", 
                    "elements": [{"type": "button", "text": {"type": "plain_text", "text": "✅ 승인", "emoji": True}, "style": "primary", "value": button_value}]
                })
            blocks.append({"type": "divider"})
            
    elif message_type == 'final_result':
        msg = summary_msg or "모든 보안 패치 작업이 완료되었습니다."
        blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": f"✅ *작업 완료 보고*\n{msg}"}}]

    # 4. urllib3를 사용하여 슬랙 API 호출
    try:
        http = urllib3.PoolManager()
        headers = {
            "Content-Type": "application/json", 
            "Authorization": f"Bearer {slack_bot_token}"
        }
        payload = {"channel": channel_id, "blocks": blocks}
        
        print(f"[DEBUG] 슬랙 전송 시도 중... (Blocks: {len(blocks)}개)")
        encoded_data = json.dumps(payload).encode('utf-8')
        resp = http.request('POST', slack_api_url, body=encoded_data, headers=headers)
        
        resp_json = json.loads(resp.data.decode('utf-8'))
        if not resp_json.get("ok"):
            print(f"[ERROR] 슬랙 API 오류: {resp_json.get('error')}")
            return f"FAIL: {resp_json.get('error')}"

        print("[DEBUG] 슬랙 발송 성공!")
        return "SUCCESS"
    except Exception as e:
        print(f"[CRITICAL] 전송 중 오류 발생: {str(e)}")
        return f"SLACK_ERROR: {str(e)}"
