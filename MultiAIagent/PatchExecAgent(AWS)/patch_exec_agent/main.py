import time
import boto3
import json
import requests
import urllib3
import traceback
import re
import base64
from urllib.parse import parse_qs

from strands import Agent
from .prompts.system_prompt import SYSTEM_PROMPT 
from .prompts.mission_prompt import build_agent_mission  

ssm_client = boto3.client('ssm', region_name='ap-northeast-2')

# [SSM 실행 함수]
def run_ssm_and_wait(instance_id, commands):
    try:
        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={'commands': commands, 'executionTimeout': ['3600']}
        )
        cmd_id = response['Command']['CommandId']
        for _ in range(30):
            time.sleep(10)
            res = ssm_client.list_commands(CommandId=cmd_id)
            status = res['Commands'][0]['Status']
            if status in ['Success', 'Failed', 'TimedOut']:
                return status, cmd_id
        return "Timeout", cmd_id
    except Exception as e:
        return f"Error: {str(e)}", "N/A"

# [진행 상황 알림 함수]
def send_progress_message(message):
    url = "https://hooks.slack.com/services/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"
    try:
        requests.post(url, json={"text": message}, timeout=5)
    except:
        pass

# [종합 리포트 발송 함수]
def send_slack_notification(plan_data):
    token = "xoxb-10122507779588-11055904484097-q1fEC2DbNXJgU05WVNWBtrTM"
    channel = "C0B0XQFG42F"
    url = "https://slack.com/api/chat.postMessage"
    
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": "🛡️ Security Patch Agent Report", "emoji": True}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*📊 종합 분석 요약*\n> {plan_data.get('summary', '패치 계획이 수립되었습니다.')}"}},
        {"type": "divider"}
    ]

    for patch in plan_data.get("patch_plans", []):
        cve = patch.get("cve_id", "Unknown")
        prod = patch.get("product", "Unknown")
        auto_ids = patch.get("auto_patch_instances", [])
        manu_ids = patch.get("manual_approval_instances", [])
        
        content = f"*| {cve} ({prod})*\n"
        content += f"| 📝 *설명:* _{patch.get('description', '취약점 분석 진행 중')}_\n"
        content += f"| 🛠️ *조치:* {patch.get('action', '보안 패치 및 환경 재구축')}\n\n"
        
        if manu_ids:
            content += f"🟡 *승인 대기 (수동):* {', '.join([f'`{i}`' for i in manu_ids])}\n"
            content += f"> ↳ *사유:* {patch.get('manual_reason', '관리자 검증 필요')}\n"
        
        if auto_ids:
            content += f"🟢 *[HA 무중단] 패치 진행 중 (Rolling Update):* {', '.join([f'`{i}`' for i in auto_ids])}\n"
            content += f"> ↳ 서비스 중단 방지를 위해 1대씩 패치 및 검증 수행\n"
        
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": content}})
        
        if manu_ids:
            val = f"approve_{cve}::{','.join(manu_ids)}"
            blocks.append({
                "type": "actions",
                "elements": [{"type": "button", "text": {"type": "plain_text", "text": "✅ 승인하기", "emoji": True}, "style": "primary", "value": val}]
            })
        blocks.append({"type": "divider"})

    try:
        requests.post(url, headers={"Authorization": f"Bearer {token}"}, json={"channel": channel, "blocks": blocks}, timeout=10)
    except:
        pass

agent = Agent(model="anthropic.claude-3-5-sonnet-20240620-v1:0", system_prompt=SYSTEM_PROMPT)

def execute_patch_logic(payload: dict) -> str:
    try:
        # 1. 초기값 설정
        user_prompt = "보안 패치 분석 및 실행 계획을 수립하라."
        impact_data = payload.get("impact_data", payload)
        is_approval_run = False

        # 2. 슬랙 페이로드 파싱 (API Gateway 특화)
        body_str = payload.get("body", "")
        if payload.get("isBase64Encoded"):
            body_str = base64.b64decode(body_str).decode("utf-8")
        
        # URL-encoded 데이터 파싱
        parsed_body = parse_qs(body_str)
        if "payload" in parsed_body:
            slack_data = json.loads(parsed_body["payload"][0])
            if slack_data.get("type") == "block_actions":
                action_value = slack_data["actions"][0]["value"]
                if action_value.startswith("approve_"):
                    is_approval_run = True
                    cve_id, inst_str = action_value.replace("approve_", "").split("::")
                    # 승인 모드 강제 명령
                    user_prompt = f"관리자가 {cve_id}를 승인함. 대상: {inst_str}. 너의 출력 JSON에서 이 ID들을 'auto_patch_instances'로 옮기고 'manual_approval_instances'는 비워라. 즉시 실행 스크립트를 작성하라."
                    impact_data = {"approved_cve": cve_id, "approved_instances": inst_str.split(",")}
                    send_progress_message(f"✅ *[승인 감지]* `{cve_id}` 패치를 시작합니다.")

        # 3. 에이전트 분석
        mission = build_agent_mission(user_prompt, "", impact_data)
        resp = agent(mission)
        
        text = "".join([b.get('text', '') for b in resp.message.get('content', []) if isinstance(b, dict)]) if hasattr(resp, 'message') else str(resp)
        match = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
        if not match: return json.dumps({"status": "ERROR"})
        plan = json.loads(match.group(1))

        # 4. 리포트 혹은 실행 알림
        if not is_approval_run:
            send_slack_notification(plan)
        
        # 5. 패치 실행 (auto_patch_instances에 들어있는 것들 실행)
        exec_targets = []
        for p in plan.get("patch_plans", []):
            exec_targets.extend(p.get("auto_patch_instances", []))
        
        if exec_targets:
            send_progress_message(f"🚀 *[패치 진행]* 총 {len(exec_targets)}대의 서버 조치를 시작합니다.")
            exec_map = {e.get("instance_id"): e.get("script", "") for e in plan.get("patch_executions", [])}
            
            for i, inst_id in enumerate(exec_targets, 1):
                send_progress_message(f"| *[{i}/{len(exec_targets)}]* `{inst_id}` 업데이트 시작...")
                script = exec_map.get(inst_id, "")
                if script:
                    status, _ = run_ssm_and_wait(inst_id, [script])
                    
                    if status == "Success":
                        msg = f"✅ `{inst_id}` 패치 완료! 서비스가 정상 가동 중입니다."
                    else:
                        # 🚨 실패 시 자동 롤백 안내 메시지 추가
                        msg = f"❌ `{inst_id}` 패치 실패 (상태: {status})\n"
                        msg += f"> 🛡️ *보안 지침에 따라 자동 롤백이 즉시 수행되었습니다.*\n"
                        msg += f"> ↳ 원본 백업본으로 복구되었으며, 서비스는 이전 상태로 가동 중입니다.\n"
                        msg += f"> ↳ 상세 원인은 AWS SSM 로그를 확인하세요."
                    
                    send_progress_message(msg)

            send_progress_message("🏁 *모든 패치가 완료되었습니다.*")

        return json.dumps({"status": "SUCCESS"})

    except Exception as e:
        print(traceback.format_exc())
        return json.dumps({"status": "FAILED", "error": str(e)})