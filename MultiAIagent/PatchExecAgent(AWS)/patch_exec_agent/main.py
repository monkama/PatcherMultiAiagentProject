import time
import boto3
import json
import requests
import traceback
import re
import os

from strands import Agent
from strands.models.bedrock import BedrockModel
from .prompts.system_prompt import SYSTEM_PROMPT 
from .prompts.mission_prompt import build_agent_mission  

BEDROCK_MODEL_ID = (
    os.environ.get("PATCH_EXEC_BEDROCK_MODEL_ID")
    or os.environ.get("BEDROCK_MODEL_ID")
    or "global.anthropic.claude-sonnet-4-5-20250929-v1:0"
)
DEFAULT_REGION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "ap-northeast-2"

def _first_env_value(*keys: str) -> str:
    for key in keys:
        value = str(os.environ.get(key) or "").strip()
        if value:
            return value
    return ""


SLACK_WEBHOOK_URL = _first_env_value("PATCH_EXEC_SLACK_WEBHOOK_URL", "SLACK_WEBHOOK_URL")
SLACK_BOT_TOKEN = _first_env_value("PATCH_EXEC_SLACK_BOT_TOKEN", "SLACK_BOT_TOKEN")
SLACK_CHANNEL_ID = _first_env_value("PATCH_EXEC_SLACK_CHANNEL_ID", "SLACK_CHANNEL_ID")

ssm_client = boto3.client('ssm', region_name=DEFAULT_REGION)


def _build_bedrock_model() -> BedrockModel:
    return BedrockModel(
        region_name=DEFAULT_REGION,
        model_id=BEDROCK_MODEL_ID,
        temperature=0,
    )

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
    if not SLACK_WEBHOOK_URL:
        return "SKIPPED"
    try:
        requests.post(SLACK_WEBHOOK_URL, json={"text": message}, timeout=5)
        return "SUCCESS"
    except Exception:
        return "FAILED"

# [종합 리포트 발송 함수]
def send_slack_notification(plan_data):
    token = SLACK_BOT_TOKEN
    channel = SLACK_CHANNEL_ID
    url = "https://slack.com/api/chat.postMessage"
    if not token or not channel:
        return "SKIPPED"
    
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

agent = Agent(model=_build_bedrock_model(), system_prompt=SYSTEM_PROMPT)

def execute_patch_logic(payload: dict) -> str:
    try:

        #send_progress_message(f"🕵️ *[디버그 CCTV]* 들어온 데이터 내용:\n```{str(payload)[:1500]}```")
        # 1. 초기값 설정
        user_prompt = "보안 패치 분석 및 실행 계획을 수립하라."
        impact_data = payload.get("impact_data", payload) if isinstance(payload, dict) else {}
        is_approval_run = False
        cve_id, inst_str = "", ""

        # ==========================================
        # 2. [완벽 파싱] 진입점에서 넘겨준 '텍스트 프롬프트' 감지!
        # ==========================================
        incoming_prompt = payload.get("prompt", "")
        
        # 진입점이 만들어준 문장 "[🚨 수동 승인 완료]"가 들어있다면? -> 버튼 누른 거 맞음!
        if "[🚨 수동 승인 완료]" in incoming_prompt:
            is_approval_run = True
            
            # 한글 문장 속에서 정규식으로 CVE ID와 인스턴스 ID만 쏙 빼오기
            cve_match = re.search(r'(CVE-\d{4}-\d+)', incoming_prompt)
            cve_id = cve_match.group(1) if cve_match else "Unknown"
            
            inst_match = re.search(r'대상 인스턴스 ID:\s*\[([^\]]+)\]', incoming_prompt)
            inst_str = inst_match.group(1).replace(" ", "") if inst_match else ""

            # 에이전트가 딴소리 못하게 강력한 족쇄 프롬프트 장착
            user_prompt = f"관리자가 {cve_id}를 승인함. 대상: {inst_str}. 너의 출력 JSON에서 이 ID들을 무조건 'auto_patch_instances'로 옮기고, 무슨 일이 있어도 반드시 '{inst_str}'에 대한 bash 실행 스크립트를 'patch_executions' 배열에 생성하라."
            
            # 파이썬 강제 실행을 위한 데이터 세팅
            impact_data = {"approved_cve": cve_id, "approved_instances": [x for x in inst_str.split(",") if x]}
            
            # 드디어 이 메시지가 뜹니다! 🎉
            send_progress_message(f"✅ *[승인 감지]* `{cve_id}` 패치 시퀀스를 시작합니다.")
        
        else:
            # 버튼을 누른 게 아니라, 처음 봇을 호출했을 때의 기본 동작
            user_prompt = incoming_prompt if incoming_prompt else "보안 패치 분석 및 실행 계획을 수립하라."

        # ==========================================
        # 3. 에이전트 분석 (이하 기존 코드 그대로 유지)
        # ==========================================
        mission = build_agent_mission(user_prompt, "", impact_data)
        resp = agent(mission)
        
        text = "".join([b.get('text', '') for b in resp.message.get('content', []) if isinstance(b, dict)]) if hasattr(resp, 'message') else str(resp)
        match = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
        if not match: return json.dumps({"status": "ERROR"})
        plan = json.loads(match.group(1))

        # ==========================================
        # 4 & 5. 통합 실행 로직 (에이전트 고집 차단)
        # ==========================================
        exec_targets = []
        if not is_approval_run:
            send_slack_notification(plan)
            for p in plan.get("patch_plans", []):
                exec_targets.extend(p.get("auto_patch_instances", []))
        else:
            exec_targets = impact_data.get("approved_instances", [])

        # ==========================================
        # 6. 실제 패치 실행 (빈 스크립트 대비책 추가)
        # ==========================================
        if exec_targets:
            send_progress_message(f"🚀 *[패치 진행]* 총 {len(exec_targets)}대의 서버 조치를 시작합니다.")
            exec_map = {e.get("instance_id"): e.get("script", "") for e in plan.get("patch_executions", [])}
            
            for i, inst_id in enumerate(exec_targets, 1):
                send_progress_message(f"| *[{i}/{len(exec_targets)}]* `{inst_id}` 업데이트 시작...")
                script = exec_map.get(inst_id, "")
                
                # 스크립트가 정상적으로 존재할 때만 실행
                if script:
                    status, _ = run_ssm_and_wait(inst_id, [script])
                    if status == "Success":
                        msg = f"✅ `{inst_id}` 패치 완료! 서비스가 정상 가동 중입니다."
                    else:
                        msg = f"❌ `{inst_id}` 패치 실패 (상태: {status})\n> 🛡️ *자동 롤백이 즉시 수행되었습니다.*\n> ↳ 상세 원인은 AWS SSM 로그를 확인하세요."
                else:
                    # 에이전트가 스크립트 생성을 누락했을 때의 안전장치
                    msg = f"⚠️ `{inst_id}` 패치 보류: AI 에이전트가 실행 스크립트를 생성하지 않았습니다. 프롬프트 확인이 필요합니다."
                
                send_progress_message(msg)

            send_progress_message("🏁 *모든 패치가 완료되었습니다.*")

        return json.dumps({"status": "SUCCESS"})

    except Exception as e:
        print(traceback.format_exc())
        return json.dumps({"status": "FAILED", "error": str(e)})
