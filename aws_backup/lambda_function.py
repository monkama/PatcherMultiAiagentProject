import json
import base64
import boto3
from urllib.parse import parse_qs

# [설정] Region과 ARN이 정확한지 마지막으로 확인하세요.
agentcore_client = boto3.client('bedrock-agentcore', region_name='ap-northeast-2')
RUNTIME_ARN = "arn:aws:bedrock-agentcore:ap-northeast-2:012345678910:runtime/patch_exec_agent"

def lambda_handler(event, context):
    try:
        # 1. 데이터 수신 및 디코딩 (Slack -> Lambda)
        body = event.get('body', '')
        if event.get('isBase64Encoded'):
            body = base64.b64decode(body).decode('utf-8')
        
        # URL Verification 처리
        if 'challenge' in body:
            return {"statusCode": 200, "body": json.loads(body).get('challenge')}

        # 2. 데이터 파싱 (Slack Payload 추출)
        if body.startswith('payload='):
            parsed_body = parse_qs(body)
            slack_payload = json.loads(parsed_body['payload'][0])
            
            if 'actions' in slack_payload:
                val = slack_payload['actions'][0]['value']
                
                if "::" in val:
                    cve_id = val.split("::")[0].replace("approve_", "")
                    inst_str = val.split("::")[1]
                    
                    # [핵심] main.py의 92행, 99행 정규식을 완벽히 트리거하는 문자열 조합
                    prompt_text = (
                        f"[🚨 수동 승인 완료] 관리자가 승인했습니다. "
                        f"대상 취약점: {cve_id}, 대상 인스턴스 ID: [{inst_str}]"
                    )
                    
                    payload_for_agent = {
                        "prompt": prompt_text,
                        "impact_data": {
                            "approved_cve": cve_id, 
                            "approved_instances": [i.strip() for i in inst_str.split(",") if i.strip()]
                        }
                    }
                    
                    # 3. 데이터 전송 (Lambda -> AgentCore)
                    # ensure_ascii=False로 한글/이모지 원형 보존, .encode()로 바이트화하여 500 에러 방지
                    binary_payload = json.dumps(payload_for_agent, ensure_ascii=False).encode('utf-8')
                    
                    print(f"[LOG] Invoking AgentCore for {cve_id}")
                    
                    response = agentcore_client.invoke_agent_runtime(
                        agentRuntimeArn=RUNTIME_ARN,
                        payload=binary_payload
                    )
                    
                    print(f"[LOG] Success: {response.get('ResponseMetadata', {}).get('HTTPStatusCode')}")
                    
        return {"statusCode": 200, "body": ""}

    except Exception as e:
        print(f"[ERROR] {str(e)}")
        return {"statusCode": 200, "body": "fail"}
