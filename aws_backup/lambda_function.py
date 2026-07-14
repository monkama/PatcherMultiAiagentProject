import os
import json
import base64
import boto3
from urllib.parse import parse_qs


AWS_REGION = os.environ["AWS_REGION"]
RUNTIME_ARN = os.environ["AGENTCORE_RUNTIME_ARN"]

agentcore_client = boto3.client(
    "bedrock-agentcore",
    region_name=AWS_REGION
)


def lambda_handler(event, context):
    try:
        body = event.get("body", "")

        if event.get("isBase64Encoded"):
            body = base64.b64decode(body).decode("utf-8")

        if "challenge" in body:
            return {
                "statusCode": 200,
                "body": json.loads(body).get("challenge")
            }

        if body.startswith("payload="):
            parsed_body = parse_qs(body)
            slack_payload = json.loads(parsed_body["payload"][0])

            if "actions" in slack_payload:
                val = slack_payload["actions"][0]["value"]

                if "::" in val:
                    cve_id = val.split("::")[0].replace("approve_", "")
                    inst_str = val.split("::")[1]

                    prompt_text = (
                        f"[🚨 수동 승인 완료] 관리자가 승인했습니다. "
                        f"대상 취약점: {cve_id}, "
                        f"대상 인스턴스 ID: [{inst_str}]"
                    )

                    payload_for_agent = {
                        "prompt": prompt_text,
                        "impact_data": {
                            "approved_cve": cve_id,
                            "approved_instances": [
                                i.strip()
                                for i in inst_str.split(",")
                                if i.strip()
                            ]
                        }
                    }

                    binary_payload = json.dumps(
                        payload_for_agent,
                        ensure_ascii=False
                    ).encode("utf-8")

                    print(f"[LOG] Invoking AgentCore for {cve_id}")

                    response = agentcore_client.invoke_agent_runtime(
                        agentRuntimeArn=RUNTIME_ARN,
                        payload=binary_payload
                    )

                    status_code = (
                        response
                        .get("ResponseMetadata", {})
                        .get("HTTPStatusCode")
                    )

                    print(f"[LOG] Success: {status_code}")

        return {"statusCode": 200, "body": ""}

    except Exception as e:
        print(f"[ERROR] {str(e)}")
        return {"statusCode": 200, "body": "fail"}