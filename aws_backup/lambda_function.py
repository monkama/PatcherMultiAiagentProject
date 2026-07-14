import os
import json
import time
import hmac
import hashlib
import base64
import boto3

from urllib.parse import parse_qs


AWS_REGION = os.environ["AWS_REGION"]
RUNTIME_ARN = os.environ["AGENTCORE_RUNTIME_ARN"]
SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"]

agentcore_client = boto3.client(
    "bedrock-agentcore",
    region_name=AWS_REGION,
)


def get_header(event: dict, header_name: str) -> str:
    """API Gateway 헤더를 대소문자 구분 없이 조회합니다."""
    headers = event.get("headers") or {}
    target = header_name.lower()

    for key, value in headers.items():
        if key.lower() == target:
            return str(value or "")

    return ""


def verify_slack_request(event: dict, raw_body: str) -> bool:
    """Slack Signing Secret을 이용해 요청의 위조 및 재전송 여부를 검증합니다."""
    timestamp = get_header(event, "X-Slack-Request-Timestamp")
    slack_signature = get_header(event, "X-Slack-Signature")

    if not timestamp or not slack_signature:
        return False

    try:
        request_timestamp = int(timestamp)
    except ValueError:
        return False

    # 5분 이상 지난 요청은 재전송 공격으로 간주합니다.
    if abs(time.time() - request_timestamp) > 60 * 5:
        return False

    signature_base = f"v0:{timestamp}:{raw_body}"

    calculated_signature = (
        "v0="
        + hmac.new(
            SLACK_SIGNING_SECRET.encode("utf-8"),
            signature_base.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
    )

    return hmac.compare_digest(
        calculated_signature,
        slack_signature,
    )


def lambda_handler(event, context):
    try:
        # Slack이 전송한 원본 body를 그대로 확보합니다.
        body = event.get("body") or ""

        if event.get("isBase64Encoded"):
            body = base64.b64decode(body).decode("utf-8")

        # payload를 파싱하기 전에 Slack 서명을 먼저 검증합니다.
        if not verify_slack_request(event, body):
            print("[SECURITY] Invalid Slack signature")

            return {
                "statusCode": 401,
                "body": "invalid signature",
            }

        # Slack URL Verification
        content_type = get_header(event, "Content-Type")

        if "application/json" in content_type:
            request_json = json.loads(body)

            if request_json.get("type") == "url_verification":
                return {
                    "statusCode": 200,
                    "body": request_json.get("challenge", ""),
                }

        # Slack Interactivity Payload
        if body.startswith("payload="):
            parsed_body = parse_qs(body)

            payload_values = parsed_body.get("payload")
            if not payload_values:
                return {
                    "statusCode": 400,
                    "body": "missing payload",
                }

            slack_payload = json.loads(payload_values[0])
            actions = slack_payload.get("actions") or []

            if not actions:
                return {
                    "statusCode": 200,
                    "body": "",
                }

            action_value = str(actions[0].get("value") or "")

            if "::" not in action_value:
                return {
                    "statusCode": 400,
                    "body": "invalid action value",
                }

            approval_value, instance_value = action_value.split("::", 1)

            cve_id = approval_value.removeprefix("approve_")
            instance_ids = [
                instance_id.strip()
                for instance_id in instance_value.split(",")
                if instance_id.strip()
            ]

            prompt_text = (
                "[수동 승인 완료] 관리자가 승인했습니다. "
                f"대상 취약점: {cve_id}, "
                f"대상 인스턴스 ID: [{','.join(instance_ids)}]"
            )

            payload_for_agent = {
                "prompt": prompt_text,
                "impact_data": {
                    "approved_cve": cve_id,
                    "approved_instances": instance_ids,
                },
            }

            binary_payload = json.dumps(
                payload_for_agent,
                ensure_ascii=False,
            ).encode("utf-8")

            print(f"[LOG] Invoking AgentCore for {cve_id}")

            response = agentcore_client.invoke_agent_runtime(
                agentRuntimeArn=RUNTIME_ARN,
                payload=binary_payload,
            )

            status_code = (
                response
                .get("ResponseMetadata", {})
                .get("HTTPStatusCode")
            )

            print(f"[LOG] AgentCore response status: {status_code}")

        return {
            "statusCode": 200,
            "body": "",
        }

    except Exception as exc:
        print(f"[ERROR] {type(exc).__name__}: {exc}")

        return {
            "statusCode": 500,
            "body": "internal error",
        }