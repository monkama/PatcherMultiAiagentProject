#!/usr/bin/env python3
"""
자산 매칭 에이전트 (AI-Agent 기반).

AWS Bedrock (Claude Haiku 4.5, Tool Use) 로 EC2 인스턴스 내부를 조사하여
취약점 평가에 필요한 자산/보안/네트워크/운영 컨텍스트를 수집한다.

두 가지 모드를 지원한다.
  1. 수집 모드 (--payload)
     payload.json 의 CVE 타겟을 받아 installed_software + network_context
     + security_context 등을 수집해 asset_info.json 으로 저장.
  2. 질의 응답 모드 (--query, swarm 대비)
     다른 Agent(위험도/운영영향 등)가 특정 질문을 주면,
     기존 asset_info.json 을 참조하면서 필요 시 EC2에서 추가 조사하여 답변한다.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import socket
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from typing import Optional

import boto3
from botocore.exceptions import ClientError
from strands import Agent, tool
from strands.models.openai import OpenAIModel


# ---------------------------------------------------------------------------
# 설정
# ---------------------------------------------------------------------------

OPENAI_MODEL_ID = os.environ.get("OPENAI_MODEL") or os.environ.get("OPENAI_MODEL_ID") or "gpt-4.1-mini"
OPENAI_BASE_URL = str(os.environ.get("OPENAI_BASE_URL") or "").strip()
COMMAND_TIMEOUT = 30
TOOL_OUTPUT_LIMIT = 2000  # LLM 에 돌려줄 tool 응답 최대 길이

DEFAULT_REGION = "ap-northeast-2"
SSM_POLL_INTERVAL = 1
SSM_MAX_WAIT = 45
QUERY_SSM_MAX_WAIT = int(os.environ.get("QUERY_SSM_MAX_WAIT", "20"))
QUERY_TOOL_CALL_LIMIT = int(os.environ.get("QUERY_TOOL_CALL_LIMIT", "8"))
QUERY_WALL_TIME_LIMIT = int(os.environ.get("QUERY_WALL_TIME_LIMIT", "90"))

_BLOCKED = re.compile(
    r"\b(rm|rmdir|mv|dd|mkfs|fdisk|kill|killall|reboot|shutdown|halt)\b",
    re.IGNORECASE,
)

# 리전별 boto3 클라이언트 캐시 — 로컬/AgentCore Runtime 모두 동일하게 동작
_boto3_clients: dict = {}


def _build_openai_model() -> OpenAIModel:
    api_key = str(os.environ.get("OPENAI_API_KEY") or "").strip()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY 환경변수가 필요합니다.")

    client_args = {"api_key": api_key}
    if OPENAI_BASE_URL:
        client_args["base_url"] = OPENAI_BASE_URL

    return OpenAIModel(
        client_args=client_args,
        model_id=OPENAI_MODEL_ID,
        params={"temperature": 0},
    )


def _client(service: str, region: str):
    key = (service, region)
    if key not in _boto3_clients:
        _boto3_clients[key] = boto3.client(service, region_name=region)
    return _boto3_clients[key]


IMDS_BASE = "http://169.254.169.254/latest/meta-data"
IMDS_TIMEOUT = 2


# ---------------------------------------------------------------------------
# 런타임 상태 — strands @tool 함수가 invocation 별 instance_id/region 에 접근할 수 있도록 사용
# ---------------------------------------------------------------------------

_runtime_state: dict = {
    "instance_id": None,
    "region": DEFAULT_REGION,
    "mode": "collect",
    "collect_result": None,
    "query_result": None,
    "tool_call_count": 0,
    "query_started_at": 0.0,
    "query_budget_exceeded": False,
    "query_budget_reason": "",
    "seen_tool_calls": set(),
}


# save_result / answer_query 의 인자는 strands 가 LLM 호출 결과를 dict 로 그대로
# 전달하므로 Pydantic 모델 강제 검증 대신 시스템 프롬프트로 형식을 안내한다.
# (중첩 Pydantic 스키마는 LLM 이 종종 인자를 비워서 호출하는 회귀가 관찰됨)


# ---------------------------------------------------------------------------
# 도구 실행
# ---------------------------------------------------------------------------

def _sanitize_output(text: str) -> str:
    """tool 출력 중 큰 HTML/XML 덩어리는 짧게 대체하고 길이 제한."""
    if not text:
        return "(출력 없음)"
    low = text.lower()
    if "<!doctype html" in low or "<html" in low or "<?xml" in low:
        marker = "(HTML/XML 응답 — 엔드포인트 미활성/미지원으로 추정)"
        m = re.search(r"<title>([^<]+)</title>", text, re.IGNORECASE)
        if m:
            marker += f" [title: {m.group(1).strip()}]"
        return marker
    if len(text) > TOOL_OUTPUT_LIMIT:
        return text[:TOOL_OUTPUT_LIMIT] + "\n...(이하 생략)"
    return text


def _execute_run_command(command: str) -> str:
    if _BLOCKED.search(command):
        return f"[BLOCKED] 허용되지 않는 명령어: {command}"
    try:
        result = subprocess.run(
            command, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=COMMAND_TIMEOUT,
        )
        out = result.stdout.decode(errors="replace").strip()
        return _sanitize_output(out)
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] {COMMAND_TIMEOUT}초 초과"
    except Exception as e:
        return f"[ERROR] {e}"


def _execute_read_file(path: str) -> str:
    try:
        text = Path(path).read_text(errors="replace")
        return _sanitize_output(text)
    except PermissionError:
        return f"[ERROR] 권한 없음: {path}"
    except FileNotFoundError:
        return f"[ERROR] 파일 없음: {path}"
    except Exception as e:
        return f"[ERROR] {e}"


def _ssm_run_command(instance_id: str, command: str, region: str, timeout: int = SSM_MAX_WAIT) -> str:
    """AWS SSM send-command 로 EC2 에 명령을 원격 실행하고 결과를 가져온다 (boto3)."""
    if _BLOCKED.search(command):
        return f"[BLOCKED] 허용되지 않는 명령어: {command}"

    ssm = _client("ssm", region)
    try:
        send = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [command]},
        )
        cmd_id = send["Command"]["CommandId"]
    except ClientError as e:
        return f"[SSM ERROR] send-command 실패: {e}"
    except Exception as e:
        return f"[ERROR] {e}"

    deadline = time.time() + timeout
    last_status = "Pending"
    while time.time() < deadline:
        time.sleep(SSM_POLL_INTERVAL)
        try:
            data = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        except ClientError as e:
            # 실행 시작 전이면 InvocationDoesNotExist → 재시도
            if e.response.get("Error", {}).get("Code") == "InvocationDoesNotExist":
                continue
            return f"[SSM ERROR] {e}"
        status = data.get("Status", "")
        last_status = status
        if status in ("Success", "Failed", "Cancelled", "TimedOut"):
            stdout = (data.get("StandardOutputContent") or "").rstrip()
            stderr = (data.get("StandardErrorContent") or "").rstrip()
            combined = "\n".join(s for s in [stdout, stderr] if s).strip()
            return _sanitize_output(combined)
    return f"[SSM TIMEOUT] {timeout}초 초과 (status={last_status})"


def _ssm_read_file(instance_id: str, path: str, region: str) -> str:
    return _ssm_run_command(instance_id, f"cat {shlex.quote(path)}", region)


def _mark_query_budget_exceeded(reason: str) -> str:
    _runtime_state["query_budget_exceeded"] = True
    _runtime_state["query_budget_reason"] = reason
    return f"[QUERY BUDGET EXCEEDED] {reason}"


def _check_query_budget(tool_name: str, tool_input: str) -> str | None:
    if _runtime_state.get("mode") != "query":
        return None

    started_at = float(_runtime_state.get("query_started_at") or 0.0)
    elapsed = time.monotonic() - started_at if started_at else 0.0
    if elapsed >= QUERY_WALL_TIME_LIMIT:
        return _mark_query_budget_exceeded(
            f"총 조사 시간 {QUERY_WALL_TIME_LIMIT}초를 초과했습니다. 현재 증거만으로 답변하거나 확인 불가로 종료하세요."
        )

    if int(_runtime_state.get("tool_call_count") or 0) >= QUERY_TOOL_CALL_LIMIT:
        return _mark_query_budget_exceeded(
            f"도구 호출 상한 {QUERY_TOOL_CALL_LIMIT}회를 초과했습니다. 현재 증거만으로 답변하거나 확인 불가로 종료하세요."
        )

    signature = f"{tool_name}:{tool_input.strip()}"
    seen_calls = _runtime_state.setdefault("seen_tool_calls", set())
    if signature in seen_calls:
        return "[QUERY SKIP] 이미 같은 도구 요청을 수행했습니다. 다른 증거로 답변을 정리하거나 확인 불가로 종료하세요."

    seen_calls.add(signature)
    _runtime_state["tool_call_count"] = int(_runtime_state.get("tool_call_count") or 0) + 1
    return None


# ---------------------------------------------------------------------------
# strands @tool — 에이전트 루프에서 LLM 이 호출하는 함수
# ---------------------------------------------------------------------------

@tool
def run_command(command: str) -> str:
    """EC2 인스턴스에서 읽기/조회 목적의 shell 명령어를 실행한다.
    파일 삭제·프로세스 종료 등 파괴적 명령은 자동 차단된다.

    Args:
        command: 실행할 shell 명령어 (bash -c 로 실행됨).
    """
    budget_message = _check_query_budget("run_command", command)
    if budget_message:
        return budget_message

    instance_id = _runtime_state.get("instance_id")
    region = _runtime_state.get("region", DEFAULT_REGION)
    if instance_id:
        timeout = QUERY_SSM_MAX_WAIT if _runtime_state.get("mode") == "query" else SSM_MAX_WAIT
        return _ssm_run_command(instance_id, command, region, timeout=timeout)
    return _execute_run_command(command)


@tool
def read_file(path: str) -> str:
    """파일 경로를 받아 텍스트 내용을 반환한다.

    Args:
        path: 읽을 파일의 절대 경로.
    """
    budget_message = _check_query_budget("read_file", path)
    if budget_message:
        return budget_message

    instance_id = _runtime_state.get("instance_id")
    region = _runtime_state.get("region", DEFAULT_REGION)
    if instance_id:
        timeout = QUERY_SSM_MAX_WAIT if _runtime_state.get("mode") == "query" else SSM_MAX_WAIT
        return _ssm_run_command(instance_id, f"cat {shlex.quote(path)}", region, timeout=timeout)
    return _execute_read_file(path)


@tool
def save_result(
    installed_software: list,
    network_context: dict,
    security_context: dict,
    data_classification: str = "unknown",
) -> str:
    """수집 모드 종료 시 반드시 한 번 호출. 자산 수집 결과를 저장한다.
    호출 후에는 추가 도구 호출 없이 짧은 종료 메시지로 응답해야 한다.

    Args:
        installed_software: payload 대상 소프트웨어 탐지 결과 — 각 항목은
            {"vendor": str, "product": str, "version": str, "source_path"?: str}.
            대상 소프트웨어가 없으면 빈 리스트 [].
        network_context: 네트워크 컨텍스트 —
            {"public_ip": str, "listening_ports": list[int]}.
        security_context: 보안 컨텍스트 —
            {"attached_iam_role": str, "running_as_root": list[str],
             "imds_v2_enforced": bool, "selinux_enforced": bool}.
        data_classification: 태그 기반 데이터 분류 (PII / Payment / Internal / unknown).
    """
    normalized_software = []
    for item in installed_software or []:
        if not isinstance(item, dict):
            continue
        normalized_software.append({
            "vendor": str(item.get("vendor") or "").strip(),
            "product": str(item.get("product") or "").strip(),
            "version": str(item.get("version") or "").strip(),
            "source_path": str(item.get("source_path") or "").strip(),
        })

    _runtime_state["collect_result"] = {
        "installed_software": normalized_software,
        "network_context": {
            "public_ip": str((network_context or {}).get("public_ip") or "").strip(),
            "listening_ports": list((network_context or {}).get("listening_ports") or []),
        },
        "security_context": security_context or {
            "attached_iam_role": "", "running_as_root": [],
            "imds_v2_enforced": False, "selinux_enforced": False,
        },
        "data_classification": data_classification,
    }
    return "COLLECTION_SAVED — 추가 도구 호출 없이 짧게 '수집 완료' 라고 응답해 주세요."


@tool
def answer_query(answer: str, evidence: list, confidence: str = "low") -> str:
    """질의 응답 모드 종료 시 반드시 한 번 호출. 답변을 저장한다.
    호출 후에는 추가 도구 호출 없이 짧은 종료 메시지로 응답해야 한다.

    Args:
        answer: 질문에 대한 짧고 명확한 답변.
        evidence: 답변 근거가 된 명령어 출력 또는 파일 경로 문자열 리스트.
        confidence: high / medium / low 중 하나.
    """
    _runtime_state["query_result"] = {
        "answer": answer,
        "evidence": evidence or [],
        "confidence": confidence,
    }
    return "ANSWER_RECORDED — 추가 도구 호출 없이 짧게 '답변 완료' 라고 응답해 주세요."


# ---------------------------------------------------------------------------
# IMDS / OS 정보 (파이썬 측에서 직접 수집)
# ---------------------------------------------------------------------------

def _imds_get(path: str) -> str:
    try:
        with urllib.request.urlopen(f"{IMDS_BASE}/{path}", timeout=IMDS_TIMEOUT) as r:
            return r.read().decode().strip()
    except (urllib.error.URLError, OSError):
        return ""


def _imds_get_v2(path: str) -> str:
    try:
        req = urllib.request.Request(
            "http://169.254.169.254/latest/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            method="PUT",
        )
        with urllib.request.urlopen(req, timeout=IMDS_TIMEOUT) as r:
            token = r.read().decode().strip()
        req2 = urllib.request.Request(
            f"{IMDS_BASE}/{path}",
            headers={"X-aws-ec2-metadata-token": token},
        )
        with urllib.request.urlopen(req2, timeout=IMDS_TIMEOUT) as r:
            return r.read().decode().strip()
    except (urllib.error.URLError, OSError):
        return ""


def get_instance_id() -> str:
    return _imds_get("instance-id") or _imds_get_v2("instance-id") or socket.gethostname()


def _parse_os_release(text: str) -> dict:
    if not text or text.startswith("[ERROR]") or text.startswith("[SSM") or text.startswith("[BLOCKED]"):
        return {"vendor": "unknown", "version": "unknown"}
    kv: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if "=" not in line or line.startswith("#"):
            continue
        k, _, v = line.partition("=")
        kv[k.strip()] = v.strip().strip('"')
    vendor = kv.get("ID", "unknown").lower()
    m = re.search(r"[\d.]+", kv.get("VERSION", ""))
    version = kv.get("VERSION_ID") or (m.group(0) if m else "unknown")
    return {"vendor": vendor, "version": version}


def get_os_info() -> dict:
    p = Path("/etc/os-release")
    if not p.exists():
        return {"vendor": "unknown", "version": "unknown"}
    return _parse_os_release(p.read_text())


def get_os_info_remote(instance_id: str, region: str) -> dict:
    return _parse_os_release(_ssm_run_command(instance_id, "cat /etc/os-release", region))


def get_hostname_remote(instance_id: str, region: str) -> str:
    out = _ssm_run_command(instance_id, "hostname", region).strip()
    if out.startswith("[") or not out or out == "(출력 없음)":
        return instance_id
    return out


# ---------------------------------------------------------------------------
# AWS EC2 Discovery (auto-discover 모드 + 자동 티어 판정)
# ---------------------------------------------------------------------------

def discover_vpc_instances(vpc_id: str, region: str) -> list:
    """VPC 내 running EC2 인스턴스 목록을 정규화해 반환."""
    ec2 = _client("ec2", region)
    try:
        data = ec2.describe_instances(Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "instance-state-name", "Values": ["running"]},
        ])
    except ClientError as e:
        raise RuntimeError(f"ec2:DescribeInstances 실패: {e}")

    instances = []
    for resv in data.get("Reservations", []):
        for inst in resv.get("Instances", []):
            tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
            iam_arn = inst.get("IamInstanceProfile", {}).get("Arn", "")
            instances.append({
                "instance_id": inst["InstanceId"],
                "subnet_id": inst.get("SubnetId", ""),
                "availability_zone": inst.get("Placement", {}).get("AvailabilityZone", ""),
                "private_ip": inst.get("PrivateIpAddress", ""),
                "public_ip": inst.get("PublicIpAddress", ""),
                "security_groups": [sg["GroupId"] for sg in inst.get("SecurityGroups", [])],
                "tags": tags,
                "iam_instance_profile": iam_arn.split("/")[-1] if iam_arn else "",
                "name": tags.get("Name", ""),
            })
    return instances


_subnet_cache: dict = {}


def describe_subnet_connectivity(subnet_id: str, region: str) -> dict:
    """서브넷 라우트 기준 연결 성격을 구조화해 반환한다."""
    if subnet_id in _subnet_cache:
        return _subnet_cache[subnet_id]

    ec2 = _client("ec2", region)

    try:
        data = ec2.describe_route_tables(Filters=[
            {"Name": "association.subnet-id", "Values": [subnet_id]},
        ])
    except ClientError as e:
        raise RuntimeError(f"ec2:DescribeRouteTables 실패: {e}")
    tables = data.get("RouteTables", [])

    if not tables:
        try:
            subnet_data = ec2.describe_subnets(SubnetIds=[subnet_id])
        except ClientError as e:
            raise RuntimeError(f"ec2:DescribeSubnets 실패: {e}")
        subnets = subnet_data.get("Subnets", [])
        if not subnets:
            result = {
                "network_exposure": "unknown",
                "subnet_route_type": "unknown",
                "internet_route_via_igw": False,
                "internet_egress_via_nat": False,
            }
            _subnet_cache[subnet_id] = result
            return result
        vpc_id = subnets[0].get("VpcId", "")
        try:
            rt_data = ec2.describe_route_tables(Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "association.main", "Values": ["true"]},
            ])
        except ClientError as e:
            raise RuntimeError(f"ec2:DescribeRouteTables(main) 실패: {e}")
        tables = rt_data.get("RouteTables", [])

    routes = tables[0].get("Routes", []) if tables else []
    has_igw = any(str(r.get("GatewayId", "")).startswith("igw-") for r in routes)
    has_nat = any(str(r.get("NatGatewayId", "")).startswith("nat-") for r in routes)

    if has_igw:
        result = {
            "network_exposure": "public",
            "subnet_route_type": "public",
            "internet_route_via_igw": True,
            "internet_egress_via_nat": False,
        }
    elif has_nat:
        result = {
            "network_exposure": "private",
            "subnet_route_type": "private_nat",
            "internet_route_via_igw": False,
            "internet_egress_via_nat": True,
        }
    else:
        result = {
            "network_exposure": "isolated",
            "subnet_route_type": "isolated",
            "internet_route_via_igw": False,
            "internet_egress_via_nat": False,
        }

    _subnet_cache[subnet_id] = result
    return result


def classify_subnet(subnet_id: str, region: str) -> str:
    """서브넷의 라우트 테이블로 public/private/isolated 판정."""
    return str(describe_subnet_connectivity(subnet_id, region).get("network_exposure", "unknown"))


def extract_tier(tags: dict, name: str) -> str:
    """태그 또는 Name 패턴에서 tier 추출."""
    for key in ("Tier", "tier", "Role", "role"):
        v = tags.get(key, "").lower()
        if not v:
            continue
        for t in ("web", "app", "was", "db", "database"):
            if t in v:
                return "app" if t == "was" else ("db" if t == "database" else t)

    n = (name or "").lower()
    for t in ("web", "app", "was", "db", "database"):
        if t in n:
            return "app" if t == "was" else ("db" if t == "database" else t)
    return "unknown"


def default_data_classification(tier: str) -> str:
    return {
        "web": "Internal",
        "app": "Confidential",
        "db":  "PII",
    }.get(tier, "unknown")


def build_asset_result_meta(result_kind: str) -> dict:
    """자산 수집 결과를 읽는 후속 에이전트를 위한 상단 설명 블록."""
    if result_kind == "single_asset":
        return {
            "result_type": "asset_info",
            "payload_purpose": "단일 자산에 대해 설치 소프트웨어, 버전, 네트워크 노출, 보안 컨텍스트를 수집한 결과입니다. 다른 에이전트가 특정 CVE와의 연관성을 판단할 때 사용합니다.",
            "field_descriptions": {
                "asset_id": "자산 식별자입니다. 보통 EC2 인스턴스 ID입니다.",
                "hostname": "자산의 호스트명입니다.",
                "metadata": "환경, 노출 수준, 데이터 분류 같은 자산 메타데이터입니다.",
                "network_context": "public IP, listening port 같은 네트워크 정보입니다.",
                "security_context": "IAM role, root 권한 실행, IMDSv2, SELinux 같은 보안 정보입니다.",
                "os_info": "운영체제 벤더/버전 정보입니다.",
                "installed_software": "탐지된 주요 소프트웨어와 버전 정보입니다.",
            },
        }

    return {
        "result_type": "infra_context",
        "payload_purpose": "VPC 내 자산들을 자동 탐색해 계층, 네트워크 노출, NAT/IGW 연결성, 운영체제, 보안 컨텍스트, 설치 소프트웨어 정보를 구조화한 결과입니다. 위험도 평가와 패치 전략 에이전트가 실제 영향 자산을 판별할 때 사용합니다.",
        "field_descriptions": {
            "vpc_id": "수집 대상 VPC ID입니다.",
            "region": "수집을 수행한 AWS 리전입니다.",
            "collected_at": "수집 시각(UTC ISO-8601)입니다.",
            "assets": "자동 탐색 모드에서 수집한 자산 목록입니다.",
            "assets[].asset_id": "EC2 인스턴스 ID입니다. 자산을 식별하는 기본 키입니다.",
            "assets[].hostname": "자산의 호스트명입니다.",
            "assets[].tier": "web, app, db 등 계층 분류입니다.",
            "assets[].availability_zone": "자산이 위치한 가용 영역입니다.",
            "assets[].subnet_id": "자산이 속한 서브넷 ID입니다.",
            "assets[].private_ip": "자산의 private IP입니다.",
            "assets[].public_ip": "자산의 public IP입니다. 없으면 빈 문자열입니다.",
            "assets[].security_groups": "자산에 연결된 security group ID 목록입니다.",
            "assets[].iam_instance_profile": "자산에 연결된 IAM instance profile 이름입니다.",
            "assets[].metadata": "자산의 환경/노출/라우팅 메타데이터입니다.",
            "assets[].metadata.environment": "수집 시점에 지정한 환경 이름입니다. 예: production.",
            "assets[].metadata.network_exposure": "서브넷 라우팅 기준 public/private/isolated 분류입니다.",
            "assets[].metadata.subnet_route_type": "public, private_nat, isolated 등 서브넷의 인터넷 연결 유형입니다.",
            "assets[].metadata.internet_route_via_igw": "인터넷 게이트웨이(IGW)를 통해 직접 인터넷 라우트가 있는지 여부입니다.",
            "assets[].metadata.internet_egress_via_nat": "NAT Gateway를 통해 외부 outbound egress가 가능한지 여부입니다.",
            "assets[].metadata.business_criticality": "업무 중요도 메타데이터입니다.",
            "assets[].metadata.data_classification": "자산의 데이터 민감도 분류입니다.",
            "assets[].network_context": "자산의 네트워크 컨텍스트입니다.",
            "assets[].network_context.public_ip": "에이전트가 OS/네트워크 관점에서 확인한 public IP입니다.",
            "assets[].network_context.listening_ports": "자산에서 수집된 listening port 목록입니다.",
            "assets[].security_context": "자산의 보안 컨텍스트입니다.",
            "assets[].security_context.attached_iam_role": "자산에 연결된 IAM role 이름입니다.",
            "assets[].security_context.running_as_root": "root 권한으로 실행 중인 주요 프로세스 목록입니다.",
            "assets[].security_context.imds_v2_enforced": "IMDSv2 강제 여부입니다.",
            "assets[].security_context.selinux_enforced": "SELinux enforce 여부입니다.",
            "assets[].os_info": "운영체제 벤더/버전 정보입니다.",
            "assets[].installed_software": "탐지된 주요 소프트웨어 목록입니다. 취약점 매칭에 직접 사용됩니다.",
            "assets[].installed_software[].vendor": "소프트웨어 벤더입니다.",
            "assets[].installed_software[].product": "소프트웨어 제품명입니다.",
            "assets[].installed_software[].version": "탐지된 정확한 버전입니다.",
            "assets[].installed_software[].source_path": "버전/설치 근거를 찾은 경로입니다.",
            "reachability": "계층 간 도달 가능성 정보입니다. source_tier, target_tier, ports를 통해 web/app/db 흐름을 설명합니다.",
        },
    }


def _extract_ports(perm: dict) -> list:
    proto = perm.get("IpProtocol", "")
    if proto == "-1":
        return ["all"]
    fp = perm.get("FromPort")
    tp = perm.get("ToPort")
    if fp is None:
        return [proto or "unknown"]
    if fp == tp:
        return [fp]
    return [f"{fp}-{tp}"]


def build_reachability(instances: list, region: str) -> list:
    """Security Group 인바운드 규칙을 분석해 tier 간 reachability 산출."""
    all_sg_ids = sorted({sg for i in instances for sg in i["security_groups"]})
    if not all_sg_ids:
        return []

    ec2 = _client("ec2", region)
    try:
        data = ec2.describe_security_groups(GroupIds=all_sg_ids)
    except ClientError as e:
        raise RuntimeError(f"ec2:DescribeSecurityGroups 실패: {e}")
    sgs = {sg["GroupId"]: sg for sg in data.get("SecurityGroups", [])}

    sg_to_tiers: dict = {}
    for inst in instances:
        tier = inst.get("tier", "unknown")
        for sgid in inst["security_groups"]:
            sg_to_tiers.setdefault(sgid, set()).add(tier)

    reach = []
    for sgid, sg in sgs.items():
        to_tiers = sg_to_tiers.get(sgid, set())
        if not to_tiers:
            continue
        for perm in sg.get("IpPermissions", []):
            ports = _extract_ports(perm)
            for ip in perm.get("IpRanges", []):
                if ip.get("CidrIp") == "0.0.0.0/0":
                    for to_t in to_tiers:
                        reach.append({"from": "internet", "to": to_t, "ports": ports})
            for pair in perm.get("UserIdGroupPairs", []):
                src_sgid = pair.get("GroupId", "")
                for src_t in sg_to_tiers.get(src_sgid, set()):
                    for to_t in to_tiers:
                        if not (src_t == to_t and src_sgid == sgid):
                            reach.append({"from": src_t, "to": to_t, "ports": ports})

    # 중복 제거
    seen, deduped = set(), []
    for r in reach:
        key = (r["from"], r["to"], tuple(str(p) for p in r["ports"]))
        if key not in seen:
            seen.add(key)
            deduped.append(r)
    return deduped


# ---------------------------------------------------------------------------
# [수집 모드] 프롬프트 & 루프
# ---------------------------------------------------------------------------

def build_collect_system_prompt(payload: dict) -> str:
    targets = json.dumps(payload.get("records", []), ensure_ascii=False, indent=2)
    return f"""당신은 Linux EC2 의 **보안 자산 조사 AI 에이전트**입니다.
다음 에이전트(위험도 평가·운영 영향 평가)가 이 데이터로 CVE의 실제 위험도를 판단합니다.

## 당신의 임무 (2가지)

1. 아래 **payload** 에 담긴 CVE 대상 소프트웨어가 이 인스턴스에 설치되어 있는지,
   있다면 **정확한 버전** 을 찾아냅니다.
2. 그 취약점이 실제로 얼마나 위험한지 판단하는 데 필요한
   **자산·네트워크·권한·비즈니스 컨텍스트** 를 수집합니다.

## 입력: payload

{targets}

payload 를 스스로 읽고, product_name(예: `nginx`, `apache-log4j`) 와 affected_version_range 를 참고해
이 인스턴스에 해당 소프트웨어가 있는지 **직접 판단** 하세요.

## 행동 원칙 (자유도)

- **어떤 shell 명령을 쓸지는 스스로 결정** 하세요. 지정된 레시피 없음.
- `run_command` / `read_file` 을 자유롭게 조합하세요.
- 파괴적 명령(rm, kill, mv, dd, mkfs, reboot 등) 은 시스템이 자동 차단합니다.
- 한 턴에 여러 tool 을 병렬로 호출해도 됩니다 (속도 향상).

## 반드시 지킬 것 (실패 패턴)

1. **같은 명령 반복 금지** — 이전 출력을 기억하세요.
2. **HTML/404 응답은 "그 기능 비활성"이라는 뜻** — 재시도하지 말고 해당 필드를 `""`/`"unknown"`/`false` 로 두고 **다음으로 넘어가세요**.
3. **installed_software 를 하나라도 확정했으면**, 나머지가 막히더라도 **지체 없이 save_result 호출**.
4. **save_result 를 호출하지 않고 텍스트로만 종료하는 것은 절대 금지** — 그 어떤 상황에서도 종료 전에는 반드시 `save_result` 도구를 정확히 한 번 호출해야 합니다. 부족한 필드는 빈 문자열/빈 배열/false 로 두면 됩니다.
5. save_result 호출 후에는 추가 도구 호출 없이 짧은 종료 메시지를 텍스트로 응답해 종료하세요.

## 결과물 스키마 (save_result 인자 — 형식은 엄수)

```
{{
  "installed_software": [
    {{
      "vendor":      "<vendor, 예: f5, apache>",
      "product":     "<product, 예: nginx, log4j>",
      "version":     "<실제 설치 버전, 예: 1.20.0, 2.14.1>",
      "source_path": "<탐지 근거 경로 (선택)>"
    }}
    // 대상 소프트웨어가 없으면 빈 배열 []
  ],
  "network_context": {{
    "public_ip":          "<IMDS /public-ipv4, 없으면 ''>",
    "listening_ports":    [<LISTEN TCP 포트 번호 정수 배열>]
  }},
  "security_context": {{
    "attached_iam_role": "<EC2 instance profile 이름, 없으면 ''>",
    "running_as_root":   [<payload 대상 서비스 중 user=root 로 실행 중인 comm 이름들>],
    "imds_v2_enforced":  <토큰 없이 IMDS 호출 시 401 이면 true>,
    "selinux_enforced":  <getenforce == 'Enforcing' 이면 true>
  }},
  "data_classification": "<태그/호스트명 힌트 기반: PII / Payment / Internal / unknown>"
}}
```

## 조사 힌트 (막혔을 때 참고)

- **nginx 버전**: `nginx -v` 안 되면 `ps aux | grep '[n]ginx'` → 실제 바이너리 경로(예: `/usr/local/nginx/sbin/nginx`) → `<경로> -v`
- **log4j 버전**: `ps aux | grep '[j]ava'` → Java classpath 의 `log4j-core-X.Y.Z.jar` 파일명에서 버전 추출.
  Fat JAR 이면 `unzip -l <jar>` / `unzip -p <jar> META-INF/maven/.../pom.properties`
- **네트워크 포트**: `ss -tuln` / `netstat -tuln` 의 LISTEN 라인
- **IMDS v2**: 토큰 PUT → GET. iam/security-credentials/ 로 role 이름 확인
- **태그**: IMDS `/latest/meta-data/tags/instance/` 응답이 HTML 이면 미활성 → 즉시 "unknown"

## 절대 금지

- 같은 IMDS URL 을 2번 이상 호출 (한 번 HTML 응답 = 비활성 = 재시도 X)
- `ps -eo user,comm` 전체 덤프 반복 요청
- 막혔다고 텍스트로 포기 선언 — 반드시 save_result 로 종료
"""


def run_collect_agent(payload: dict,
                      instance_id: Optional[str] = None,
                      region: str = DEFAULT_REGION) -> dict:
    """수집 모드 (strands Agent). save_result 가 채운 dict 를 반환."""
    _runtime_state["instance_id"] = instance_id
    _runtime_state["region"] = region
    _runtime_state["mode"] = "collect"
    _runtime_state["collect_result"] = None
    _runtime_state["tool_call_count"] = 0
    _runtime_state["query_started_at"] = 0.0
    _runtime_state["query_budget_exceeded"] = False
    _runtime_state["query_budget_reason"] = ""
    _runtime_state["seen_tool_calls"] = set()

    system_prompt = build_collect_system_prompt(payload)
    exec_mode = f"SSM→{instance_id}" if instance_id else "LOCAL"
    print(f"[AGENT] 수집 모드 시작 — 모델: {OPENAI_MODEL_ID}, 실행: {exec_mode}")

    agent = Agent(
        model=_build_openai_model(),
        system_prompt=system_prompt,
        tools=[run_command, read_file, save_result],
    )
    agent("payload 분석을 시작합니다. 조사를 마치면 save_result 를 한 번 호출하고 종료해 주세요.")

    if _runtime_state["collect_result"] is None:
        # LLM 이 save_result 호출 없이 종료한 경우 — 동일 대화에 이어 강제 호출 유도
        print("[AGENT] save_result 누락 — 강제 호출 복구 시도")
        agent(
            "지금까지 조사한 내용으로 즉시 save_result 를 한 번 호출해 주세요. "
            "확인하지 못한 필드는 빈 문자열/빈 배열/false 로 두세요. "
            "save_result 호출 후 짧은 종료 메시지로 종료해 주세요."
        )

    if _runtime_state["collect_result"] is not None:
        return _runtime_state["collect_result"]
    print("[AGENT] 복구 실패 — 빈 결과 반환")
    return {"installed_software": []}


# ---------------------------------------------------------------------------
# [질의 응답 모드] swarm 대비 — 다른 Agent의 질문에 자산 정보로 답변
# ---------------------------------------------------------------------------

def build_query_system_prompt(asset_info: dict) -> str:
    asset_context = json.dumps(asset_info, ensure_ascii=False, indent=2)
    return f"""당신은 자산 매칭 에이전트의 질의 응답 모드입니다.
다른 에이전트(위험도 평가·운영 영향 평가)가 이 자산에 대해 구체적인 질문을 보내면
아래 수집된 자산 정보를 우선 참고하고, 부족하면 run_command / read_file 로
EC2 에서 직접 추가 조사한 뒤 answer_query 를 호출해 답변하세요.

[이미 수집된 asset_info.json]
{asset_context}

[응답 규칙]
1. 이미 asset_info 에 답이 있으면 추가 명령 없이 바로 answer_query 를 호출.
2. 없으면 최소한의 명령만 실행해 확인한 뒤 answer_query.
3. answer 는 간결한 한 줄, evidence 에는 근거 명령/파일, confidence 는 high/medium/low 중 하나.
4. **answer_query 를 호출하지 않고 텍스트로만 종료하는 것은 절대 금지** — 종료 전 반드시 answer_query 를 정확히 한 번 호출해야 합니다. 확신이 부족하면 confidence='low' 로 두면 됩니다.
5. answer_query 호출 후에는 추가 도구 호출 없이 짧은 종료 메시지를 텍스트로 응답해 종료하세요.
6. 질의 응답 모드에는 조사 예산이 있습니다. 같은 명령/파일 재확인 금지, 도구 호출 상한과 시간 상한을 넘기면 더 파고들지 말고 현재까지의 증거로 답변하거나 확인 불가로 종료하세요.
7. `[QUERY BUDGET EXCEEDED]` 또는 `[QUERY SKIP]` 응답을 받으면 추가 조사 대신 즉시 answer_query 를 호출하세요.
8. 추정으로 "yes" 또는 "활성"이라고 단정하지 마세요. 직접 확인한 파일, 명령 출력, 프로세스, 설정 근거가 없으면 unknown/확인 불가로 답하십시오.
9. 추가 조사가 필요하면 asset_info.installed_software 를 먼저 보십시오. 이미 탐지된 product, version, source_path 가 있으면 일반적인 기본 경로 추정보다 그 경로와 인접한 바이너리/설정 파일을 우선 확인하십시오.

[실습 환경 조사 힌트]
- 질문이 `CVE-2021-23017`, `nginx`, `resolver`, `DNS`, `upstream`, `proxy_pass` 관련이면 우선 다음 근거를 확인하세요.
  - 이미 탐지된 `source_path` 또는 실제 실행 중인 nginx 바이너리 경로를 기준으로 설정과 실행 정보를 확인하세요.
  - 설정 안의 `resolver` 지시어, `proxy_pass`, upstream 구성이 실제 사용되는지 확인하세요.
  - DNS 이름 기반 upstream/proxy 경로가 실제 사용되는지 확인하세요.
- 질문이 `CVE-2021-44228`, `log4j`, `JNDI`, `message lookup`, `formatMsgNoLookups`, `User-Agent` 관련이면 우선 다음 근거를 확인하세요.
  - 이미 탐지된 `source_path`, Java 실행 인자, classpath, 관련 설정 파일과 애플리케이션 코드를 우선 확인하세요.
  - message lookup, lookup(`${...}`) 해석, `${{jndi:...}}` 처리 가능 여부와 관련된 설정/코드 근거를 확인하세요.
  - 외부 입력값이 실제 로그 호출까지 도달하는 코드/설정 경로를 확인하세요.
  - 직접 읽은 설정 파일이나 코드에서 JNDI/lookup 활성화 근거가 없으면 추정하지 말고 unknown 으로 두세요.
"""


def run_query_agent(asset_info: dict, query: str,
                    instance_id: Optional[str] = None,
                    region: str = DEFAULT_REGION) -> dict:
    """질의 응답 모드 (strands Agent). answer_query 가 채운 dict 를 반환."""
    _runtime_state["instance_id"] = instance_id
    _runtime_state["region"] = region
    _runtime_state["mode"] = "query"
    _runtime_state["query_result"] = None
    _runtime_state["tool_call_count"] = 0
    _runtime_state["query_started_at"] = time.monotonic()
    _runtime_state["query_budget_exceeded"] = False
    _runtime_state["query_budget_reason"] = ""
    _runtime_state["seen_tool_calls"] = set()

    system_prompt = build_query_system_prompt(asset_info)
    exec_mode = f"SSM→{instance_id}" if instance_id else "LOCAL"
    print(f"[AGENT] 질의 응답 모드 ({exec_mode}) — 질문: {query}")

    agent = Agent(
        model=_build_openai_model(),
        system_prompt=system_prompt,
        tools=[run_command, read_file, answer_query],
    )
    agent(f"[질문] {query}")

    if _runtime_state["query_result"] is None:
        if _runtime_state.get("query_budget_exceeded"):
            reason = str(_runtime_state.get("query_budget_reason") or "조사 예산 초과로 확인 불가")
            return {"answer": "확인할 수 없습니다.", "evidence": [reason], "confidence": "low"}
        # LLM 이 answer_query 호출 없이 종료한 경우 강제 호출 유도
        print("[AGENT] answer_query 누락 — 강제 호출 복구 시도")
        agent(
            "지금까지 조사한 내용으로 즉시 answer_query 를 한 번 호출해 주세요. "
            "확신이 부족하면 confidence='low' 로 두고 답변하세요. "
            "answer_query 호출 후 짧은 종료 메시지로 종료해 주세요."
        )

    if _runtime_state["query_result"] is not None:
        return _runtime_state["query_result"]
    if _runtime_state.get("query_budget_exceeded"):
        reason = str(_runtime_state.get("query_budget_reason") or "조사 예산 초과로 확인 불가")
        return {"answer": "확인할 수 없습니다.", "evidence": [reason], "confidence": "low"}
    return {"answer": "(응답 생성 실패)", "evidence": [], "confidence": "low"}


# ---------------------------------------------------------------------------
# 공용 헬퍼: 자산 수집 진입점 (CLI / AgentCore Runtime 공용)
# Bedrock 인증은 IAM Role 기반 — 별도 키 헬퍼 불필요.
# ---------------------------------------------------------------------------

def collect_single_asset(
    payload: dict,
    instance_id: str | None = None,
    region: str = DEFAULT_REGION,
    environment: str = "production",
    network_exposure: str = "public",
    business_criticality: str = "high",
) -> dict:
    """단일 인스턴스 자산 수집.

    instance_id 가 있으면 SSM 으로 원격 실행, 없으면 로컬 머신에서 실행.
    """
    if instance_id:
        actual_id = instance_id
        hostname = get_hostname_remote(instance_id, region)
        os_info = get_os_info_remote(instance_id, region)
    else:
        actual_id = get_instance_id()
        hostname = socket.gethostname()
        os_info = get_os_info()

    collected = run_collect_agent(
        payload, instance_id=instance_id, region=region,
    )

    return {
        "_meta": build_asset_result_meta("single_asset"),
        "asset_id": actual_id,
        "hostname": hostname,
        "metadata": {
            "environment": environment,
            "network_exposure": network_exposure,
            "business_criticality": business_criticality,
            "data_classification": collected.get("data_classification", "unknown"),
        },
        "network_context": collected.get("network_context", {
            "public_ip": "", "listening_ports": [],
        }),
        "security_context": collected.get("security_context", {
            "attached_iam_role": "", "running_as_root": [],
            "imds_v2_enforced": False, "selinux_enforced": False,
        }),
        "os_info": os_info,
        "installed_software": collected.get("installed_software", []),
    }


def run_auto_discover(
    payload: dict,
    vpc_id: str,
    region: str = DEFAULT_REGION,
    environment: str = "production",
    business_criticality: str = "high",
) -> dict:
    """VPC 내 running EC2 전체 자동 탐색 + 자산 수집 + reachability 산출."""
    print(f"[DISCOVERY] VPC {vpc_id} 탐색 중 (region={region})...")
    instances = discover_vpc_instances(vpc_id, region)

    if not instances:
        raise RuntimeError(f"VPC {vpc_id} 에 running 상태의 EC2 가 없습니다.")

    print(f"[DISCOVERY] {len(instances)}개 인스턴스 발견")
    for inst in instances:
        inst["tier"] = extract_tier(inst["tags"], inst["name"])
        connectivity = describe_subnet_connectivity(inst["subnet_id"], region)
        inst["network_exposure"] = str(connectivity.get("network_exposure", "unknown"))
        inst["subnet_route_type"] = str(connectivity.get("subnet_route_type", "unknown"))
        inst["internet_route_via_igw"] = bool(connectivity.get("internet_route_via_igw", False))
        inst["internet_egress_via_nat"] = bool(connectivity.get("internet_egress_via_nat", False))
        print(f"  - {inst['instance_id']} "
              f"name={inst['name'] or '-':<20} "
              f"tier={inst['tier']:<7} "
              f"exposure={inst['network_exposure']:<8} "
              f"az={inst['availability_zone']}")

    try:
        reachability = build_reachability(instances, region)
    except RuntimeError as e:
        print(f"[WARN] reachability 수집 실패: {e}")
        reachability = []
    print(f"[DISCOVERY] reachability 규칙 {len(reachability)}건")

    assets = []
    for idx, inst in enumerate(instances, 1):
        iid = inst["instance_id"]
        print(f"\n===== [{idx}/{len(instances)}] {iid} ({inst['tier']}) 자산 수집 =====")
        collected = run_collect_agent(payload, instance_id=iid, region=region)
        os_info = get_os_info_remote(iid, region)
        hostname = get_hostname_remote(iid, region)

        data_class = (
            inst["tags"].get("DataClassification")
            or collected.get("data_classification")
            or default_data_classification(inst["tier"])
        )

        assets.append({
            "asset_id": iid,
            "hostname": hostname,
            "tier": inst["tier"],
            "availability_zone": inst["availability_zone"],
            "subnet_id": inst["subnet_id"],
            "private_ip": inst["private_ip"],
            "public_ip": inst["public_ip"],
            "security_groups": inst["security_groups"],
            "iam_instance_profile": inst["iam_instance_profile"],
            "metadata": {
                "environment": environment,
                "network_exposure": inst["network_exposure"],
                "subnet_route_type": inst["subnet_route_type"],
                "internet_route_via_igw": inst["internet_route_via_igw"],
                "internet_egress_via_nat": inst["internet_egress_via_nat"],
                "business_criticality": business_criticality,
                "data_classification": data_class,
            },
            "network_context": collected.get("network_context", {}),
            "security_context": collected.get("security_context", {}),
            "os_info": os_info,
            "installed_software": collected.get("installed_software", []),
        })

    return {
        "_meta": build_asset_result_meta("infra_context"),
        "vpc_id": vpc_id,
        "region": region,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "assets": assets,
        "reachability": reachability,
    }


# ---------------------------------------------------------------------------
# CLI & 메인
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bedrock(Claude) AI Agent 기반 자산 매칭 에이전트 (수집·질의 이중 모드)."
    )
    parser.add_argument("--payload", default=None, help="[수집 모드] payload.json 경로")
    parser.add_argument("--query",   default=None, help="[질의 응답 모드] 다른 Agent가 보낸 질문 텍스트")
    parser.add_argument("--asset-info", default="asset_info.json", help="[질의 응답 모드] 참조할 asset_info.json 경로")
    parser.add_argument("--env", dest="environment", default="production",
                        choices=["production", "staging", "development"])
    parser.add_argument("--exposure", dest="network_exposure", default="public",
                        choices=["public", "private", "internal"])
    parser.add_argument("--criticality", dest="business_criticality", default="high",
                        choices=["critical", "high", "medium", "low"])
    parser.add_argument("--output", default="asset_info.json", help="[수집 모드] 출력 파일 경로")
    parser.add_argument("--instance-id", default=None,
                        help="원격 EC2 인스턴스 ID (예: i-0123abcd). 지정 시 AWS SSM 으로 원격 실행.")
    parser.add_argument("--region", default=DEFAULT_REGION,
                        help=f"AWS 리전 (기본: {DEFAULT_REGION})")
    parser.add_argument("--vpc-id", default=None,
                        help="[auto-discover] 탐색 대상 VPC ID (예: vpc-0abcd1234)")
    parser.add_argument("--auto-discover", action="store_true",
                        help="VPC 내 running EC2 전체 자동 탐색 + 티어/노출 자동 판정")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # ----- 질의 응답 모드 -----
    if args.query:
        asset_path = Path(args.asset_info)
        if not asset_path.exists():
            print(f"[ERROR] asset_info 파일 없음: {asset_path}")
            raise SystemExit(1)
        asset_info = json.loads(asset_path.read_text())
        result = run_query_agent(asset_info, args.query,
                                 instance_id=args.instance_id, region=args.region)
        print("\n[RESULT]")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    # ----- 수집 모드: 공통 payload 로드 -----
    if not args.payload:
        print("[ERROR] 수집 모드에서는 --payload 가 필요합니다. (--query 로 질의 응답 모드 사용 가능)")
        raise SystemExit(1)

    payload_path = Path(args.payload)
    if not payload_path.exists():
        print(f"[ERROR] payload 파일 없음: {payload_path}")
        raise SystemExit(1)

    payload = json.loads(payload_path.read_text())
    print(f"[INFO] payload 로드: {len(payload.get('records', []))}개 CVE 레코드")

    # ----- [auto-discover 모드] VPC 내 모든 EC2 자동 탐색 + 티어 판정 -----
    if args.auto_discover:
        if not args.vpc_id:
            print("[ERROR] --auto-discover 사용 시 --vpc-id 가 필요합니다.")
            raise SystemExit(1)

        try:
            infra = run_auto_discover(
                payload, args.vpc_id,
                region=args.region,
                environment=args.environment,
                business_criticality=args.business_criticality,
            )
        except RuntimeError as e:
            print(f"[ERROR] {e}")
            raise SystemExit(1)

        output_path = Path(args.output)
        output_path.write_text(json.dumps(infra, ensure_ascii=False, indent=2))
        print(f"\n[OK] 저장 완료: {output_path.resolve()}")
        print(f"[SUMMARY] assets={len(infra['assets'])}, "
              f"reachability={len(infra['reachability'])}")
        return

    # ----- 단일 인스턴스 수집 모드 -----
    exec_mode = f"SSM→{args.instance_id}" if args.instance_id else "LOCAL"
    print(f"[INFO] 단일 인스턴스 수집 — {exec_mode} / 리전: {args.region}")

    asset_info = collect_single_asset(
        payload,
        instance_id=args.instance_id,
        region=args.region,
        environment=args.environment,
        network_exposure=args.network_exposure,
        business_criticality=args.business_criticality,
    )

    output_path = Path(args.output)
    output_path.write_text(json.dumps(asset_info, ensure_ascii=False, indent=2))
    print(f"\n[OK] 저장 완료: {output_path.resolve()}")
    print(json.dumps(asset_info, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
