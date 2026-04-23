import json
import re
from pathlib import Path

from tools.tooling import tool

_BASE_DIR = Path(__file__).parent.parent


@tool
def load_collected_records(input_path: str = "data/focused_selected_raw_cves.json") -> dict:
    path = _BASE_DIR / input_path
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _clean_cpe_part(value: str) -> str:
    if not value or value in {"*", "-"}:
        return ""

    return value.replace("\\:", ":").replace("_", "-").lower()


def _parse_cpe(criteria: str) -> dict:
    parts = criteria.split(":")
    if len(parts) < 6:
        return {}

    return {
        "part": _clean_cpe_part(parts[2]),
        "vendor": _clean_cpe_part(parts[3]),
        "product": _clean_cpe_part(parts[4]),
        "version": _clean_cpe_part(parts[5]),
    }


def _walk_cpe_matches(value) -> list[dict]:
    matches = []

    if isinstance(value, dict):
        for key in ("cpeMatch", "cpe_match"):
            cpe_matches = value.get(key)
            if isinstance(cpe_matches, list):
                matches.extend(item for item in cpe_matches if isinstance(item, dict))

        for child in value.values():
            matches.extend(_walk_cpe_matches(child))

    elif isinstance(value, list):
        for item in value:
            matches.extend(_walk_cpe_matches(item))

    return matches


def _version_range_from_match(match: dict) -> str:
    parts = []

    if match.get("versionStartIncluding"):
        parts.append(f">={match['versionStartIncluding']}")
    if match.get("versionStartExcluding"):
        parts.append(f">{match['versionStartExcluding']}")
    if match.get("versionEndIncluding"):
        parts.append(f"<={match['versionEndIncluding']}")
    if match.get("versionEndExcluding"):
        parts.append(f"<{match['versionEndExcluding']}")

    if parts:
        return " ".join(parts)

    criteria = match.get("criteria") or ""
    cpe = _parse_cpe(criteria)
    return cpe.get("version") or "unknown"


def _cpe_products(record: dict) -> list[str]:
    products = []
    for match in _walk_cpe_matches(record.get("nvd_cpe_configurations") or []):
        cpe = _parse_cpe(match.get("criteria") or "")
        product = cpe.get("product")
        if product and product not in products:
            products.append(product)
    return products


def _primary_product(record: dict) -> str:
    cpe_products = _cpe_products(record)
    if cpe_products:
        product = cpe_products[0]
        if product == "log4j":
            return "apache-log4j"
        return product

    text = f"{record.get('title', '')} {record.get('description', '')}".lower()
    for keyword in ("apache-log4j", "log4j", "nginx"):
        if keyword in text:
            return keyword

    return "unknown"


def _product_components(record: dict) -> list[str]:
    text = f"{record.get('title', '')} {record.get('description', '')}".lower()
    components = []
    primary_product = _primary_product(record)

    if primary_product != "unknown":
        components.append(primary_product)

    keyword_map = {
        "resolver": "dns-resolver",
        "jndi": "jndi",
        "lookup": "message-lookup",
        "ldap": "ldap-endpoints",
        "log-messages": "log-messages",
        "parameters": "log-parameters",
    }
    for keyword, component in keyword_map.items():
        if keyword in text and component not in components:
            components.append(component)

    for product in _cpe_products(record):
        normalized = "apache-log4j" if product == "log4j" else product
        if normalized not in components:
            components.append(normalized)

    return components


def _affected_version_ranges(record: dict) -> list[str]:
    ranges = []
    for match in _walk_cpe_matches(record.get("nvd_cpe_configurations") or []):
        if match.get("vulnerable") is False:
            continue

        version_range = _version_range_from_match(match)
        if version_range not in ranges:
            ranges.append(version_range)

    return ranges or ["unknown"]


def _fixed_version(record: dict) -> str:
    candidates = []
    for match in _walk_cpe_matches(record.get("nvd_cpe_configurations") or []):
        if match.get("versionEndExcluding"):
            candidates.append(match["versionEndExcluding"])
        if match.get("versionEndIncluding"):
            candidates.append(match["versionEndIncluding"])

    if candidates:
        def _version_key(value: str):
            parts = re.findall(r"[A-Za-z]+|\d+", value)
            key = []
            for part in parts:
                if part.isdigit():
                    key.append((0, int(part)))
                else:
                    key.append((1, part.lower()))
            return key

        return max(candidates, key=_version_key)

    description = record.get("description", "")
    match = re.search(r"\b(?:from version|before versions?|before version|before)\s+([A-Za-z0-9][A-Za-z0-9._+-]*)", description)
    if match:
        return match.group(1)

    return "unknown"


def _security_domain(record: dict) -> str:
    text = f"{record.get('title', '')} {record.get('description', '')}".lower()
    weakness_names = " ".join(item.get("name", "") for item in record.get("cwe_details", []))
    consequence_text = json.dumps(record.get("cwe_details", []), ensure_ascii=False).lower()

    if any(keyword in text for keyword in ("execute arbitrary code", "remote code", "code execution")):
        return "remote-code-execution"
    if any(keyword in weakness_names.lower() for keyword in ("deserialization",)):
        return "deserialization"
    if any(keyword in text for keyword in ("memory overwrite", "buffer overflow", "off-by-one", "memory disclosure")):
        return "memory-corruption"
    if "crash" in text or "denial of service" in text:
        return "denial-of-service"
    if "bypass" in text or "authentication" in text:
        return "authentication"
    if "authorization" in text:
        return "authorization"
    if "path" in text and "travers" in text:
        return "path-traversal"
    if "http header" in text:
        return "http-header"
    if "modify memory" in consequence_text:
        return "memory-corruption"

    return "unknown"


def _severity_bucket(score) -> str:
    if not isinstance(score, (int, float)):
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def _risk_signals(record: dict) -> dict:
    details = (record.get("cvss") or {}).get("vector_details") or {}
    return {
        "network_exploitable": details.get("attack_vector") == "network",
        "no_privileges_required": details.get("privileges_required") == "none",
        "no_user_interaction": details.get("user_interaction") == "none",
        "attack_complexity": details.get("attack_complexity", "unknown"),
        "scope": details.get("scope", "unknown"),
    }


def _operational_impacts(record: dict) -> list[str]:
    impacts = []
    for cwe in record.get("cwe_details", []):
        for consequence in cwe.get("common_consequences", []):
            for impact in consequence.get("impact", []):
                if impact not in impacts:
                    impacts.append(impact)
    return impacts


def _mitigation_summaries(record: dict) -> list[str]:
    summaries = []
    fixed_version = _fixed_version(record)

    if fixed_version != "unknown":
        summaries.append(f"Upgrade to {fixed_version} or later.")

    for cwe in record.get("cwe_details", []):
        for mitigation in cwe.get("potential_mitigations", []):
            description = mitigation.get("description", "")
            if description and description not in summaries:
                summaries.append(description)
    return summaries


@tool
def build_asset_matching_payloads(dataset: dict) -> dict:
    records = []

    for record in dataset.get("records", []):
        records.append({
            "cve_id": record.get("cve_id"),
            "product_name": _primary_product(record),
            "affected_version_range": _affected_version_ranges(record),
            "fixed_version": _fixed_version(record),
            "product_status": "affected",
            "cpe_criteria": [
                match.get("criteria")
                for match in _walk_cpe_matches(record.get("nvd_cpe_configurations") or [])
                if match.get("criteria")
            ],
        })

    return {
        "agent": "asset_matching",
        "source_dataset": "focused_selected_raw_cves.json",
        "record_count": len(records),
        "records": records,
    }


@tool
def build_risk_assessment_payloads(dataset: dict) -> dict:
    records = []

    for record in dataset.get("records", []):
        cvss = record.get("cvss") or {}
        records.append({
            "cve_id": record.get("cve_id"),
            "title": record.get("title"),
            "description": record.get("description"),
            "cvss": cvss,
            "severity": _severity_bucket(cvss.get("score")),
            "security_domain": _security_domain(record),
            "weaknesses": record.get("weaknesses", []),
            "cwe_names": [item.get("name", "unknown") for item in record.get("cwe_details", [])],
            "risk_signals": _risk_signals(record),
            "common_consequences": [
                consequence
                for cwe in record.get("cwe_details", [])
                for consequence in cwe.get("common_consequences", [])
            ],
        })

    return {
        "agent": "risk_assessment",
        "source_dataset": "focused_selected_raw_cves.json",
        "record_count": len(records),
        "records": records,
    }


@tool
def build_operational_impact_payloads(dataset: dict) -> dict:
    records = []

    for record in dataset.get("records", []):
        records.append({
            "cve_id": record.get("cve_id"),
            "title": record.get("title"),
            "product_name": _primary_product(record),
            "affected_components": _product_components(record),
            "affected_version_range": _affected_version_ranges(record),
            "fixed_version": _fixed_version(record),
            "patch_type": (
                "service_upgrade" if _primary_product(record) == "nginx"
                else "library_upgrade" if _primary_product(record) == "apache-log4j"
                else "unknown"
            ),
            "security_domain": _security_domain(record),
            "operational_impacts": _operational_impacts(record),
            "mitigation_summaries": _mitigation_summaries(record),
            "notes": record.get("description"),
        })

    return {
        "agent": "operational_impact",
        "source_dataset": "focused_selected_raw_cves.json",
        "record_count": len(records),
        "records": records,
    }
