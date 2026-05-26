"""Sigma → Splunk SPL / Elastic KQL / Microsoft Sentinel KQL conversion.

Uses PyYAML to parse Sigma YAML, then emits equivalent SIEM queries via
field-mapping tables and condition parsing. Not a full sigma-cli replacement —
covers the common modifiers (contains, endswith, startswith, re) and basic
AND/OR condition composition sufficient for the curated rule set.
"""

from __future__ import annotations

from typing import Any

import yaml

# ── Field maps ────────────────────────────────────────────────────────────────
# Maps (sigma_field, modifier) → platform-specific field expression builder.

_SPLUNK_FIELDS: dict[str, str] = {
    "Image": "Image",
    "CommandLine": "CommandLine",
    "ParentImage": "ParentImage",
    "OriginalFileName": "OriginalFileName",
    "User": "User",
    "DestinationIp": "dest_ip",
    "DestinationPort": "dest_port",
    "SourceIp": "src_ip",
    "SourcePort": "src_port",
    "cs-uri-stem": "cs_uri_stem",
    "cs-method": "cs_method",
    "c-useragent": "useragent",
    "EventID": "EventCode",
    "Hashes": "hash",
    "TargetFilename": "TargetFilename",
    "QueryName": "query",
}

_ELASTIC_FIELDS: dict[str, str] = {
    "Image": "process.executable",
    "CommandLine": "process.command_line",
    "ParentImage": "process.parent.executable",
    "OriginalFileName": "process.pe.original_file_name",
    "User": "user.name",
    "DestinationIp": "destination.ip",
    "DestinationPort": "destination.port",
    "SourceIp": "source.ip",
    "SourcePort": "source.port",
    "cs-uri-stem": "url.path",
    "cs-method": "http.request.method",
    "c-useragent": "user_agent.original",
    "EventID": "winlog.event_id",
    "Hashes": "file.hash.sha256",
    "TargetFilename": "file.path",
    "QueryName": "dns.question.name",
}

_SENTINEL_FIELDS: dict[str, str] = {
    "Image": "FileName",
    "CommandLine": "ProcessCommandLine",
    "ParentImage": "InitiatingProcessFileName",
    "OriginalFileName": "FileName",
    "User": "AccountName",
    "DestinationIp": "RemoteIP",
    "DestinationPort": "RemotePort",
    "SourceIp": "LocalIP",
    "SourcePort": "LocalPort",
    "cs-uri-stem": "csUriStem",
    "cs-method": "csMethod",
    "c-useragent": "csUserAgent",
    "EventID": "EventID",
    "Hashes": "SHA256",
    "TargetFilename": "FolderPath",
    "QueryName": "Name",
}

_SENTINEL_TABLE: dict[tuple[str, str], str] = {
    ("process_creation", "windows"): "DeviceProcessEvents",
    ("network_connection", "windows"): "DeviceNetworkEvents",
    ("network_connection", ""): "DeviceNetworkEvents",
    ("file_event", "windows"): "DeviceFileEvents",
    ("file_event", ""): "DeviceFileEvents",
    ("web", ""): "W3CIISLog",
    ("web", "webserver"): "W3CIISLog",
    ("dns_query", "windows"): "DeviceEvents",
    ("dns_query", ""): "DeviceEvents",
}

_SPLUNK_BASE: dict[tuple[str, str], str] = {
    ("process_creation", "windows"): "index=windows (EventCode=4688 OR source=WinEventLog:Security)",
    ("network_connection", "windows"): "index=windows (EventCode=3 OR source=WinEventLog:Security)",
    ("network_connection", ""): "index=network",
    ("file_event", "windows"): "index=windows EventCode=11",
    ("file_event", ""): "index=*",
    ("web", ""): "index=web",
    ("web", "webserver"): "index=web",
    ("dns_query", "windows"): "index=windows EventCode=22",
    ("dns_query", ""): "index=network sourcetype=stream:dns",
}


def _norm_value(v: str, modifier: str, platform: str) -> str:
    """Wrap a single condition value in platform-appropriate wildcards/syntax."""
    v = v.replace("'", "\\'") if platform == "splunk" else v
    if modifier == "contains":
        return f"*{v}*" if platform in ("splunk",) else f"*{v}*"
    if modifier == "endswith":
        return f"*{v}"
    if modifier == "startswith":
        return f"{v}*"
    return v  # exact / re


def _field_map(field: str, platform: str) -> str:
    mapping = {"splunk": _SPLUNK_FIELDS, "elastic": _ELASTIC_FIELDS, "sentinel": _SENTINEL_FIELDS}
    return mapping[platform].get(field, field)


def _selection_to_clause(sel: dict[str, Any], platform: str) -> str:
    """Convert a single Sigma selection dict to a query clause."""
    parts: list[str] = []

    for key, value in sel.items():
        if "|" in key:
            field_raw, modifier = key.split("|", 1)
        else:
            field_raw, modifier = key, "exact"

        field = _field_map(field_raw, platform)
        values = value if isinstance(value, list) else [value]

        if platform == "splunk":
            terms = [f'{field}="{_norm_value(str(v), modifier, platform)}"' for v in values]
            parts.append(f"({' OR '.join(terms)})")

        elif platform == "elastic":
            if modifier == "re":
                terms = [f'{field}: /{v}/' for v in values]
            else:
                terms = [f'{field}: "{_norm_value(str(v), modifier, platform)}"' for v in values]
            parts.append(f"({' or '.join(terms)})")

        elif platform == "sentinel":
            kql_ops = {
                "contains": "contains",
                "endswith": "endswith",
                "startswith": "startswith",
                "exact": "==",
                "re": "matches regex",
            }
            op = kql_ops.get(modifier, "contains")
            if len(values) > 1:
                quoted = ", ".join(f'"{v}"' for v in values)
                terms = f"({field} in~ ({quoted}))" if op == "==" else f"({field} has_any ({quoted}))"
            else:
                terms = f'({field} {op} "{values[0]}")'
            parts.append(terms)

    return " and ".join(parts) if parts else ""


def _parse_condition(condition_str: str, selections: dict[str, dict[str, Any]], platform: str) -> str:
    """Evaluate a Sigma condition expression against named selections."""
    tokens = condition_str.strip().split()
    # Replace selection names with their clause
    clauses: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.lower() == "and":
            clauses.append("AND" if platform == "splunk" else "and")
        elif tok.lower() == "or":
            clauses.append("OR" if platform == "splunk" else "or")
        elif tok.lower() == "not":
            clauses.append("NOT" if platform == "splunk" else "not")
        elif tok in selections:
            clause = _selection_to_clause(selections[tok], platform)
            clauses.append(clause if clause else "1==1")
        else:
            clauses.append(tok)
        i += 1
    return " ".join(clauses)


def convert(sigma_yaml: str, backend: str) -> str:
    """Convert a Sigma YAML rule to a SIEM-specific query string.

    backend: "splunk" | "elastic" | "sentinel"
    Returns an empty string if conversion fails.
    """
    try:
        sig: dict[str, Any] = yaml.safe_load(sigma_yaml)
    except Exception:
        return ""

    if not isinstance(sig, dict):
        return ""

    logsource: dict[str, str] = sig.get("logsource", {})
    category = str(logsource.get("category", "")).lower()
    product = str(logsource.get("product", "")).lower()

    detection: dict[str, Any] = sig.get("detection", {})
    condition_str: str = str(detection.get("condition", "selection"))

    # Collect named selections (everything in detection except 'condition')
    selections: dict[str, dict[str, Any]] = {
        k: v for k, v in detection.items()
        if k != "condition" and isinstance(v, dict)
    }
    # Handle list-style selections (Sigma allows list of dicts — OR them)
    for k, v in list(selections.items()):
        if isinstance(v, list):
            selections[k] = {str(i): item for i, item in enumerate(v)}

    platform = backend.lower()
    if platform not in ("splunk", "elastic", "sentinel"):
        return ""

    try:
        condition_clause = _parse_condition(condition_str, selections, platform)
    except Exception:
        condition_clause = ""

    if platform == "splunk":
        base = _SPLUNK_BASE.get((category, product), _SPLUNK_BASE.get((category, ""), "index=*"))
        return f"{base} {condition_clause}".strip()

    elif platform == "elastic":
        return condition_clause

    elif platform == "sentinel":
        table = _SENTINEL_TABLE.get((category, product), _SENTINEL_TABLE.get((category, ""), "Event"))
        where = f"| where {condition_clause}" if condition_clause else ""
        return f"{table}\n{where}".strip()

    return ""
