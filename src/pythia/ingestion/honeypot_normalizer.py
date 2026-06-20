"""Maps T-Pot JSON event formats to HoneypotEvent field dicts."""

from __future__ import annotations

from datetime import datetime


def normalize_cowrie(raw: dict) -> dict:
    ts_str = raw.get("timestamp") or raw.get("time") or raw.get("ts")
    try:
        ts = (
            datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
            if ts_str
            else datetime.utcnow()
        )
    except ValueError:
        ts = datetime.utcnow()

    commands: list[str] = []
    files_downloaded: list[str] = []
    username: str | None = None
    password: str | None = None

    event_id = raw.get("eventid", "")
    if "login" in event_id:
        username = raw.get("username")
        password = raw.get("password")
    if "command" in event_id:
        cmd = raw.get("input") or raw.get("command")
        if cmd:
            commands = [cmd]
    if "file_download" in event_id or "download" in event_id:
        url = raw.get("url") or raw.get("shasum") or raw.get("outfile")
        if url:
            files_downloaded = [str(url)]

    from pythia.ingestion.cowrie_ttp_map import map_commands_to_ttps

    ttp_ids = map_commands_to_ttps(commands)

    return {
        "honeypot_type": "cowrie",
        "attacker_ip": raw.get("src_ip") or raw.get("remote_host") or "",
        "target_port": raw.get("dst_port") or raw.get("port"),
        "protocol": raw.get("protocol") or "ssh",
        "event_timestamp": ts,
        "tpot_session_id": raw.get("session") or raw.get("sessionid"),
        "username_attempted": username,
        "password_attempted": password,
        "commands_run": commands,
        "files_downloaded": files_downloaded,
        "payload_hash": raw.get("sha256") or raw.get("shasum"),
        "raw_payload": raw,
        "ttp_ids": ttp_ids,
    }


def normalize_dionaea(raw: dict) -> dict:
    ts_str = raw.get("timestamp") or raw.get("time") or raw.get("ts")
    try:
        ts = (
            datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
            if ts_str
            else datetime.utcnow()
        )
    except ValueError:
        ts = datetime.utcnow()

    port = raw.get("dst_port") or raw.get("port")
    if isinstance(port, str):
        try:
            port = int(port)
        except ValueError:
            port = None

    from pythia.ingestion.cowrie_ttp_map import map_dionaea_port_to_ttps

    ttp_ids = map_dionaea_port_to_ttps(port)

    return {
        "honeypot_type": "dionaea",
        "attacker_ip": raw.get("src_ip") or raw.get("remote_host") or "",
        "target_port": port,
        "protocol": raw.get("protocol") or raw.get("connection_type"),
        "event_timestamp": ts,
        "tpot_session_id": raw.get("connection_id"),
        "username_attempted": None,
        "password_attempted": None,
        "commands_run": [],
        "files_downloaded": [],
        "payload_hash": raw.get("sha256") or raw.get("sha512"),
        "raw_payload": raw,
        "ttp_ids": ttp_ids,
    }


def normalize_honeytrap(raw: dict) -> dict:
    ts_str = raw.get("timestamp") or raw.get("time")
    try:
        ts = (
            datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
            if ts_str
            else datetime.utcnow()
        )
    except ValueError:
        ts = datetime.utcnow()

    return {
        "honeypot_type": "honeytrap",
        "attacker_ip": raw.get("remote_addr") or raw.get("src_ip") or "",
        "target_port": raw.get("local_port") or raw.get("port"),
        "protocol": raw.get("protocol") or raw.get("type"),
        "event_timestamp": ts,
        "tpot_session_id": None,
        "username_attempted": None,
        "password_attempted": None,
        "commands_run": [],
        "files_downloaded": [],
        "payload_hash": None,
        "raw_payload": raw,
        "ttp_ids": [],
    }


def normalize_mailoney(raw: dict) -> dict:
    ts_str = raw.get("timestamp") or raw.get("time")
    try:
        ts = (
            datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
            if ts_str
            else datetime.utcnow()
        )
    except ValueError:
        ts = datetime.utcnow()

    return {
        "honeypot_type": "mailoney",
        "attacker_ip": raw.get("src_ip") or raw.get("remote_host") or "",
        "target_port": 25,
        "protocol": "smtp",
        "event_timestamp": ts,
        "tpot_session_id": None,
        "username_attempted": raw.get("username"),
        "password_attempted": raw.get("password"),
        "commands_run": [],
        "files_downloaded": [],
        "payload_hash": None,
        "raw_payload": raw,
        "ttp_ids": [],
    }


def normalize(raw: dict) -> dict:
    """Auto-detect T-Pot event format and normalize to HoneypotEvent field dict."""
    honeypot_type = (raw.get("honeypot_type") or raw.get("type") or raw.get("sensor") or "").lower()

    if "cowrie" in honeypot_type or "eventid" in raw or "session" in raw:
        return normalize_cowrie(raw)
    if "dionaea" in honeypot_type or "connection_type" in raw or "sha512" in raw:
        return normalize_dionaea(raw)
    if "mailoney" in honeypot_type or "mail" in honeypot_type:
        return normalize_mailoney(raw)
    if "honeytrap" in honeypot_type or "remote_addr" in raw:
        return normalize_honeytrap(raw)
    # fallback to cowrie-style
    return normalize_cowrie(raw)
