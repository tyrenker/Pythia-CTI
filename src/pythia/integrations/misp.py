"""MISP integration client to push extracted IoCs."""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Any

from pythia.core.config import get_settings


def push_to_misp(event_info: str, iocs: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Push a list of IoCs to a configured MISP instance as a new Event.
    
    Returns the created MISP event data, or None if MISP is not configured or fails.
    """
    # Pythia doesn't have MISP config in settings by default, we simulate checking env vars
    # In a real setup, these would be in get_settings()
    import os
    misp_url = os.getenv("MISP_URL")
    misp_key = os.getenv("MISP_KEY")

    if not misp_url or not misp_key:
        print("MISP integration not configured (MISP_URL, MISP_KEY). Skipping push.")
        return None

    # 1. Create a new MISP event
    event_payload = {
        "Event": {
            "info": event_info,
            "distribution": 0, # Organization only
            "threat_level_id": 3, # Low
            "analysis": 0, # Initial
        }
    }

    headers = {
        "Authorization": misp_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    try:
        req = urllib.request.Request(
            f"{misp_url.rstrip('/')}/events/add",
            data=json.dumps(event_payload).encode(),
            headers=headers,
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            event_resp = json.loads(resp.read().decode())
            event_id = event_resp.get("Event", {}).get("id")
    except Exception as exc:
        print(f"Failed to create MISP event: {exc}")
        return None

    if not event_id:
        print("MISP returned invalid event ID.")
        return None

    # 2. Add attributes (IoCs) to the created event
    attributes = []
    for ioc in iocs:
        ioc_val = ioc.get("value")
        ioc_type = ioc.get("type", "unknown")
        if not ioc_val:
            continue

        misp_type = "other"
        if ioc_type == "ip":
            misp_type = "ip-dst"
        elif ioc_type == "domain":
            misp_type = "domain"
        elif ioc_type in ("md5", "sha1", "sha256"):
            misp_type = ioc_type.lower()
        elif ioc_type == "url":
            misp_type = "url"
        
        attributes.append({
            "event_id": event_id,
            "type": misp_type,
            "value": ioc_val,
            "category": "Network activity" if misp_type in ("ip-dst", "domain", "url") else "Payload delivery",
            "to_ids": True,
        })

    for attr in attributes:
        try:
            req = urllib.request.Request(
                f"{misp_url.rstrip('/')}/attributes/add/{event_id}",
                data=json.dumps(attr).encode(),
                headers=headers,
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                pass # Successfully added
        except Exception as exc:
            print(f"Failed to add attribute to MISP event {event_id}: {exc}")

    # 3. Publish the event
    try:
        req = urllib.request.Request(
            f"{misp_url.rstrip('/')}/events/publish/{event_id}",
            headers=headers,
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(f"Successfully pushed and published MISP event {event_id}")
    except Exception as exc:
        print(f"Failed to publish MISP event {event_id}: {exc}")

    return event_resp
