#!/usr/bin/env python3
"""
Seed a fully-populated demo threat hunt session for interview / portfolio demos.

Creates: hunt session + 12 observations + analyst notes + 3 draft detections
No Claude API calls required — detections are written directly.

Usage (server must be running):
    python3 scripts/seed_demo_hunt.py

Options:
    --base-url   API base URL (default: http://localhost:8000/v1)
    --api-key    API key (default: reads from .env in project root)
    --reset      Delete the existing demo hunt first if found
"""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BASE_URL = "http://localhost:8000/v1"
DEMO_HUNT_NAME = "APT29 Q2 Spearphishing — Tier-1 Finance Targeting"


def load_api_key() -> str:
    env_file = PROJECT_ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.startswith("PYTHIA_API_KEY="):
                return line.split("=", 1)[1].strip()
    return "changeme"


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

class Client:
    def __init__(self, base_url: str, api_key: str) -> None:
        self.base = base_url.rstrip("/")
        self.headers = {
            "Content-Type": "application/json",
            "X-API-Key": api_key,
        }

    def get(self, path: str) -> dict | list:
        r = requests.get(f"{self.base}{path}", headers=self.headers, timeout=10)
        r.raise_for_status()
        return r.json()

    def post(self, path: str, body: dict) -> dict:
        r = requests.post(f"{self.base}{path}", json=body, headers=self.headers, timeout=10)
        r.raise_for_status()
        return r.json()

    def put(self, path: str, body: dict) -> dict:
        r = requests.put(f"{self.base}{path}", json=body, headers=self.headers, timeout=10)
        r.raise_for_status()
        return r.json()

    def delete(self, path: str) -> None:
        r = requests.delete(f"{self.base}{path}", headers=self.headers, timeout=10)
        r.raise_for_status()


def ok(msg: str) -> None:
    print(f"  \033[32m✓\033[0m {msg}")


def info(msg: str) -> None:
    print(f"  \033[34m→\033[0m {msg}")


# ---------------------------------------------------------------------------
# Hunt session
# ---------------------------------------------------------------------------

HUNT_PAYLOAD = {
    "name": DEMO_HUNT_NAME,
    "hypothesis": (
        "APT29 (Cozy Bear) is conducting a targeted spearphishing campaign against "
        "tier-1 financial institutions using weaponized Excel lure documents to deploy "
        "a lightweight backdoor and establish persistent C2 via HTTPS to actor-controlled "
        "infrastructure masquerading as Microsoft CDN endpoints."
    ),
    "analyst": "Ty Renker",
    "sector_focus": ["Financial Services", "Banking"],
    "motivation_focus": ["espionage", "data-theft"],
}

# ---------------------------------------------------------------------------
# Observations  (obs_type, value, confidence_source, confidence_info, notes)
# ---------------------------------------------------------------------------

OBSERVATIONS = [
    # ── IOCs — Hashes (Pyramid tier: hash) ───────────────────────────────────
    {
        "obs_type": "ioc_hash",
        "value": "4a8b2f3c9e1d6045ab7c8f2e3d4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2",
        "confidence_source": "B",
        "confidence_info": "2",
        "notes": "SHA-256 of q2-earnings-analysis.xlsm — macro dropper confirmed by three AV engines. Drops Stage-2 DLL to %APPDATA%\\Microsoft\\Update\\svchost32.dll",
    },
    {
        "obs_type": "ioc_hash",
        "value": "9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0",
        "confidence_source": "B",
        "confidence_info": "2",
        "notes": "SHA-256 of Stage-2 DLL (svchost32.dll). Packed with custom XTEA variant. Communicates with C2 over port 443 with self-signed cert using OU=Microsoft Corporation.",
    },
    # ── IOCs — IPs (Pyramid tier: ip) ────────────────────────────────────────
    {
        "obs_type": "ioc_ip",
        "value": "185.220.101.47",
        "confidence_source": "B",
        "confidence_info": "1",
        "notes": "Known Tor exit node observed in C2 beacon traffic. Pivot from pcap captured by finance sector ISAC member. Certificate thumbprint matches known APT29 cluster.",
    },
    {
        "obs_type": "ioc_ip",
        "value": "45.142.212.100",
        "confidence_source": "C",
        "confidence_info": "2",
        "notes": "Secondary C2 IP. Hosted on AS202425 (IP Volume Inc), a bulletproof hosting provider repeatedly associated with APT29 infrastructure. Registered 2026-03-14.",
    },
    # ── IOCs — Domains (Pyramid tier: domain) ────────────────────────────────
    {
        "obs_type": "ioc_domain",
        "value": "update.microsoft-cdn[.]net",
        "confidence_source": "B",
        "confidence_info": "1",
        "notes": "Primary C2 domain. Typosquats the legitimate microsoft.com CDN. WHOIS shows registration 2026-04-01 via Namecheap — 47 days before first observed use. Resolves to 185.220.101.47.",
    },
    {
        "obs_type": "ioc_domain",
        "value": "secure-docs-portal[.]com",
        "confidence_source": "B",
        "confidence_info": "1",
        "notes": "Phishing landing site serving weaponized XLSM lures. Hosting on Cloudflare proxy. Cert issued by Let's Encrypt. Related subdomain sharepoint.secure-docs-portal[.]com also observed.",
    },
    # ── IOCs — URLs (Pyramid tier: artifact) ─────────────────────────────────
    {
        "obs_type": "ioc_url",
        "value": "https://secure-docs-portal[.]com/documents/q2-earnings-analysis.xlsm",
        "confidence_source": "A",
        "confidence_info": "1",
        "notes": "Direct download URL for weaponized lure. Subject line 'Q2 Earnings Preview — Restricted Distribution'. Targeted CFOs and IR analysts at three named banks per ISAC report TLP:AMBER.",
    },
    # ── IOCs — Email (Pyramid tier: artifact) ────────────────────────────────
    {
        "obs_type": "ioc_email",
        "value": "investor-relations@secure-docs-portal[.]com",
        "confidence_source": "B",
        "confidence_info": "1",
        "notes": "Sender address on confirmed phishing emails. Display name spoofs 'Goldman Sachs IR'. DKIM fails — no valid SPF record for domain. Sent via SendGrid API (abuse report submitted).",
    },
    # ── IOCs — Mutex (Pyramid tier: artifact) ────────────────────────────────
    {
        "obs_type": "ioc_mutex",
        "value": "Global\\MicrosoftCryptographicService_7fa3b",
        "confidence_source": "B",
        "confidence_info": "2",
        "notes": "Mutex created by Stage-2 DLL on first execution — used as single-instance guard. Pattern 'MicrosoftCryptographicService_[5 hex chars]' consistent with previously documented APT29 SUNBURST loader family.",
    },
    # ── TTPs ─────────────────────────────────────────────────────────────────
    {
        "obs_type": "ttp",
        "value": "T1566.001",
        "confidence_source": "A",
        "confidence_info": "1",
        "notes": "Spearphishing Attachment — confirmed delivery of .xlsm lure via email. Macro executes on Open via Excel 4.0 macro technique (XLM), not VBA, to evade many AV signatures.",
    },
    {
        "obs_type": "ttp",
        "value": "T1059.001",
        "confidence_source": "B",
        "confidence_info": "2",
        "notes": "PowerShell execution — Stage-1 XLM macro spawns PowerShell with -WindowStyle Hidden -EncodedCommand. Encoded payload is a AMSI bypass + reflective DLL loader.",
    },
    {
        "obs_type": "ttp",
        "value": "T1071.001",
        "confidence_source": "B",
        "confidence_info": "1",
        "notes": "C2 over HTTPS (port 443). Beacon interval observed at 30s ± jitter. JA3 fingerprint: 771,4866-4867-4865-49196-49195-49188-49187-49162-49161-52393-49200-49199-49192-49191-49172-49171-157-156-61-60-53-47-49160-49170-10,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
    },
    # ── Actor attribution ─────────────────────────────────────────────────────
    {
        "obs_type": "actor",
        "value": "APT29 (Cozy Bear)",
        "confidence_source": "C",
        "confidence_info": "2",
        "notes": "Attribution to APT29 based on: (1) TTP overlap with NOBELIUM cluster, (2) infrastructure registration patterns matching historic APT29 ops, (3) XLM macro technique consistent with 2020-2023 APT29 campaigns. Not yet corroborated by independent intel.",
    },
]

# ---------------------------------------------------------------------------
# Analyst notes (markdown)
# ---------------------------------------------------------------------------

NOTES_CONTENT = """# Hunt: APT29 Q2 Spearphishing — Tier-1 Finance Targeting

**Analyst:** Ty Renker
**Status:** Active
**Classification:** TLP:AMBER — Restricted to financial sector partners

---

## Hypothesis

APT29 (Cozy Bear) is conducting a targeted spearphishing campaign against tier-1 financial institutions using weaponized Excel lure documents to deploy a lightweight backdoor and establish persistent C2 via HTTPS to actor-controlled infrastructure masquerading as Microsoft CDN endpoints.

---

## Timeline

| Date | Event |
|------|-------|
| 2026-05-12 | ISAC TLP:AMBER advisory circulated — three tier-1 banks received suspicious XLSM lures |
| 2026-05-14 | Hash confirmed malicious by internal sandbox; macro analysis completed |
| 2026-05-18 | C2 domain `update.microsoft-cdn[.]net` identified via passive DNS pivot |
| 2026-05-20 | Secondary IP `45.142.212.100` observed in PCAP from ISAC partner |
| 2026-05-22 | Hunt formally initiated; observations loaded into Pythia |
| 2026-05-29 | Sigma and KQL detections drafted; pending review + pipeline deployment |

---

## Pivot 1 — Lure Document Analysis

Starting IOC: `q2-earnings-analysis.xlsm` (SHA256: `4a8b2f3c...`)

The XLSM uses Excel 4.0 macros (XLM), not VBA — this sidesteps the majority of macro-based AV detections and many EDR heuristics. The macro chain:

1. `Auto_Open` → calls hidden sheet cells containing obfuscated XLM
2. XLM decodes a PowerShell command: `-WindowStyle Hidden -EncodedCommand <base64>`
3. PowerShell performs AMSI patching via `[Ref].Assembly...` reflection
4. Reflective DLL loader drops `svchost32.dll` to `%APPDATA%\\Microsoft\\Update\\`
5. Persistence via `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`

**Key indicator for detection:** `excel.exe` spawning `powershell.exe` with `-EncodedCommand` is reliably detectable and low-FP in financial sector environments where macro policies are enforced.

---

## Pivot 2 — Infrastructure Analysis

Domain: `update.microsoft-cdn[.]net`
- Registered 2026-04-01 via Namecheap with privacy protection
- WHOIS pattern matches prior APT29 infrastructure cluster documented in Mandiant APT29 2023 report
- Hosted on IP `185.220.101.47` (Tor exit node — likely intermediary relay)
- TLS certificate: self-signed, OU=Microsoft Corporation — classic APT29 masquerading pattern

Secondary IP `45.142.212.100`:
- ASN: AS202425 (IP Volume Inc) — bulletproof hoster
- Co-hosted with 14 other suspicious domains on same /24 subnet
- Recommend full /24 block in perimeter defenses

---

## Pivot 3 — TTP Overlap with Known APT29

Cross-referencing against ATT&CK:

| Technique | Confidence | Notes |
|-----------|-----------|-------|
| T1566.001 Spearphishing Attachment | High | Direct observation |
| T1059.001 PowerShell | High | Macro → PS chain confirmed |
| T1071.001 Web Protocols | Medium | HTTPS C2, 30s beacon |
| T1547.001 Registry Run Keys | Medium | Inferred from DLL dropper pattern |
| T1027 Obfuscated Files | High | XLM + encoded PS + packed DLL |

XLM macro technique and XTEA packing variant are consistent with the NOBELIUM/APT29 cluster documented in public reporting from 2021–2024. Confidence in APT29 attribution: **MEDIUM** (C2 / pre-corroborated).

---

## Gaps & Recommended Pivots

- [ ] Obtain PCAP from affected organization to confirm beacon timing and JA3/JA3S fingerprints
- [ ] Check internal mail gateway logs for the sender domain `secure-docs-portal[.]com`
- [ ] Submit mutex string to internal intel team for cross-hunt correlation
- [ ] Verify if any internal endpoints communicated with `185.220.101.47` or `45.142.212.100`
- [ ] Review EDR telemetry for `excel.exe` → `powershell.exe` process chains in the last 30 days

---

## Assessment

Campaign is consistent with APT29 Q1-Q2 2026 operational tempo targeting Western financial institutions ahead of anticipated rate decision disclosures. Recommend escalation to incident response if any internal endpoint telemetry matches the C2 indicators.
"""

# ---------------------------------------------------------------------------
# Draft detections  (written directly — no Claude call needed)
# ---------------------------------------------------------------------------

DETECTIONS = [
    {
        "title": "APT29 Lure — Excel Spawning Encoded PowerShell",
        "rule_type": "sigma",
        "pyramid_tier": "ttp",
        "rationale": (
            "Excel 4.0 macro lures consistently spawn PowerShell with -EncodedCommand. "
            "This chain (excel.exe → powershell.exe -EncodedCommand) is high-confidence in "
            "environments where macro execution policies are enforced. Low FP rate in finance sector."
        ),
        "linked_ttp_ids": ["T1566.001", "T1059.001"],
        "status": "reviewed",
        "content": """\
title: APT29 Excel Lure Spawning Encoded PowerShell
id: 7f3a2d91-84bc-4e1f-b6c3-1a9e05f82d47
status: experimental
description: |
    Detects Excel spawning PowerShell with an encoded command — primary delivery
    mechanism for APT29 Q2 2026 spearphishing campaign targeting finance sector.
    The XLM macro chain decodes a base64 payload that performs AMSI bypass and
    reflective DLL loading.
references:
    - https://attack.mitre.org/techniques/T1566/001/
    - https://attack.mitre.org/techniques/T1059/001/
author: Ty Renker
date: 2026-05-29
tags:
    - attack.initial_access
    - attack.t1566.001
    - attack.execution
    - attack.t1059.001
    - detection.emerging_threats
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\\\excel.exe'
            - '\\\\EXCEL.EXE'
    selection_child:
        Image|endswith: '\\\\powershell.exe'
        CommandLine|contains:
            - '-EncodedCommand'
            - '-enc '
            - '-e '
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate Excel-based automation tools using encoded PS (rare in finance environments)
    - Developer workstations running Excel add-in build pipelines
level: high
""",
    },
    {
        "title": "APT29 C2 — HTTPS Beacon to Known Infrastructure",
        "rule_type": "kql",
        "pyramid_tier": "domain",
        "rationale": (
            "KQL query for Microsoft Sentinel to detect outbound connections to confirmed APT29 C2 "
            "infrastructure. Covers both the primary CDN-masquerading domain and the secondary bulletproof "
            "hosting IP. Pivot from this alert to DeviceProcessEvents to identify the parent process."
        ),
        "linked_ttp_ids": ["T1071.001"],
        "status": "draft",
        "content": """\
// APT29 Q2 2026 — C2 Beacon Detection
// Detects outbound HTTPS connections to confirmed APT29 infrastructure
// Pivot: join on DeviceId to DeviceProcessEvents to identify parent process
//
// References:
//   ATT&CK T1071.001 — Application Layer Protocol: Web Protocols
//   Hunt: APT29 Q2 Spearphishing — Tier-1 Finance Targeting

let apt29_domains = dynamic([
    "update.microsoft-cdn.net",
    "secure-docs-portal.com"
]);
let apt29_ips = dynamic([
    "185.220.101.47",
    "45.142.212.100"
]);

DeviceNetworkEvents
| where TimeGenerated >= ago(30d)
| where ActionType == "ConnectionSuccess"
| where RemotePort == 443
| where (RemoteUrl has_any (apt29_domains))
    or (RemoteIP in (apt29_ips))
| project
    TimeGenerated,
    DeviceName,
    LocalIP,
    RemoteIP,
    RemoteUrl,
    RemotePort,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName
| order by TimeGenerated desc
""",
    },
    {
        "title": "APT29 Persistence — Suspicious Run Key from Office Process",
        "rule_type": "sigma",
        "pyramid_tier": "artifact",
        "rationale": (
            "Stage-2 DLL establishes persistence via HKCU Run key written by the Office process chain. "
            "Detecting Office applications writing to standard Run key locations with DLL or executable "
            "paths in APPDATA is a reliable indicator of post-exploitation persistence."
        ),
        "linked_ttp_ids": ["T1547.001"],
        "status": "draft",
        "content": """\
title: APT29 Persistence via Run Key Written by Office Process
id: c9b1e4a7-3d2f-4891-a7b6-2e5f8c3d1a09
status: experimental
description: |
    Detects registry Run key persistence written by Microsoft Office processes.
    Consistent with APT29 Stage-2 DLL loader establishing persistence after
    initial Excel macro execution. The DLL is dropped to %APPDATA%\\Microsoft\\Update\\
    and registered under HKCU Run to survive reboots.
references:
    - https://attack.mitre.org/techniques/T1547/001/
author: Ty Renker
date: 2026-05-29
tags:
    - attack.persistence
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection_key:
        TargetObject|contains:
            - '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
            - '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
    selection_process:
        Image|endswith:
            - '\\excel.exe'
            - '\\EXCEL.EXE'
            - '\\powershell.exe'
            - '\\wscript.exe'
            - '\\cscript.exe'
    selection_value:
        Details|contains:
            - 'AppData'
            - 'AppData\\Roaming'
            - '.dll'
    condition: selection_key and selection_process and selection_value
falsepositives:
    - Legitimate Office automation or IT management tools
    - Software installers run inside Office environments
level: high
""",
    },
]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(base_url: str, api_key: str, reset: bool) -> None:
    client = Client(base_url, api_key)

    # Health check
    try:
        client.get("/health")
    except Exception as e:
        print(f"\n\033[31m✗\033[0m Cannot reach {base_url} — is the server running?\n  {e}")
        sys.exit(1)

    print(f"\n\033[1mPythia demo hunt seeder\033[0m")
    print(f"  Target: {base_url}")
    print()

    # Optional reset — find and delete existing demo hunt by name
    if reset:
        info("Checking for existing demo hunt to reset...")
        hunts = client.get("/hunts?limit=100")
        for h in hunts:  # type: ignore[union-attr]
            if h["name"] == DEMO_HUNT_NAME:
                client.delete(f"/hunts/{h['id']}")
                ok(f"Deleted existing demo hunt ({h['id']})")

    # Create hunt session
    info("Creating hunt session...")
    hunt = client.post("/hunts", HUNT_PAYLOAD)
    session_id = hunt["id"]
    ok(f"Created hunt '{hunt['name']}' — {session_id}")

    # Add observations
    print()
    info(f"Adding {len(OBSERVATIONS)} observations...")
    for obs in OBSERVATIONS:
        result = client.post(f"/hunts/{session_id}/observations", obs)
        tier = result.get("pyramid_tier") or obs["obs_type"]
        ok(f"  [{tier:8s}] {obs['value'][:60]}")

    # Add analyst notes
    print()
    info("Adding analyst notes...")
    client.put(f"/hunts/{session_id}/notes", {"content": NOTES_CONTENT})
    ok(f"Notes added ({len(NOTES_CONTENT)} chars, {len(NOTES_CONTENT.splitlines())} lines)")

    # Insert draft detections directly into the SQLite DB.
    # Uses sqlite3 (stdlib) so no extra deps are needed.
    print()
    info(f"Adding {len(DETECTIONS)} draft detections (direct SQLite insert)...")
    db_candidates = [
        PROJECT_ROOT / "db" / "pythia.db",     # Docker mount path
        PROJECT_ROOT / "pythia.db",             # local dev path
    ]
    db_path = next((p for p in db_candidates if p.exists()), None)
    if not db_path:
        print("  \033[33m!\033[0m SQLite DB not found — skipping detections.")
        print(f"    Looked in: {', '.join(str(p) for p in db_candidates)}")
    else:
        import sqlite3
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        con = sqlite3.connect(str(db_path))
        try:
            for d in DETECTIONS:
                con.execute(
                    """INSERT INTO hunt_draft_detections
                       (id, session_id, title, rule_type, content, pyramid_tier,
                        linked_ttp_ids, linked_obs_ids, rationale, status,
                        created_at, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        str(uuid.uuid4()),
                        session_id,
                        d["title"],
                        d["rule_type"],
                        d["content"],
                        d["pyramid_tier"],
                        json.dumps(d["linked_ttp_ids"]),
                        json.dumps([]),
                        d["rationale"],
                        d["status"],
                        now,
                        now,
                    ),
                )
                ok(f"  [{d['rule_type']:5s}] {d['title']}")
            con.commit()
        finally:
            con.close()

    # Done
    print()
    print(f"\033[1m\033[32m✓ Demo hunt ready!\033[0m")
    print(f"  URL: http://localhost:3000/hunt/{session_id}")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed a demo threat hunt session in Pythia")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="API base URL")
    parser.add_argument("--api-key", default=None, help="Pythia API key (reads .env if omitted)")
    parser.add_argument("--reset", action="store_true", help="Delete existing demo hunt first")
    args = parser.parse_args()

    api_key = args.api_key or load_api_key()
    run(args.base_url, api_key, args.reset)
