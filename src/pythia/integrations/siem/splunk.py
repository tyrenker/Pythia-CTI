"""Splunk REST API SIEM integration."""

from __future__ import annotations

import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

import httpx

from pythia.integrations.siem.base import SiemIntegration
from pythia.models.rule import DetectionRule


class SplunkIntegration(SiemIntegration):
    def __init__(self, url: str, username: str, password: str) -> None:
        self._url = url.rstrip("/")
        self._username = username
        self._password = password

    def _auth(self) -> tuple[str, str]:
        return (self._username, self._password)

    def test_connection(self) -> bool:
        try:
            resp = httpx.get(
                f"{self._url}/services/server/info",
                auth=self._auth(),
                verify=False,
                timeout=10,
                params={"output_mode": "json"},
            )
            return resp.status_code < 500
        except Exception:
            return False

    def _sigma_to_spl(self, rule: DetectionRule) -> str:
        with tempfile.NamedTemporaryFile(suffix=".yml", mode="w", delete=False) as f:
            f.write(rule.content)
            tmp_path = f.name
        try:
            result = subprocess.run(
                ["sigma", "convert", "-t", "splunk", tmp_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout
        except Exception:
            pass
        finally:
            Path(tmp_path).unlink(missing_ok=True)
        return f'search index=* | where match(_raw, "pythia_{rule.id[:8]}")'

    def deploy_rule(self, rule: DetectionRule) -> str:
        spl = self._sigma_to_spl(rule)
        name = f"pythia_{rule.id[:8]}_{rule.title[:30].replace(' ', '_')}"
        resp = httpx.post(
            f"{self._url}/services/saved/searches",
            auth=self._auth(),
            data={"name": name, "search": spl, "alert_type": "always"},
            verify=False,
            timeout=30,
        )
        resp.raise_for_status()
        return name

    def delete_rule(self, external_id: str) -> None:
        httpx.delete(
            f"{self._url}/services/saved/searches/{external_id}",
            auth=self._auth(),
            verify=False,
            timeout=10,
        ).raise_for_status()

    def get_recent_alerts(self, since: datetime) -> list[dict]:
        try:
            resp = httpx.get(
                f"{self._url}/services/alerts/fired_alerts",
                auth=self._auth(),
                params={"output_mode": "json", "count": 100},
                verify=False,
                timeout=15,
            )
            if resp.status_code == 200:
                entries = resp.json().get("entry", [])
                return [e.get("content", {}) for e in entries]
        except Exception:
            pass
        return []
