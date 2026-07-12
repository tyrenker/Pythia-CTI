"""Wazuh REST API SIEM integration."""

from __future__ import annotations

import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

import httpx

from pythia.integrations.siem.base import SiemIntegration
from pythia.models.rule import DetectionRule


class WazuhIntegration(SiemIntegration):
    def __init__(self, url: str, username: str, password: str) -> None:
        self._url = url.rstrip("/")
        self._username = username
        self._password = password
        self._token: str | None = None

    def _auth_header(self) -> dict[str, str]:
        if not self._token:
            resp = httpx.post(
                f"{self._url}/security/user/authenticate",
                auth=(self._username, self._password),
                verify=False,
                timeout=10,
            )
            resp.raise_for_status()
            self._token = resp.json()["data"]["token"]
        return {"Authorization": f"Bearer {self._token}"}

    def test_connection(self) -> bool:
        try:
            resp = httpx.get(
                f"{self._url}/",
                headers=self._auth_header(),
                verify=False,
                timeout=10,
            )
            return resp.status_code < 500
        except Exception:
            return False

    def _sigma_to_wazuh_xml(self, rule: DetectionRule) -> str:
        with tempfile.NamedTemporaryFile(suffix=".yml", mode="w", delete=False) as f:
            f.write(rule.content)
            tmp_path = f.name
        try:
            result = subprocess.run(
                ["sigma", "convert", "-t", "wazuh", tmp_path],
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
        # Fallback: minimal Wazuh XML rule
        rule_id = abs(hash(rule.id)) % 90000 + 100000
        return (
            f'<group name="pythia,">\n'
            f'  <rule id="{rule_id}" level="10">\n'
            f"    <description>Pythia: {rule.title}</description>\n"
            f"    <group>pythia,{rule.severity or 'medium'},</group>\n"
            f"  </rule>\n"
            f"</group>\n"
        )

    def deploy_rule(self, rule: DetectionRule) -> str:
        xml_content = self._sigma_to_wazuh_xml(rule)
        filename = f"pythia_{rule.id[:8]}.xml"
        resp = httpx.put(
            f"{self._url}/manager/rules/files/{filename}",
            headers={**self._auth_header(), "Content-Type": "application/xml"},
            content=xml_content.encode(),
            verify=False,
            timeout=30,
        )
        resp.raise_for_status()
        return filename

    def delete_rule(self, external_id: str) -> None:
        httpx.delete(
            f"{self._url}/manager/rules/files/{external_id}",
            headers=self._auth_header(),
            verify=False,
            timeout=10,
        ).raise_for_status()

    def get_recent_alerts(self, since: datetime) -> list[dict]:
        try:
            resp = httpx.get(
                f"{self._url}/alerts",
                params={"q": "rule.groups=pythia", "limit": 100},
                headers=self._auth_header(),
                verify=False,
                timeout=15,
            )
            if resp.status_code == 200:
                return resp.json().get("data", {}).get("affected_items", [])
        except Exception:
            pass
        return []
