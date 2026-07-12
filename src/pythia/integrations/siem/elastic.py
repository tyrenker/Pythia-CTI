"""Elasticsearch/Kibana detection rules SIEM integration."""

from __future__ import annotations

import subprocess
import tempfile
import uuid
from datetime import datetime
from pathlib import Path

import httpx

from pythia.integrations.siem.base import SiemIntegration
from pythia.models.rule import DetectionRule


class ElasticIntegration(SiemIntegration):
    def __init__(self, url: str, api_token: str) -> None:
        self._url = url.rstrip("/")
        self._headers = {
            "Authorization": f"ApiKey {api_token}",
            "kbn-xsrf": "true",
            "Content-Type": "application/json",
        }

    def test_connection(self) -> bool:
        try:
            resp = httpx.get(
                f"{self._url}/api/status",
                headers=self._headers,
                verify=False,
                timeout=10,
            )
            return resp.status_code < 500
        except Exception:
            return False

    def _sigma_to_eql(self, rule: DetectionRule) -> str:
        with tempfile.NamedTemporaryFile(suffix=".yml", mode="w", delete=False) as f:
            f.write(rule.content)
            tmp_path = f.name
        try:
            result = subprocess.run(
                ["sigma", "convert", "-t", "elasticsearch", tmp_path],
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
        return f'network where process.name : "*"  // Pythia: {rule.title}'

    def deploy_rule(self, rule: DetectionRule) -> str:
        query = self._sigma_to_eql(rule)
        rule_uuid = str(uuid.uuid4())
        payload = {
            "name": f"Pythia: {rule.title}",
            "description": f"Auto-deployed by Pythia from rule {rule.id}",
            "risk_score": {"critical": 99, "high": 73, "medium": 47, "low": 21}.get(
                rule.severity or "medium", 47
            ),
            "severity": rule.severity or "medium",
            "type": "query",
            "query": query,
            "index": ["logs-*", "filebeat-*"],
            "tags": ["pythia"],
            "rule_id": rule_uuid,
            "enabled": True,
        }
        resp = httpx.post(
            f"{self._url}/api/detection_engine/rules",
            headers=self._headers,
            json=payload,
            verify=False,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json().get("id", rule_uuid)

    def delete_rule(self, external_id: str) -> None:
        httpx.delete(
            f"{self._url}/api/detection_engine/rules",
            headers=self._headers,
            params={"id": external_id},
            verify=False,
            timeout=10,
        ).raise_for_status()

    def get_recent_alerts(self, since: datetime) -> list[dict]:
        try:
            resp = httpx.post(
                f"{self._url}/api/alerts/find",
                headers=self._headers,
                json={
                    "filter": {"bool": {"filter": [{"term": {"tags": "pythia"}}]}},
                    "page": 1,
                    "per_page": 100,
                },
                verify=False,
                timeout=15,
            )
            if resp.status_code == 200:
                return resp.json().get("data", [])
        except Exception:
            pass
        return []
