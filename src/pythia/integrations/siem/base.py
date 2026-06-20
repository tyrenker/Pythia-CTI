"""Abstract SIEM integration interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from pythia.models.rule import DetectionRule


class SiemIntegration(ABC):
    @abstractmethod
    def test_connection(self) -> bool: ...

    @abstractmethod
    def deploy_rule(self, rule: DetectionRule) -> str:
        """Returns the external rule ID assigned by the SIEM."""
        ...

    @abstractmethod
    def delete_rule(self, external_id: str) -> None: ...

    @abstractmethod
    def get_recent_alerts(self, since: datetime) -> list[dict]: ...
