"""Factory that returns the configured SIEM integration."""

from __future__ import annotations

from pythia.integrations.siem.base import SiemIntegration


def get_siem_client() -> SiemIntegration | None:
    from pythia.core.config import get_settings

    settings = get_settings()
    siem_type = (settings.siem_type or "").lower()
    if not siem_type:
        return None
    if siem_type == "wazuh":
        from pythia.integrations.siem.wazuh import WazuhIntegration

        return WazuhIntegration(settings.siem_url, settings.siem_username, settings.siem_password)
    if siem_type == "splunk":
        from pythia.integrations.siem.splunk import SplunkIntegration

        return SplunkIntegration(settings.siem_url, settings.siem_username, settings.siem_password)
    if siem_type == "elastic":
        from pythia.integrations.siem.elastic import ElasticIntegration

        return ElasticIntegration(settings.siem_url, settings.siem_api_token)
    return None
