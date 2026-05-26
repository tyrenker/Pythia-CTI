"""Loaders for MITRE ATT&CK, ATLAS, CAPEC, CWE, and OWASP LLM Top 10."""

from __future__ import annotations


def load_attack() -> dict[str, object]:
    raise NotImplementedError("Will read data/seed/mitre-attack.json")


def load_atlas() -> dict[str, object]:
    raise NotImplementedError("Will read data/seed/mitre-atlas.yaml")


def load_capec() -> dict[str, object]:
    raise NotImplementedError("Will read data/seed/capec.json")


def load_cwe() -> dict[str, object]:
    raise NotImplementedError("Will read data/seed/cwe.json")


def load_owasp_llm_top10() -> dict[str, object]:
    raise NotImplementedError("Will read data/seed/owasp-llm-top10.yaml")


def load_kev() -> dict[str, object]:
    raise NotImplementedError("Will fetch CISA KEV catalog")
