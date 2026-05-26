"""Shared enums for CTI fields: TLP, Admiralty Code, Pyramid of Pain, etc."""

from __future__ import annotations

from enum import StrEnum


class TLP(StrEnum):
    """Traffic Light Protocol — sharing classification."""

    WHITE = "WHITE"
    GREEN = "GREEN"
    AMBER = "AMBER"
    RED = "RED"


class SourceReliability(StrEnum):
    """NATO Admiralty Code, source axis (A–F)."""

    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"


class InfoCredibility(StrEnum):
    """NATO Admiralty Code, info axis (1–6)."""

    ONE = "1"
    TWO = "2"
    THREE = "3"
    FOUR = "4"
    FIVE = "5"
    SIX = "6"


class PyramidOfPain(StrEnum):
    """David Bianco's Pyramid of Pain tiers, low → high."""

    HASH = "hash"
    IP = "ip"
    DOMAIN = "domain"
    ARTIFACT = "artifact"
    TOOL = "tool"
    TTP = "ttp"


class ActorSponsorType(StrEnum):
    NATION_STATE = "nation-state"
    FINANCIALLY_MOTIVATED = "financially-motivated"
    HACKTIVIST = "hacktivist"
    SCRIPT_KIDDIE = "script-kiddie"
    UNKNOWN = "unknown"


class IoCType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "md5"
    HASH_SHA1 = "sha1"
    HASH_SHA256 = "sha256"
    EMAIL = "email"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    FILE_PATH = "file_path"


class KillChainPhase(StrEnum):
    """Lockheed Martin Cyber Kill Chain phases."""

    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "command-and-control"
    ACTIONS_ON_OBJECTIVES = "actions-on-objectives"
