"""Maps Cowrie command patterns to MITRE ATT&CK technique IDs."""

from __future__ import annotations

import re

COMMAND_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(wget|curl)\b"), "T1105"),
    (re.compile(r"\bchmod\b.*[+x]"), "T1222"),
    (re.compile(r"(/etc/passwd|/etc/shadow)"), "T1003.008"),
    (re.compile(r"\b(uname|/proc/cpuinfo|hostname)\b"), "T1082"),
    (re.compile(r"\b(crontab|/etc/cron)"), "T1053.003"),
    (re.compile(r"\b(iptables|ufw|firewall)\b"), "T1562.004"),
    (re.compile(r"\bssh\b.*-[oO]"), "T1021.004"),
    (re.compile(r"base64\s+(--decode|-d)"), "T1140"),
    (re.compile(r"\b(rm\s+-rf|shred|wipe)\b"), "T1070.004"),
    (re.compile(r"\b(ps\s|top\b|htop\b|netstat\b)"), "T1057"),
    (re.compile(r"\b(ifconfig|ip\s+addr|ip\s+link)\b"), "T1016"),
    (re.compile(r"/bin/bash|/bin/sh|/bin/dash"), "T1059.004"),
    (re.compile(r"\b(python|perl|ruby)\b.*-[ce]"), "T1059"),
    (re.compile(r"\b(nmap|masscan|zmap)\b"), "T1046"),
    (re.compile(r"\btar\b.*-[czjxf]"), "T1560"),
    (re.compile(r"\b(echo|printf)\b.*>>.*(bashrc|profile|rc\.local)"), "T1546.004"),
    (re.compile(r"\b(adduser|useradd|passwd)\b"), "T1136.001"),
    (re.compile(r"\b(pkill|kill|killall)\b"), "T1489"),
    (re.compile(r"\b(cryptominer|xmrig|minerd|cpuminer)\b"), "T1496"),
    (re.compile(r"\b(nc|netcat|ncat)\b.*(-e|-c)"), "T1059"),
]

DIONAEA_PORT_TTPS: dict[int, str] = {
    445: "T1210",  # SMB — Exploitation of Remote Services
    80: "T1105",  # HTTP — Ingress Tool Transfer
    443: "T1105",
    1433: "T1190",  # MSSQL — Exploit Public-Facing Application
    21: "T1105",  # FTP
}


def map_commands_to_ttps(commands: list[str]) -> list[str]:
    matched: set[str] = set()
    for cmd in commands:
        for pattern, ttp_id in COMMAND_PATTERNS:
            if pattern.search(cmd):
                matched.add(ttp_id)
    return sorted(matched)


def map_dionaea_port_to_ttps(port: int | None) -> list[str]:
    if port is None:
        return []
    ttp = DIONAEA_PORT_TTPS.get(port)
    return [ttp] if ttp else []
