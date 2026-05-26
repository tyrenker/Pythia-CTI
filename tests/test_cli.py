"""Smoke tests for the extended Typer CLI commands."""

from __future__ import annotations

import json
import uuid
from typer.testing import CliRunner
from pythia.cli.main import app

runner = CliRunner()


def test_cli_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "Pythia" in result.stdout


def test_cli_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "list" in result.stdout
    assert "create" in result.stdout
    assert "parse" in result.stdout
    assert "report" in result.stdout


def test_cli_list_help() -> None:
    result = runner.invoke(app, ["list", "--help"])
    assert result.exit_code == 0
    assert "actors" in result.stdout
    assert "threats" in result.stdout
    assert "ttps" in result.stdout
    assert "iocs" in result.stdout
    assert "rules" in result.stdout


def test_cli_create_help() -> None:
    result = runner.invoke(app, ["create", "--help"])
    assert result.exit_code == 0
    assert "actor" in result.stdout


def test_cli_list_actors_json() -> None:
    result = runner.invoke(app, ["list", "actors", "--json", "--limit", "2"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert isinstance(data, list)


def test_cli_list_threats_json() -> None:
    result = runner.invoke(app, ["list", "threats", "--json", "--limit", "2"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert isinstance(data, list)


def test_cli_create_actor() -> None:
    name = f"TestActor-{uuid.uuid4().hex[:6]}"
    result = runner.invoke(
        app,
        [
            "create",
            "actor",
            "--name",
            name,
            "--country",
            "US",
            "--sponsor",
            "nation-state",
            "--sophistication",
            "3",
        ],
    )
    assert result.exit_code == 0
    assert "Successfully created threat actor" in result.stdout
    assert name in result.stdout


def test_cli_list_rule_detail() -> None:
    result = runner.invoke(app, ["list", "rule", "Suspicious Beaconing"])
    assert result.exit_code == 0
    assert "Rule Details" in result.stdout
    assert "Rule Definition" in result.stdout
    assert "Suspicious Beaconing" in result.stdout


def test_cli_list_ttp_detail() -> None:
    result = runner.invoke(app, ["list", "ttp", "T1010"])
    assert result.exit_code == 0
    assert "MITRE ATT&CK Technique" in result.stdout
    assert "T1010" in result.stdout
    assert "Application Window Discovery" in result.stdout


def test_cli_list_actor_detail() -> None:
    result = runner.invoke(app, ["list", "actor", "TestActor"])
    assert result.exit_code == 0
    assert "Actor Profile" in result.stdout
    assert "TestActor" in result.stdout
