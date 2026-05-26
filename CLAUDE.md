# CLAUDE.md — Pythia conventions for LLM-assisted development

This file briefs an LLM coding agent on how to work in this repo. Read it before writing code.

## Project

Pythia is a CTI (cyber threat intelligence) platform. Full build spec lives at `internal_docs/threat_intel_spec.md` — treat it as the source of truth for features, data models, and roadmap.

## Stack

- Python **3.11+**
- **FastAPI** for the HTTP API
- **SQLAlchemy 2.0** (sync) for ORM
- **Pydantic v2** for schemas and config
- **Typer** for the CLI
- **pytest** for tests
- **ruff** for lint + format, **mypy** for types

## Conventions

- **Type everything.** `mypy --strict` is on. No untyped functions.
- **Imports.** Use `from __future__ import annotations` in every module so type hints are strings.
- **No barrel re-exports.** Import from the source module (e.g. `from pythia.api.actors import router`), not from `__init__.py`.
- **Routers** live in `src/pythia/api/<topic>.py` and are registered in `api/main.py::create_app`.
- **Settings** flow through `pythia.core.config.get_settings()` — never read `os.environ` directly.
- **DB sessions** are dependency-injected via `pythia.core.db.get_session`.
- **Auth** on write endpoints uses the `pythia.core.security.require_api_key` dependency.
- **Stubs** raise `NotImplementedError` or return HTTP 501. Don't fake responses.
- **Tests** mirror the source tree under `tests/` (e.g. `tests/api/test_actors.py`).
- **Frontend** lives under `frontend/` (React/Vite/TS) and is served statically by the FastAPI backend when built.

## When adding a feature

1. Read the relevant section of `internal_docs/threat_intel_spec.md`.
2. If a model needs fields, add them in `pythia/models/` first.
3. Wire the route in the matching `pythia/api/<topic>.py` and remove the 501 stub.
4. Add a pytest in `tests/api/test_<topic>.py` that hits the route via the FastAPI `TestClient`.
5. Run `ruff check . && ruff format . && mypy src && pytest` before declaring done.

## Out of scope (do not add without asking)

- User accounts / RBAC — single API key is enough for v1.
- Multi-tenancy.
- GraphQL.
- Kubernetes manifests.

See `internal_docs/threat_intel_spec.md` §10 for the full deliberate-exclusion list.

## Style guardrails for the LLM

- Don't add error handling for cases that can't happen.
- Don't add backward-compat shims — this project has no users yet.
- Don't write multi-line comment blocks. One short line max; only when *why* is non-obvious.
- Don't introduce abstractions you don't immediately need. Three similar lines beats a premature interface.
- Don't create `README.md` files inside subpackages — the root README is the only one.
