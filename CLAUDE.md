# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TraceGuard is an agentic CVE triage and ownership automation tool. It analyzes CVEs from multiple sources (NVD, OSV, GitHub Advisory) against a codebase to determine vulnerability applicability using AI-powered analysis.

## Tech Stack

- **Backend**: FastAPI (async API server)
- **Frontend**: Streamlit (Python-based dashboard)
- **Database**: SQLite with SQLAlchemy ORM (async)
- **AI**: OpenAI GPT for agentic triage analysis
- **CVE Sources**: NVD API, OSV Database, GitHub Advisory

## Build & Development Commands

```bash
# Create virtual environment and install dependencies
uv venv
uv pip install -e .

# Install dev dependencies
uv pip install -e ".[dev]"

# Run the API server
uv run python -m src.main
# or
uv run uvicorn src.main:app --reload

# Run the Streamlit UI
uv run streamlit run src/ui/app.py

# Run tests
uv run pytest

# Lint code
uv run ruff check src/
```

## Architecture

```
src/
├── main.py                 # FastAPI app entry point
├── config.py               # Configuration management (pydantic-settings)
├── database/
│   ├── models.py           # SQLAlchemy models (CVE, TriageResult, Ownership, ScanJob)
│   └── connection.py       # Async database connection
├── cve_sources/
│   ├── base.py             # Abstract CVESource class
│   ├── nvd.py              # NVD API client
│   ├── osv.py              # OSV Database client
│   ├── github_advisory.py  # GitHub Advisory client
│   └── aggregator.py       # Multi-source aggregator
├── analysis/
│   ├── agent.py            # AI-powered triage (TriageAgent, TriageOrchestrator)
│   ├── code_scanner.py     # Source code pattern matching
│   ├── dependency_scanner.py # Dependency file parser
│   └── ownership.py        # CODEOWNERS + git blame analysis
├── api/
│   └── routes.py           # FastAPI routes
└── ui/
    └── app.py              # Streamlit dashboard
```

## Key Components

### CVE Sources
- All sources implement `CVESource` abstract base class
- `CVEAggregator` fetches from multiple sources and deduplicates

### Analysis Pipeline
1. `DependencyScanner` - Parses requirements.txt, pyproject.toml, package.json, etc.
2. `CodeScanner` - Finds imports/usage of affected packages
3. `OwnershipResolver` - Determines code owners via CODEOWNERS and git blame
4. `TriageAgent` - Uses OpenAI GPT to analyze CVE applicability

### API Endpoints
- `POST /api/scan` - Start CVE scan for a codebase
- `GET /api/cves` - List CVEs
- `GET /api/triage` - List triage results
- `POST /api/triage/{id}/override` - Manual override

## Environment Variables

Copy `.env.example` to `.env` and configure:

- `OPENAI_API_KEY` - Required for AI triage
- `NVD_API_KEY` - Optional, increases rate limits
- `GITHUB_TOKEN` - Required for GitHub Advisory source
