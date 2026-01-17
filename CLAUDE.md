# CLAUDE.md

## Project: TraceGuard

TraceGuard is an **agentic vulnerability triage and ownership automation tool** designed to close the gap between security findings and developer action. It continuously ingests GitHub security alerts, translates them into developer-friendly guidance, resolves ownership, and creates actionable Jira tickets with full transparency and auditability.

The system is designed to scale from local, ad-hoc analysis to CI/CD-triggered automation while remaining explainable at every step.

## Core Goals

- Reduce alert fatigue from GitHub / Dependabot security findings
- Translate CVEs into **clear, developer-actionable summaries**
- Automatically determine **who owns the fix**
- Create **high-signal Jira tickets** instead of raw security alerts
- Maintain **full auditability** of every decision made by agents

## Tech Stack

- **FastAPI (async)** — primary API surface
- **LangGraph** — agent orchestration and state management
- **SQLAlchemy (async)** + **SQLite** — job state, artifacts, audit logs
- **Streamlit** — inspection UI for agent runs and artifacts
- **OpenAI GPT** — CVE summarization and reasoning
- **GitHub API** — Dependabot & security advisory ingestion
- **Jira API** — ticket creation and assignment

## Features

### 1. GitHub Security Intake Agent
- Token is provided in the .env file.
- Fetches **open security alerts** (Dependabot / GitHub Security Advisories).
- Exits cleanly if no open alerts exist.
- Iterates over each alert when present.

**Outputs**
- Normalized security alert list
- Raw CVE identifiers and metadata

### 2. CVE Summarization Agent
- Converts raw CVE data into **developer-friendly summaries**:
  - What is vulnerable
  - Why it matters
  - Likely impact on the repo
  - What action is required (possible fixes)
- Avoids security jargon and CVE boilerplate.
- Produces a concise, actionable summary artifact.

**Outputs**
- Developer-focused CVE summary
- Severity and urgency signals

### 3. Ownership Resolution Agent
- Produces a resolved owner by looking up the repo owner.
- Fails explicitly if ownership cannot be determined.

**Outputs**
- Owner(s)

### 4. Jira Ticket Creation Agent
- JIRA token and key to use is provided in .env
- Creates a Jira issue containing:
  - CVE summary (developer-focused)
  - Severity → Jira priority mapping
  - Recommended remediation path
  - References and evidence
- Assigns the ticket to the resolved owner.
- Supports **dry-run mode** for previewing tickets.

**Outputs**
- Jira ticket payload
- Jira issue URL (if created)

### 5. Agent Transparency & Audit Trail
- Every agent step records:
  - Inputs
  - Outputs
  - Decisions
  - Failures
- All artifacts are persisted and visible in the UI.
- No silent failures or hidden heuristics.

## API Design Principles

- All functionality is exposed via **async APIs**
- UI is a consumer of the same APIs (no hidden logic)
- Designed for future CI/CD triggers and webhooks
- Agent boundaries are explicit and replaceable

## Extensibility Guidelines

- Use **abstract base classes** for:
  - Security sources (GitHub today, others later)
  - Ownership resolvers
  - Ticketing systems
- New agents must:
  - Accept structured inputs
  - Emit structured artifacts
  - Fail loudly and explicitly

## Codebase Standards

- Python only
- Package management via **uv**
- Virtual environment required
- Async-first design
- Type hints everywhere
- No side-effects outside agent boundaries

## Configuration & Secrets

All secrets are loaded via `.env`:
