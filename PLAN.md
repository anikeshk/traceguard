# TraceGuard Implementation Plan

## Overview

TraceGuard is an agentic CVE triage and ownership automation tool with two main components:
1. **Agentic AI System** - Analyzes CVEs against a target codebase using OpenAI GPT
2. **Web UI** - Streamlit dashboard showing triage progress and results

## Design Decisions

### Technology Choices

| Component | Choice | Rationale |
|-----------|--------|-----------|
| AI Provider | OpenAI GPT | Strong reasoning capabilities for CVE analysis |
| Backend Framework | FastAPI | Modern, async, auto-generated API docs |
| Frontend | Streamlit | Python-only, quick to build data dashboards |
| Database | SQLite + SQLAlchemy | Simple, no setup, good for single-user/small teams |
| CVE Sources | Multiple (NVD, OSV, GitHub) | Comprehensive coverage, data deduplication |
| Triage Logic | Full analysis | Both dependency scanning AND code pattern matching |
| Ownership | CODEOWNERS + Git Blame | CODEOWNERS primary, git blame as fallback |

## Tech Stack

- **Backend**: FastAPI (async API server)
- **Frontend**: Streamlit (Python-based dashboard)
- **Database**: SQLite with SQLAlchemy ORM (async via aiosqlite)
- **AI**: OpenAI GPT (via openai SDK)
- **CVE Sources**: NVD API, OSV Database, GitHub Advisory

## Project Structure

```
traceguard/
├── pyproject.toml           # Project config & dependencies
├── .env.example             # Environment template
├── .gitignore
├── CLAUDE.md                # Developer documentation
├── PLAN.md                  # This file
├── src/
│   ├── __init__.py
│   ├── main.py              # FastAPI app entry point
│   ├── config.py            # Configuration management (pydantic-settings)
│   ├── database/
│   │   ├── __init__.py
│   │   ├── models.py        # SQLAlchemy models (CVE, TriageResult, Ownership, ScanJob)
│   │   └── connection.py    # Async database connection
│   ├── cve_sources/
│   │   ├── __init__.py
│   │   ├── base.py          # Abstract CVESource class
│   │   ├── nvd.py           # NVD API client
│   │   ├── osv.py           # OSV Database client
│   │   ├── github_advisory.py # GitHub Advisory client
│   │   └── aggregator.py    # Multi-source aggregator
│   ├── analysis/
│   │   ├── __init__.py
│   │   ├── agent.py         # Agentic CVE analysis orchestrator
│   │   ├── code_scanner.py  # Code pattern matching
│   │   ├── dependency_scanner.py # Dependency file analysis
│   │   └── ownership.py     # CODEOWNERS + git blame analysis
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes.py        # FastAPI routes
│   └── ui/
│       ├── __init__.py
│       └── app.py           # Streamlit dashboard
└── tests/
    └── __init__.py
```

## Implementation Phases

### Phase 1: Project Foundation ✅

1. Initialize Python project with pyproject.toml
2. Set up dependencies (fastapi, streamlit, openai, sqlalchemy, httpx)
3. Create config management (environment variables, .env support)
4. Set up SQLite database with SQLAlchemy models:
   - `CVE` - CVE metadata (id, description, severity, source, etc.)
   - `TriageResult` - Analysis results (cve_id, affected, confidence, reasoning)
   - `Ownership` - Owner assignments (triage_result_id, owner, source)
   - `ScanJob` - Track scanning job progress

### Phase 2: CVE Data Sources ✅

1. Create abstract `CVESource` base class with standardized `CVEData` dataclass
2. Implement NVD API client (rate-limited, paginated)
3. Implement OSV Database client
4. Implement GitHub Advisory client (GraphQL)
5. Create `CVEAggregator` to fetch/dedupe CVEs from all sources

### Phase 3: Code Analysis Engine ✅

1. **Dependency Scanner**:
   - Parse requirements.txt, Pipfile, pyproject.toml
   - Parse package.json, package-lock.json
   - Parse go.mod for Go projects
   - Match dependencies against CVE affected packages

2. **Code Scanner**:
   - Search for vulnerable code patterns (regex + AST for Python)
   - Check for imports of affected packages
   - Identify usage of vulnerable functions/methods
   - Support multiple languages (Python, JS/TS, Go)

### Phase 4: Ownership Analysis ✅

1. Parse CODEOWNERS file format (GitHub/GitLab style)
2. Implement git blame analysis for affected files
3. Create ownership resolution logic (CODEOWNERS > git blame fallback)
4. Calculate confidence scores based on line ownership percentage

### Phase 5: Agentic AI Triage ✅

1. Create OpenAI client wrapper with structured output
2. Design agent prompts for CVE analysis:
   - Context: CVE details, affected code snippets, dependency info
   - Task: Determine applicability, severity assessment, remediation
3. Implement multi-step agent workflow:
   - Step 1: Gather context (code scan + dependency scan)
   - Step 2: AI analysis of applicability
   - Step 3: Severity/priority assessment
   - Step 4: Generate remediation suggestions
4. Store results with confidence scores and reasoning

### Phase 6: FastAPI Backend ✅

1. Create API routes:
   - `POST /api/scan` - Trigger new CVE scan for a codebase
   - `GET /api/scan/{id}` - Get scan job status
   - `GET /api/cves` - List CVEs with filters
   - `GET /api/cves/{id}` - Get CVE details + triage results
   - `GET /api/triage` - List triage results with status
   - `POST /api/triage/{id}/override` - Manual override of triage decision
   - `GET /api/dashboard/stats` - Dashboard statistics
2. Add WebSocket endpoint for real-time progress updates

### Phase 7: Streamlit UI ✅

1. **Dashboard page**:
   - Summary stats (total CVEs, triaged, pending, affected)
   - Severity distribution chart
   - Quick actions

2. **Scan page**:
   - Configure target codebase (local path)
   - Select package ecosystem
   - Optional package filter
   - Real-time progress indicator

3. **CVE List page**:
   - Filterable table of CVEs
   - Severity filter
   - Pagination
   - Expandable details

4. **Triage Results page**:
   - Status filter (affected, not affected, pending)
   - AI reasoning display
   - Remediation suggestions
   - Owner information
   - Manual override controls

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan` | Start CVE scan for a codebase |
| GET | `/api/scan/{id}` | Get scan job status |
| WS | `/api/ws/scan/{id}` | WebSocket for real-time progress |
| GET | `/api/cves` | List CVEs with filters |
| GET | `/api/cves/{id}` | Get CVE details |
| GET | `/api/triage` | List triage results |
| POST | `/api/triage/{id}/override` | Manual override |
| GET | `/api/dashboard/stats` | Dashboard statistics |

## Database Schema

### CVE Table
- `id` (PK): CVE ID (e.g., CVE-2024-1234)
- `title`: Short title
- `description`: Full description
- `severity`: critical/high/medium/low/unknown
- `cvss_score`: CVSS base score
- `cvss_vector`: CVSS vector string
- `source`: Data source (nvd, osv, github)
- `affected_packages`: JSON list of package names
- `affected_versions`: JSON dict of version ranges
- `references`: JSON list of URLs

### TriageResult Table
- `id` (PK): Auto-increment
- `cve_id` (FK): Reference to CVE
- `codebase_path`: Path that was scanned
- `status`: pending/in_progress/affected/not_affected/needs_review
- `is_affected`: Boolean result
- `confidence`: 0.0-1.0 confidence score
- `reasoning`: AI explanation
- `affected_files`: JSON list of file paths
- `remediation`: Suggested fixes
- `priority_score`: 1-10 priority rating
- `manual_override`: Boolean flag
- `override_reason`: Human explanation

### Ownership Table
- `id` (PK): Auto-increment
- `triage_result_id` (FK): Reference to TriageResult
- `owner`: Email/username/team
- `source`: codeowners/git_blame/manual
- `file_path`: Associated file
- `confidence`: 0.0-1.0 for git blame

### ScanJob Table
- `id` (PK): Auto-increment
- `codebase_path`: Target path
- `status`: pending/running/completed/failed
- `total_cves`: Count of CVEs to process
- `processed_cves`: Current progress
- `affected_count`: CVEs marked affected
- `error_message`: Error details if failed

## Dependencies

```
fastapi>=0.109.0
uvicorn[standard]>=0.27.0
streamlit>=1.31.0
openai>=1.12.0
sqlalchemy>=2.0.0
httpx>=0.26.0
python-dotenv>=1.0.0
pydantic>=2.6.0
pydantic-settings>=2.1.0
gitpython>=3.1.0
aiosqlite>=0.19.0
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENAI_API_KEY` | Yes | OpenAI API key for AI triage |
| `OPENAI_MODEL` | No | Model to use (default: gpt-4o) |
| `NVD_API_KEY` | No | NVD API key (increases rate limits) |
| `GITHUB_TOKEN` | No | GitHub token for Advisory API |
| `DATABASE_URL` | No | Database URL (default: SQLite) |
| `DEBUG` | No | Enable debug mode |
| `API_HOST` | No | API host (default: 127.0.0.1) |
| `API_PORT` | No | API port (default: 8000) |

## Getting Started

1. **Install dependencies:**
   ```bash
   pip install -e .
   ```

2. **Configure environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your OPENAI_API_KEY
   ```

3. **Run the API server:**
   ```bash
   python -m src.main
   ```

4. **Run the Streamlit UI (separate terminal):**
   ```bash
   streamlit run src/ui/app.py
   ```

5. **Access the application:**
   - UI: http://localhost:8501
   - API docs: http://localhost:8000/docs

## Future Enhancements

- [ ] Add support for Git URL cloning (scan remote repos)
- [ ] Implement scheduled/periodic scanning
- [ ] Add Slack/email notifications for new vulnerabilities
- [ ] Support additional CVE sources (Snyk, etc.)
- [ ] Add SBOM (Software Bill of Materials) generation
- [ ] Implement batch remediation suggestions
- [ ] Add role-based access control
- [ ] Support PostgreSQL for team deployments
