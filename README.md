# TraceGuard

TraceGuard is an agentic CVE triage and ownership automation tool. It analyzes CVEs from OSV against a codebase to determine vulnerability applicability using AI-powered analysis.

## Features

- **CVE Context Collection**: Fetches vulnerability details from OSV and GitHub Security Advisories
- **Dependency Usage Detection**: Tree-sitter based static analysis to find package usage
- **Ownership Resolution**: Maps affected files to owners using CODEOWNERS
- **Ticket Generation**: AI-powered GitHub issue generation with impact assessment
- **Dashboard**: Streamlit UI for managing scans and viewing results

## Tech Stack

- **Backend**: FastAPI (async)
- **Frontend**: Streamlit
- **Database**: SQLite + async SQLAlchemy
- **AI**: OpenAI GPT + LangGraph for agent orchestration
- **CVE Sources**: OSV, GitHub Security Advisories
- **Static Analysis**: Tree-sitter (AST-based)
- **Package Manager**: uv

## Setup

### 1. Install dependencies

```bash
uv venv
uv sync
```

### 2. Configure environment

Copy the example environment file and add your API keys:

```bash
cp .env.example .env
```

Edit `.env` and add:
- `OPENAI_API_KEY` - Your OpenAI API key (for AI-powered impact assessment)
- `GITHUB_TOKEN` - GitHub personal access token (for GitHub Security Advisories API)

### 3. Initialize the database

```bash
uv run alembic upgrade head
```

## Running the Application

### Start the FastAPI server

```bash
uv run uvicorn traceguard.main:app --reload
```

The API will be available at http://localhost:8000

- API docs: http://localhost:8000/docs
- Health check: http://localhost:8000/api/v1/health

### Start the Streamlit dashboard

In a separate terminal:

```bash
uv run streamlit run streamlit_app/app.py
```

The dashboard will be available at http://localhost:8501

## Usage

### Via Streamlit UI

1. Open http://localhost:8501
2. Click "New Scan"
3. Enter the path to your codebase
4. Enter CVE IDs to analyze (one per line)
5. Click "Start Scan"
6. View results in the Dashboard

### Via API

Create a scan job:

```bash
curl -X POST http://localhost:8000/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "codebase_path": "/path/to/your/codebase",
    "cve_ids": ["CVE-2021-44228", "CVE-2022-22965"]
  }'
```

Get job details:

```bash
curl http://localhost:8000/api/v1/jobs/1
```

Get dashboard stats:

```bash
curl http://localhost:8000/api/v1/stats
```

## Project Structure

```
traceguard/
├── src/traceguard/
│   ├── main.py                 # FastAPI entry point
│   ├── config.py               # Configuration
│   ├── core/                   # Database, exceptions
│   ├── models/                 # SQLAlchemy models
│   ├── schemas/                # Pydantic schemas
│   ├── cve_sources/            # OSV, GitHub clients
│   ├── analyzers/              # Tree-sitter, CODEOWNERS
│   ├── agents/                 # LangGraph pipeline
│   ├── services/               # Business logic
│   └── api/                    # FastAPI routes
├── streamlit_app/              # Streamlit frontend
├── alembic/                    # Database migrations
└── tests/                      # Test suite
```

## Agent Pipeline

The triage pipeline executes these steps:

1. **CVE Context Agent**: Fetches CVE data from OSV and GitHub
2. **Dependency Usage Agent**: Scans codebase for package usage via Tree-sitter
3. **Ownership Agent**: Resolves file owners from CODEOWNERS
4. **Ticket Generation Agent**: Generates GitHub issue with AI impact assessment

If a package is not used in the codebase, the CVE is marked as "Not Applicable" and the pipeline ends early.

## Supported Ecosystems

Currently supported:
- **npm** (JavaScript/TypeScript)

The architecture supports adding more ecosystems (Python, Go, etc.) by implementing the `DependencyAnalyzer` interface.

## License

MIT
