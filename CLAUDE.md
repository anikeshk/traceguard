# TraceGuard

TraceGuard is an agentic CVE triage and ownership automation tool. It analyzes CVEs from OSV against a codebase to determine vulnerability applicability using AI-powered analysis.

## Tech Stack

This is the tech stack we should use:

- **Backend**: FastAPI (async API server)
- **Frontend**: Streamlit (Python-based dashboard)
- **Database**: SQLite with SQLAlchemy ORM (async)
- **AI**: OpenAI GPT for agentic triage analysis
- **CVE Sources**: OSV Database

## Features

### **1. Local CVE Analysis (Agentic Pipeline)**
- User provides:
  - **Local codebase path**
  - **One or more CVE IDs**
- A LangGraph-based agent pipeline is triggered and executed step-by-step.
- Each agent produces artifacts and audit logs that are persisted and shown in the UI.

---

### **2. CVE Context Collection Agent**
- Fetches full CVE context from:
  - GitHub Security Advisories
  - OSV (as fallback / enrichment)
- Normalizes and stores:
  - Affected package(s)
  - Ecosystem (npm, pip, etc.)
  - Vulnerable version ranges
  - Fixed versions
  - Severity (CVSS, EPSS if available)
  - Description, references, remediation notes
- Outputs a structured CVE context file (JSON) used by downstream agents.
- Fails explicitly if CVE data cannot be resolved.

---

### **3. Dependency Usage Detection Agent (Static Analysis)**
- Uses **Tree-sitter (AST-based analysis)** to scan the local JavaScript codebase.
- Finds **evidence of dependency usage**, including:
  - `import ... from "<package>"`
  - `require("<package>")`
  - Framework-specific global usage (e.g., test runners)
- Produces file-level evidence:
  - File path
  - Line number
  - Usage type
- If no usage is found, agent marks the CVE as **Not Applicable** with evidence.

---

### **4. Ownership Resolution Agent**
- Reads and parses the repository’s **CODEOWNERS** file.
- Maps affected file paths to responsible owners.
- Fails clearly if:
  - CODEOWNERS is missing
  - No owner can be resolved
- Outputs a resolved owner list with reasoning.

---

### **5. Ticket Generation & GitHub Issue Agent**
- Generates a **copy-paste–ready security issue** containing:
  - CVE summary and severity
  - Evidence of usage in the codebase
  - Impact assessment
  - Recommended fix (including whether a major upgrade is required)
  - Assigned owner(s)
- Optionally generates a **one-click GitHub Issue creation URL** with:
  - Pre-filled title
  - Pre-filled body
  - Pre-assigned owners (when supported)
- Does not auto-create issues unless explicitly enabled.

---

### **6. UI Visibility & Failure Transparency**
- Streamlit UI shows:
  - Each agent step as a discrete stage
  - Inputs, outputs, and artifacts per agent
  - Success / failure state per step
- Any missing data, failed API call, or analysis error is:
  - Explicitly surfaced in the UI
  - Logged as part of the job’s audit trail




**2. Create Issue with Context**
- Download the CODEOWNERS file (assume it will be there or exit)
- Based on severity, create an issue with the CVE context specific to this project and assign the owner based on the CODEOWNERs file

**3. Dashboard**
- Dashboard shows each scan as a job with the different steps (audit trail)
- Basic stats on top
- The main page is stats on top; list of job scans below the stats
- Button to create a new scan
- If you click a job scan you get all the details

## Codebase

These are codebase standards for this project that Claude Code must use.

- Python codebase using uv as the package manager; create a virtual env
- Abstract classes as much as possible (so we can add more CVE sources later or extract the dependencies from other place)
- APIs whenever possible to enable extensibility (CICD pipeline can trigger a scan instead of using the UI for example)
- .env file for the tokens (OpenAI API, GitHub)