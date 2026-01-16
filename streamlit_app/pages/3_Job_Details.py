"""Job Details page showing analysis results."""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st
from datetime import datetime
from api_client import get_api_client

st.set_page_config(
    page_title="Job Details - TraceGuard",
    page_icon="📋",
    layout="wide",
)


def get_client():
    return get_api_client()


def format_datetime(dt_str: str | None) -> str:
    """Format datetime string for display."""
    if not dt_str:
        return "-"
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return dt_str


def get_status_badge(status: str) -> str:
    """Get status badge HTML."""
    colors = {
        "pending": ("🟡", "#ffc107"),
        "running": ("🔵", "#17a2b8"),
        "completed": ("🟢", "#28a745"),
        "failed": ("🔴", "#dc3545"),
        "skipped": ("⚪", "#6c757d"),
    }
    icon, color = colors.get(status.lower(), ("⚪", "#6c757d"))
    return f"{icon} {status.capitalize()}"


def get_applicability_badge(applicability: str | None) -> str:
    """Get applicability badge."""
    if applicability == "applicable":
        return "🔴 Applicable"
    elif applicability == "not_applicable":
        return "🟢 Not Applicable"
    else:
        return "⚪ Unknown"


# Check API connectivity
try:
    client = get_client()
    client.health_check()
except Exception as e:
    st.error(f"Cannot connect to API: {e}")
    st.stop()

# Get job ID from session state or URL params
job_id = st.session_state.get("selected_job_id")

if not job_id:
    st.warning("No job selected. Please select a job from the Dashboard.")
    if st.button("← Go to Dashboard"):
        st.switch_page("pages/1_Dashboard.py")
    st.stop()

# Fetch job details
try:
    job = client.get_job(job_id)
except Exception as e:
    st.error(f"Error loading job: {e}")
    if st.button("← Go to Dashboard"):
        st.switch_page("pages/1_Dashboard.py")
    st.stop()

# Header
st.title(f"📋 Job #{job_id}")

# Job overview
col1, col2, col3 = st.columns(3)

with col1:
    st.markdown(f"**Status:** {get_status_badge(job.get('status', 'unknown'))}")

with col2:
    st.markdown(f"**Created:** {format_datetime(job.get('created_at'))}")

with col3:
    if job.get("completed_at"):
        st.markdown(f"**Completed:** {format_datetime(job.get('completed_at'))}")
    elif job.get("started_at"):
        st.markdown(f"**Started:** {format_datetime(job.get('started_at'))}")

st.markdown(f"**Codebase:** `{job.get('codebase_path', 'Unknown')}`")

if job.get("error_message"):
    st.error(f"Error: {job.get('error_message')}")

st.markdown("---")

# CVE Analyses
st.markdown("### CVE Analyses")

cve_analyses = job.get("cve_analyses", [])

if not cve_analyses:
    st.info("No CVE analyses found for this job.")
else:
    for cve in cve_analyses:
        cve_id = cve.get("cve_id", "Unknown")
        applicability = cve.get("applicability")

        with st.expander(f"**{cve_id}** - {get_applicability_badge(applicability)}", expanded=True):
            # Applicability reason
            reason = cve.get("applicability_reason")
            if reason:
                if applicability == "applicable":
                    st.warning(f"📍 {reason}")
                else:
                    st.success(f"✓ {reason}")

            # Agent steps
            st.markdown("#### Pipeline Steps")
            steps = cve.get("steps", [])

            if steps:
                for step in sorted(steps, key=lambda s: s.get("step_order", 0)):
                    agent_name = step.get("agent_name", "Unknown")
                    status = step.get("status", "unknown")
                    status_badge = get_status_badge(status)

                    # Format agent name
                    agent_display = agent_name.replace("_", " ").title()

                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.markdown(f"**{step.get('step_order', '?')}. {agent_display}**")
                    with col2:
                        st.markdown(status_badge)

                    # Show error if failed
                    if step.get("error_message"):
                        st.error(f"Error: {step.get('error_message')}")

                    # Show output data summary
                    output = step.get("output_data", {})
                    if output:
                        if agent_name == "cve_context" and output.get("cve_context"):
                            ctx = output.get("cve_context", {})
                            severity = ctx.get("severity", "Unknown")
                            st.markdown(f"- Severity: **{severity}**")
                            st.markdown(f"- Packages: {len(ctx.get('affected_packages', []))}")

                        elif agent_name == "dependency_usage":
                            is_applicable = output.get("is_applicable")
                            evidence_count = output.get("evidence_count", 0)
                            if is_applicable:
                                st.markdown(f"- Found **{evidence_count}** usage(s)")
                            else:
                                st.markdown("- No usage found")

                        elif agent_name == "ownership":
                            owner_count = output.get("owner_count", 0)
                            st.markdown(f"- Resolved **{owner_count}** owner(s)")

                        elif agent_name == "ticket_generation":
                            title = output.get("title")
                            if title:
                                st.markdown(f"- Issue: *{title[:60]}...*")

                    st.markdown("---")

            # Generated Issue
            issue = cve.get("generated_issue")
            if issue:
                st.markdown("#### Generated Issue")

                st.markdown(f"**Title:** {issue.get('title', 'No title')}")

                # Show issue body in expandable section
                with st.expander("View Issue Body"):
                    st.markdown(issue.get("body", "No body"))

                # GitHub URL
                github_url = issue.get("github_issue_url")
                if github_url:
                    st.markdown("**GitHub Issue URL:**")
                    st.code(f"https://github.com/YOUR_ORG/YOUR_REPO{github_url}", language=None)
                    st.info("Replace YOUR_ORG/YOUR_REPO with your actual repository path")

# Refresh button
st.markdown("---")
col1, col2 = st.columns([1, 5])

with col1:
    if st.button("🔄 Refresh"):
        st.rerun()

with col2:
    if st.button("← Back to Dashboard"):
        st.switch_page("pages/1_Dashboard.py")

# Auto-refresh for running jobs
if job.get("status") == "running":
    st.info("Job is running... Auto-refreshing in 5 seconds.")
    import time
    time.sleep(5)
    st.rerun()
