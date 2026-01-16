"""Dashboard page with statistics and job list."""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st
from datetime import datetime
from api_client import get_api_client

st.set_page_config(
    page_title="Dashboard - TraceGuard",
    page_icon="📊",
    layout="wide",
)

st.title("📊 Dashboard")


# Initialize API client
def get_client():
    return get_api_client()


def format_datetime(dt_str: str | None) -> str:
    """Format datetime string for display."""
    if not dt_str:
        return "-"
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return dt_str


def get_status_color(status: str) -> str:
    """Get color for status display."""
    colors = {
        "pending": "🟡",
        "running": "🔵",
        "completed": "🟢",
        "failed": "🔴",
    }
    return colors.get(status.lower(), "⚪")


# Check API connectivity
try:
    client = get_client()
    client.health_check()
    api_connected = True
except Exception as e:
    api_connected = False
    st.error(f"Cannot connect to API: {e}")
    st.info("Make sure the FastAPI server is running on http://localhost:8000")
    st.stop()

# Statistics section
st.markdown("### Statistics")

try:
    stats = client.get_stats()

    # Display stats in columns
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Scans", stats.get("total_jobs", 0))

    with col2:
        st.metric("Last 7 Days", stats.get("jobs_last_7_days", 0))

    with col3:
        st.metric("CVEs Analyzed", stats.get("cves_analyzed", 0))

    with col4:
        st.metric("Applicable CVEs", stats.get("applicable_cves", 0))

    # Severity breakdown
    st.markdown("### Severity Breakdown")
    severity = stats.get("by_severity", {})

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("🔴 Critical", severity.get("critical", 0))
    with col2:
        st.metric("🟠 High", severity.get("high", 0))
    with col3:
        st.metric("🟡 Medium", severity.get("medium", 0))
    with col4:
        st.metric("🟢 Low", severity.get("low", 0))
    with col5:
        st.metric("⚪ Unknown", severity.get("unknown", 0))

except Exception as e:
    st.warning(f"Could not load statistics: {e}")

# Job list section
st.markdown("---")
st.markdown("### Recent Scans")

# Add new scan button
col1, col2 = st.columns([6, 1])
with col2:
    if st.button("➕ New Scan", type="primary"):
        st.switch_page("pages/2_New_Scan.py")

# Pagination
page = st.session_state.get("job_page", 1)
page_size = 10

try:
    jobs_response = client.list_jobs(page=page, page_size=page_size)
    jobs = jobs_response.get("jobs", [])
    total = jobs_response.get("total", 0)

    if not jobs:
        st.info("No scans yet. Click 'New Scan' to start your first CVE analysis.")
    else:
        # Display jobs as a table
        for job in jobs:
            job_id = job.get("id")
            status = job.get("status", "unknown")
            status_icon = get_status_color(status)
            cve_count = job.get("cve_count", 0)
            codebase = job.get("codebase_path", "Unknown")
            created = format_datetime(job.get("created_at"))

            with st.container():
                col1, col2, col3, col4, col5 = st.columns([0.5, 3, 1, 1.5, 1])

                with col1:
                    st.markdown(f"**#{job_id}**")

                with col2:
                    # Truncate long paths
                    display_path = codebase if len(codebase) < 50 else f"...{codebase[-47:]}"
                    st.markdown(f"`{display_path}`")

                with col3:
                    st.markdown(f"{cve_count} CVE(s)")

                with col4:
                    st.markdown(f"{status_icon} {status.capitalize()}")

                with col5:
                    if st.button("View", key=f"view_{job_id}"):
                        st.session_state["selected_job_id"] = job_id
                        st.switch_page("pages/3_Job_Details.py")

                st.markdown("---")

        # Pagination controls
        total_pages = (total + page_size - 1) // page_size

        col1, col2, col3 = st.columns([1, 2, 1])
        with col1:
            if page > 1:
                if st.button("← Previous"):
                    st.session_state["job_page"] = page - 1
                    st.rerun()

        with col2:
            st.markdown(f"<center>Page {page} of {total_pages}</center>", unsafe_allow_html=True)

        with col3:
            if page < total_pages:
                if st.button("Next →"):
                    st.session_state["job_page"] = page + 1
                    st.rerun()

except Exception as e:
    st.error(f"Error loading jobs: {e}")

# Auto-refresh
st.markdown("---")
if st.button("🔄 Refresh"):
    st.rerun()
