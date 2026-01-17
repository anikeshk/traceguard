import logging

import streamlit as st
import httpx

logger = logging.getLogger(__name__)

API_BASE_URL = "http://localhost:8000"


def fetch_repositories() -> list[dict]:
    """Fetch repositories from the FastAPI backend."""
    try:
        response = httpx.get(f"{API_BASE_URL}/api/repos", timeout=30.0)
        response.raise_for_status()
        return response.json()
    except httpx.ConnectError:
        st.error("Cannot connect to API. Ensure FastAPI server is running on port 8000.")
        return []
    except httpx.ReadTimeout:
        st.error("Request timed out.")
        return []
    except httpx.HTTPStatusError as e:
        st.error(f"API error: {e.response.text}")
        return []
    except Exception as e:
        logger.error(f"Failed to fetch repositories: {e}")
        st.error(f"Failed to fetch repositories: {e}")
        return []


def fetch_jobs() -> list[dict]:
    """Fetch jobs from the FastAPI backend."""
    try:
        response = httpx.get(f"{API_BASE_URL}/api/jobs", timeout=30.0)
        response.raise_for_status()
        return response.json()
    except httpx.ConnectError:
        st.error("Cannot connect to API. Ensure FastAPI server is running on port 8000.")
        return []
    except httpx.ReadTimeout:
        st.error("Request timed out.")
        return []
    except httpx.HTTPStatusError as e:
        st.error(f"API error: {e.response.text}")
        return []
    except Exception as e:
        logger.error(f"Failed to fetch jobs: {e}")
        st.error(f"Failed to fetch jobs: {e}")
        return []


def fetch_job_details(job_id: int) -> dict | None:
    """Fetch job details from the FastAPI backend."""
    try:
        response = httpx.get(f"{API_BASE_URL}/api/jobs/{job_id}", timeout=30.0)
        response.raise_for_status()
        return response.json()
    except httpx.ConnectError:
        st.error("Cannot connect to API. Ensure FastAPI server is running on port 8000.")
        return None
    except httpx.ReadTimeout:
        st.error("Request timed out.")
        return None
    except httpx.HTTPStatusError as e:
        st.error(f"API error: {e.response.text}")
        return None
    except Exception as e:
        logger.error(f"Failed to fetch job details: {e}")
        st.error(f"Failed to fetch job details: {e}")
        return None


def create_job(repo: dict) -> dict | None:
    """Create a new job for a repository."""
    try:
        response = httpx.post(
            f"{API_BASE_URL}/api/jobs",
            json={
                "repo_name": repo["name"],
                "repo_full_name": repo["full_name"],
                "repo_owner": repo["owner"],
                "repo_url": repo["url"],
            },
            timeout=30.0,
        )
        response.raise_for_status()
        return response.json()
    except httpx.ConnectError:
        st.error("Cannot connect to API. Ensure FastAPI server is running on port 8000.")
        return None
    except httpx.ReadTimeout:
        st.error("Request timed out.")
        return None
    except httpx.HTTPStatusError as e:
        st.error(f"API error: {e.response.text}")
        return None
    except Exception as e:
        logger.error(f"Failed to create job: {e}")
        st.error(f"Failed to create job: {e}")
        return None


def fetch_audit_trail(job_id: int) -> list[dict]:
    """Fetch audit trail for a job from the FastAPI backend."""
    try:
        response = httpx.get(f"{API_BASE_URL}/api/jobs/{job_id}/audit", timeout=30.0)
        response.raise_for_status()
        return response.json()
    except httpx.ConnectError:
        st.error("Cannot connect to API. Ensure FastAPI server is running on port 8000.")
        return []
    except httpx.ReadTimeout:
        st.error("Request timed out.")
        return []
    except httpx.HTTPStatusError as e:
        st.error(f"API error: {e.response.text}")
        return []
    except Exception as e:
        logger.error(f"Failed to fetch audit trail: {e}")
        st.error(f"Failed to fetch audit trail: {e}")
        return []


def get_status_color(status: str) -> str:
    """Get color for job status."""
    colors = {
        "pending": "gray",
        "fetching_alerts": "blue",
        "resolving_owner": "blue",
        "completed": "green",
        "failed": "red",
    }
    return colors.get(status, "gray")


def get_severity_color(severity: str) -> str:
    """Get color for alert severity."""
    colors = {
        "critical": "red",
        "high": "orange",
        "medium": "yellow",
        "low": "blue",
    }
    return colors.get(severity.lower(), "gray")


def render_scan_page() -> None:
    """Render the Scan page for repository selection."""
    st.header("Scan Repositories")
    st.write("Select a repository to scan for security vulnerabilities")

    # Initialize session state for selected repo
    if "selected_repo" not in st.session_state:
        st.session_state.selected_repo = None

    # Fetch repositories
    with st.spinner("Loading repositories..."):
        repos = fetch_repositories()

    if not repos:
        st.warning("No repositories found. Check your GitHub token configuration.")
        return

    st.write(f"Found {len(repos)} repositories")

    # Display repositories as a selection list
    for repo in repos:
        full_name = repo["full_name"]
        description = repo.get("description") or "No description"
        visibility = repo["visibility"]

        col1, col2, col3 = st.columns([3, 1, 1])

        with col1:
            st.write(f"**{full_name}**")
            st.caption(f"{description} | {visibility}")

        with col2:
            st.link_button("GitHub", repo["url"], use_container_width=True)

        with col3:
            if st.button("Scan", key=f"scan_{full_name}", use_container_width=True):
                with st.spinner(f"Creating scan job for {full_name}..."):
                    job = create_job(repo)
                    if job:
                        st.success(f"Scan job created! Job ID: {job['id']}")
                        st.info("The scan is running in the background. Check the Jobs tab for results.")


def render_jobs_page() -> None:
    """Render the Jobs page for viewing scan results."""
    st.header("Scan Jobs")

    # Add refresh button
    col1, col2 = st.columns([6, 1])
    with col2:
        if st.button("Refresh", use_container_width=True):
            st.rerun()

    # Fetch jobs
    with st.spinner("Loading jobs..."):
        jobs = fetch_jobs()

    if not jobs:
        st.info("No scan jobs found. Go to the Scan tab to create one.")
        return

    st.write(f"Found {len(jobs)} jobs")

    # Display jobs
    for job in jobs:
        status = job["status"]
        status_color = get_status_color(status)

        with st.expander(
            f"**{job['repo_full_name']}** | :{status_color}[{status}] | {job['alert_count']} alerts",
            expanded=False,
        ):
            # Job metadata
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Job ID:** {job['id']}")
                st.write(f"**Repository:** [{job['repo_full_name']}]({job['repo_url']})")
                st.write(f"**Owner:** {job['repo_owner']}")

            with col2:
                st.write(f"**Status:** :{status_color}[{status}]")
                st.write(f"**Created:** {job['created_at']}")
                st.write(f"**Alerts:** {job['alert_count']}")

            if job["error_message"]:
                st.error(f"Error: {job['error_message']}")

            # Show details button
            if st.button("View Details", key=f"details_{job['id']}"):
                st.session_state.selected_job_id = job["id"]
                st.rerun()

    # Show job details if selected
    if "selected_job_id" in st.session_state and st.session_state.selected_job_id:
        render_job_details(st.session_state.selected_job_id)


def render_job_details(job_id: int) -> None:
    """Render detailed view of a job."""
    st.divider()
    st.subheader(f"Job Details (ID: {job_id})")

    # Close button
    if st.button("Close Details"):
        st.session_state.selected_job_id = None
        st.rerun()

    with st.spinner("Loading job details..."):
        job = fetch_job_details(job_id)

    if not job:
        st.error("Failed to load job details")
        return

    # Job info
    status_color = get_status_color(job["status"])
    st.write(f"**Repository:** [{job['repo_full_name']}]({job['repo_url']})")
    st.write(f"**Status:** :{status_color}[{job['status']}]")

    # Owner info
    st.subheader("Owner")
    if job["owner"]:
        owner = job["owner"]
        st.write(f"**Username:** {owner['username']}")
        st.write(f"**Name:** {owner['name'] or 'N/A'}")
        st.write(f"**Email:** {owner['email'] or 'No public email'}")
    else:
        st.info("Owner information not yet resolved")

    # Alerts
    st.subheader(f"Security Alerts ({len(job['alerts'])})")
    if not job["alerts"]:
        st.success("No security alerts found!")
    else:
        for alert in job["alerts"]:
            severity = alert["severity"]
            severity_color = get_severity_color(severity)

            with st.expander(
                f":{severity_color}[{severity.upper()}] | {alert['package_name']} | {alert['cve_id'] or 'No CVE'}",
                expanded=False,
            ):
                col1, col2 = st.columns(2)

                with col1:
                    st.write(f"**Package:** {alert['package_name']}")
                    st.write(f"**Ecosystem:** {alert['package_ecosystem']}")
                    st.write(f"**CVE:** {alert['cve_id'] or 'N/A'}")
                    st.write(f"**Severity:** :{severity_color}[{severity}]")

                with col2:
                    st.write(f"**State:** {alert['state']}")
                    st.write(f"**Vulnerable:** {alert['vulnerable_version_range'] or 'N/A'}")
                    st.write(f"**Patched:** {alert['patched_version'] or 'No patch available'}")
                    st.link_button("View on GitHub", alert["html_url"])

                if alert["summary"]:
                    st.write("**Summary:**")
                    st.write(alert["summary"])

                if alert["description"]:
                    with st.expander("Full Description"):
                        st.write(alert["description"])

    # Audit Trail
    render_audit_trail(job_id)


def render_audit_trail(job_id: int) -> None:
    """Render the audit trail for a job."""
    st.subheader("Audit Trail")
    st.caption("Step-by-step execution log with inputs, outputs, and decisions")

    with st.spinner("Loading audit trail..."):
        audit_entries = fetch_audit_trail(job_id)

    if not audit_entries:
        st.info("No audit trail available yet. The job may still be running.")
        return

    for entry in audit_entries:
        step_name = entry["step_name"].replace("_", " ").title()
        timestamp = entry["timestamp"]
        has_errors = bool(entry.get("errors"))

        # Use different icon based on success/failure
        icon = "x" if has_errors else "white_check_mark"

        with st.expander(f":{icon}: **{step_name}** - {timestamp}", expanded=False):
            col1, col2 = st.columns(2)

            with col1:
                st.write("**Inputs:**")
                if entry["inputs"]:
                    for key, value in entry["inputs"].items():
                        st.write(f"- {key}: `{value}`")
                else:
                    st.write("- None")

            with col2:
                st.write("**Outputs:**")
                if entry["outputs"]:
                    for key, value in entry["outputs"].items():
                        st.write(f"- {key}: `{value}`")
                else:
                    st.write("- None")

            st.write("**Decisions:**")
            if entry["decisions"]:
                for decision in entry["decisions"]:
                    st.write(f"- {decision}")
            else:
                st.write("- No decisions recorded")

            if has_errors:
                st.error("**Errors:**")
                for error in entry["errors"]:
                    st.write(f"- {error}")


def main() -> None:
    st.set_page_config(
        page_title="TraceGuard",
        page_icon="shield",
        layout="wide",
    )

    st.title("TraceGuard")

    # Sidebar navigation
    with st.sidebar:
        st.header("Navigation")
        page = st.radio(
            "Select a page",
            ["Scan", "Jobs"],
            label_visibility="collapsed",
        )

    # Render selected page
    if page == "Scan":
        render_scan_page()
    elif page == "Jobs":
        render_jobs_page()


if __name__ == "__main__":
    main()
