"""Streamlit UI for TraceGuard."""

import asyncio
import json
import time
from pathlib import Path

import httpx
import streamlit as st

from src.config import get_settings

settings = get_settings()
API_BASE = f"http://{settings.api_host}:{settings.api_port}/api"


def get_api_client() -> httpx.Client:
    """Get HTTP client for API calls."""
    return httpx.Client(base_url=API_BASE, timeout=30.0)


def main():
    """Main Streamlit application."""
    st.set_page_config(
        page_title="TraceGuard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    st.title("🛡️ TraceGuard")
    st.caption("Agentic CVE Triage and Ownership Automation")

    # Sidebar navigation
    page = st.sidebar.radio(
        "Navigation",
        ["Dashboard", "Scan", "CVE List", "Triage Results"],
        index=0,
    )

    if page == "Dashboard":
        show_dashboard()
    elif page == "Scan":
        show_scan_page()
    elif page == "CVE List":
        show_cve_list()
    elif page == "Triage Results":
        show_triage_results()


def show_dashboard():
    """Show the dashboard page."""
    st.header("Dashboard")

    try:
        with get_api_client() as client:
            response = client.get("/dashboard/stats")
            if response.status_code == 200:
                stats = response.json()
            else:
                st.error("Failed to load dashboard stats")
                return
    except httpx.ConnectError:
        st.error("Cannot connect to API server. Make sure it's running.")
        st.info("Start the API server with: `python -m src.main`")
        return

    # Stats cards
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total CVEs", stats["total_cves"])

    with col2:
        st.metric("Triaged", stats["triaged_count"])

    with col3:
        st.metric(
            "Affected",
            stats["affected_count"],
            delta=None if stats["affected_count"] == 0 else "needs attention",
            delta_color="inverse",
        )

    with col4:
        st.metric("Pending", stats["pending_count"])

    st.divider()

    # Severity breakdown
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Severity Distribution")
        if stats["total_cves"] > 0:
            severity_data = {
                "Critical": stats["critical_count"],
                "High": stats["high_count"],
                "Other": stats["total_cves"] - stats["critical_count"] - stats["high_count"],
            }
            st.bar_chart(severity_data)
        else:
            st.info("No CVEs in database yet. Run a scan to get started.")

    with col2:
        st.subheader("Quick Actions")
        st.info("Use the sidebar navigation to access Scan, CVE List, and Triage Results.")


def show_scan_page():
    """Show the scan configuration page."""
    st.header("New CVE Scan")

    with st.form("scan_form"):
        codebase_path = st.text_input(
            "Codebase Path",
            placeholder="/path/to/your/project",
            help="Enter the full path to the codebase you want to scan",
        )

        ecosystem = st.selectbox(
            "Package Ecosystem",
            ["pypi", "npm", "go", "maven", "rubygems", "rust"],
            index=0,
        )

        package_filter = st.text_input(
            "Package Filter (optional)",
            placeholder="e.g., requests, django",
            help="Filter CVEs to specific packages",
        )

        submitted = st.form_submit_button("Start Scan", type="primary")

    if submitted:
        if not codebase_path:
            st.error("Please enter a codebase path")
            return

        path = Path(codebase_path)
        if not path.exists():
            st.error(f"Path does not exist: {codebase_path}")
            return

        # Start the scan
        try:
            with get_api_client() as client:
                response = client.post(
                    "/scan",
                    json={
                        "codebase_path": codebase_path,
                        "ecosystem": ecosystem,
                        "package_filter": package_filter or None,
                    },
                )

                if response.status_code == 200:
                    result = response.json()
                    st.success(f"Scan started! Job ID: {result['job_id']}")
                    st.session_state["current_job_id"] = result["job_id"]

                    # Show progress
                    show_scan_progress(result["job_id"])
                else:
                    st.error(f"Failed to start scan: {response.text}")

        except httpx.ConnectError:
            st.error("Cannot connect to API server")


def show_scan_progress(job_id: int):
    """Show scan progress."""
    progress_bar = st.progress(0)
    status_text = st.empty()

    with get_api_client() as client:
        while True:
            response = client.get(f"/scan/{job_id}")
            if response.status_code != 200:
                st.error("Failed to get scan status")
                break

            status = response.json()

            if status["status"] == "running":
                progress = 0
                if status["total_cves"] > 0:
                    progress = status["processed_cves"] / status["total_cves"]
                progress_bar.progress(progress)
                status_text.text(
                    f"Processing: {status['processed_cves']}/{status['total_cves']} CVEs"
                )

            elif status["status"] == "completed":
                progress_bar.progress(1.0)
                status_text.text("Scan completed!")
                st.success(
                    f"Scan complete! Found {status['affected_count']} affected CVEs "
                    f"out of {status['total_cves']} analyzed."
                )
                break

            elif status["status"] == "failed":
                st.error(f"Scan failed: {status['error_message']}")
                break

            time.sleep(1)


def show_cve_list():
    """Show the CVE list page."""
    st.header("CVE List")

    # Filters
    col1, col2, col3 = st.columns(3)

    with col1:
        severity_filter = st.selectbox(
            "Severity",
            ["All", "critical", "high", "medium", "low"],
            index=0,
        )

    with col2:
        limit = st.number_input("Results per page", min_value=10, max_value=200, value=50)

    with col3:
        offset = st.number_input("Offset", min_value=0, value=0, step=int(limit))

    # Fetch CVEs
    try:
        with get_api_client() as client:
            params = {"limit": limit, "offset": offset}
            if severity_filter != "All":
                params["severity"] = severity_filter

            response = client.get("/cves", params=params)

            if response.status_code == 200:
                cves = response.json()
            else:
                st.error("Failed to fetch CVEs")
                return

    except httpx.ConnectError:
        st.error("Cannot connect to API server")
        return

    if not cves:
        st.info("No CVEs found. Run a scan to populate the database.")
        return

    # Display CVEs
    for cve in cves:
        severity_color = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
        }.get(cve["severity"], "⚪")

        with st.expander(f"{severity_color} {cve['id']} - {cve['title'] or 'No title'}"):
            col1, col2 = st.columns([3, 1])

            with col1:
                st.markdown(f"**Description:** {cve['description'][:500]}...")
                st.markdown(f"**Affected Packages:** {', '.join(cve['affected_packages']) or 'N/A'}")

            with col2:
                st.metric("CVSS", cve["cvss_score"] or "N/A")
                st.caption(f"Source: {cve['source']}")
                if cve["source_url"]:
                    st.link_button("View Details", cve["source_url"])


def show_triage_results():
    """Show triage results page."""
    st.header("Triage Results")

    # Filters
    col1, col2, col3 = st.columns(3)

    with col1:
        status_filter = st.selectbox(
            "Status",
            ["All", "affected", "not_affected", "pending", "needs_review"],
            index=0,
        )

    with col2:
        affected_only = st.checkbox("Affected Only", value=False)

    with col3:
        limit = st.number_input("Results", min_value=10, max_value=200, value=50, key="triage_limit")

    # Fetch results
    try:
        with get_api_client() as client:
            params = {"limit": limit, "affected_only": affected_only}
            if status_filter != "All":
                params["status"] = status_filter

            response = client.get("/triage", params=params)

            if response.status_code == 200:
                results = response.json()
            else:
                st.error("Failed to fetch triage results")
                return

    except httpx.ConnectError:
        st.error("Cannot connect to API server")
        return

    if not results:
        st.info("No triage results found. Run a scan to generate results.")
        return

    # Display results
    for result in results:
        status_icon = {
            "affected": "⚠️",
            "not_affected": "✅",
            "pending": "⏳",
            "needs_review": "🔍",
        }.get(result["status"], "❓")

        with st.expander(
            f"{status_icon} {result['cve_id']} - "
            f"{'AFFECTED' if result['is_affected'] else 'Not Affected'} "
            f"(Confidence: {result['confidence']:.0%})"
        ):
            col1, col2 = st.columns([3, 1])

            with col1:
                st.markdown("**AI Analysis:**")
                st.markdown(result["reasoning"] or "No reasoning provided")

                if result["remediation"]:
                    st.markdown("**Remediation:**")
                    st.markdown(result["remediation"])

                if result["affected_files"]:
                    st.markdown("**Affected Files:**")
                    for f in result["affected_files"]:
                        st.code(f, language=None)

            with col2:
                st.metric("Priority", f"{result['priority_score']:.1f}/10")

                if result["owners"]:
                    st.markdown("**Owners:**")
                    for owner in result["owners"]:
                        st.caption(f"• {owner['identifier']}")

                # Override controls
                st.markdown("---")
                st.markdown("**Manual Override:**")

                with st.form(f"override_{result['id']}"):
                    new_status = st.radio(
                        "Status",
                        ["Affected", "Not Affected"],
                        index=0 if result["is_affected"] else 1,
                        key=f"status_{result['id']}",
                    )
                    reason = st.text_input("Reason", key=f"reason_{result['id']}")

                    if st.form_submit_button("Override"):
                        try:
                            with get_api_client() as client:
                                resp = client.post(
                                    f"/triage/{result['id']}/override",
                                    json={
                                        "is_affected": new_status == "Affected",
                                        "reason": reason,
                                    },
                                )
                                if resp.status_code == 200:
                                    st.success("Override saved!")
                                    st.rerun()
                                else:
                                    st.error("Failed to save override")
                        except httpx.ConnectError:
                            st.error("Cannot connect to API server")


if __name__ == "__main__":
    main()
