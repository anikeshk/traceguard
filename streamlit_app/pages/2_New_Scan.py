"""New Scan page for creating CVE analysis jobs."""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st
import os
from api_client import get_api_client

st.set_page_config(
    page_title="New Scan - TraceGuard",
    page_icon="➕",
    layout="wide",
)

st.title("➕ New Scan")
st.markdown("Start a new CVE analysis against your codebase.")


def get_client():
    return get_api_client()


# Check API connectivity
try:
    client = get_client()
    client.health_check()
except Exception as e:
    st.error(f"Cannot connect to API: {e}")
    st.info("Make sure the FastAPI server is running on http://localhost:8000")
    st.stop()

# Form for creating a new scan
st.markdown("### Scan Configuration")

with st.form("new_scan_form"):
    # Codebase path input
    codebase_path = st.text_input(
        "Codebase Path",
        placeholder="/path/to/your/codebase",
        help="Enter the absolute path to the codebase you want to scan",
    )

    # Validate path exists
    path_valid = False
    if codebase_path:
        if os.path.exists(codebase_path):
            st.success(f"✓ Path exists: {codebase_path}")
            path_valid = True
        else:
            st.error(f"✗ Path does not exist: {codebase_path}")

    st.markdown("---")

    # CVE IDs input
    st.markdown("### CVE IDs to Analyze")
    st.markdown("Enter one CVE ID per line (e.g., CVE-2021-44228)")

    cve_input = st.text_area(
        "CVE IDs",
        placeholder="CVE-2021-44228\nCVE-2022-22965\nGHSA-xxxx-xxxx-xxxx",
        height=150,
        help="Enter CVE IDs or GHSA IDs, one per line",
    )

    # Parse CVE IDs
    cve_ids = []
    if cve_input:
        lines = cve_input.strip().split("\n")
        for line in lines:
            cve_id = line.strip()
            if cve_id:
                cve_ids.append(cve_id)

    if cve_ids:
        st.info(f"Will analyze {len(cve_ids)} CVE(s): {', '.join(cve_ids)}")

    st.markdown("---")

    # Submit button
    submitted = st.form_submit_button("🚀 Start Scan", type="primary")

if submitted:
    if not codebase_path:
        st.error("Please enter a codebase path")
    elif not path_valid:
        st.error("Please enter a valid codebase path")
    elif not cve_ids:
        st.error("Please enter at least one CVE ID")
    else:
        try:
            with st.spinner("Creating scan job..."):
                result = client.create_job(
                    codebase_path=codebase_path,
                    cve_ids=cve_ids,
                )

            job_id = result.get("job_id")
            st.success(f"✓ Scan job #{job_id} created successfully!")
            st.info("The scan is running in the background. Click below to view progress.")

            # Store job ID and redirect
            st.session_state["selected_job_id"] = job_id

            if st.button("View Job Details"):
                st.switch_page("pages/3_Job_Details.py")

        except Exception as e:
            st.error(f"Error creating scan: {e}")

# Help section
st.markdown("---")
st.markdown("### Help")

with st.expander("What is a CVE?"):
    st.markdown("""
    A **CVE (Common Vulnerabilities and Exposures)** is a unique identifier for a publicly known security vulnerability.

    Examples:
    - `CVE-2021-44228` - Log4Shell vulnerability
    - `CVE-2022-22965` - Spring4Shell vulnerability

    You can also use **GHSA IDs** (GitHub Security Advisory IDs) like `GHSA-xxxx-xxxx-xxxx`.
    """)

with st.expander("How does TraceGuard work?"):
    st.markdown("""
    TraceGuard performs the following steps:

    1. **CVE Context Collection**: Fetches vulnerability details from OSV and GitHub
    2. **Dependency Usage Detection**: Scans your codebase for affected package usage
    3. **Ownership Resolution**: Maps affected files to owners using CODEOWNERS
    4. **Ticket Generation**: Creates a ready-to-use GitHub issue

    If the affected package is not used in your codebase, the CVE is marked as **Not Applicable**.
    """)

with st.expander("What ecosystems are supported?"):
    st.markdown("""
    Currently supported ecosystems:
    - **npm** (JavaScript/TypeScript)

    Support for Python (pip), Go, and other ecosystems is planned.
    """)

# Back button
st.markdown("---")
if st.button("← Back to Dashboard"):
    st.switch_page("pages/1_Dashboard.py")
