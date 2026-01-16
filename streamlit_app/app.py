"""TraceGuard Streamlit Dashboard - Main Entry Point."""

import streamlit as st

st.set_page_config(
    page_title="TraceGuard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        color: #666;
        font-size: 1.1rem;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        border-radius: 10px;
        padding: 1rem;
        text-align: center;
    }
    .status-running {
        color: #ffa500;
    }
    .status-completed {
        color: #00cc00;
    }
    .status-failed {
        color: #ff0000;
    }
    .status-pending {
        color: #808080;
    }
</style>
""", unsafe_allow_html=True)

# Main header
st.markdown('<p class="main-header">🛡️ TraceGuard</p>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">CVE Triage & Ownership Automation</p>', unsafe_allow_html=True)

# Sidebar navigation
st.sidebar.title("Navigation")
st.sidebar.markdown("---")

# Links to pages
st.sidebar.page_link("pages/1_Dashboard.py", label="📊 Dashboard", icon="📊")
st.sidebar.page_link("pages/2_New_Scan.py", label="➕ New Scan", icon="➕")

st.sidebar.markdown("---")
st.sidebar.markdown("### About")
st.sidebar.markdown("""
TraceGuard analyzes CVEs against your codebase to determine vulnerability applicability using AI-powered analysis.
""")

# Main content - redirect to Dashboard
st.markdown("### Welcome to TraceGuard")
st.markdown("""
Use the sidebar to navigate:
- **Dashboard**: View scan statistics and job history
- **New Scan**: Start a new CVE analysis

Or click a job from the dashboard to view detailed results.
""")

# Quick stats preview
st.markdown("---")
st.markdown("### Quick Start")

col1, col2 = st.columns(2)

with col1:
    st.info("""
    **To scan for vulnerabilities:**
    1. Go to **New Scan**
    2. Enter your codebase path
    3. Add CVE IDs to analyze
    4. Click **Start Scan**
    """)

with col2:
    st.info("""
    **What TraceGuard does:**
    - Fetches CVE details from OSV & GitHub
    - Scans your code for package usage
    - Resolves ownership from CODEOWNERS
    - Generates GitHub issues
    """)
