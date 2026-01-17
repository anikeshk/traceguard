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


def main() -> None:
    st.set_page_config(
        page_title="TraceGuard",
        page_icon="🛡️",
        layout="wide",
    )

    st.title("TraceGuard")
    st.subheader("Select repositories to monitor for security vulnerabilities")

    # Initialize session state for selected repos
    if "selected_repos" not in st.session_state:
        st.session_state.selected_repos = set()

    # Fetch repositories
    with st.spinner("Loading repositories..."):
        repos = fetch_repositories()

    if not repos:
        st.warning("No repositories found. Check your GitHub token configuration.")
        return

    st.write(f"Found {len(repos)} repositories")

    # Display repositories with checkboxes
    for repo in repos:
        full_name = repo["full_name"]
        description = repo.get("description") or "No description"
        visibility = repo["visibility"]

        col1, col2 = st.columns([3, 1])

        with col1:
            checked = st.checkbox(
                f"**{full_name}**",
                key=f"repo_{full_name}",
                value=full_name in st.session_state.selected_repos,
            )

            if checked:
                st.session_state.selected_repos.add(full_name)
            elif full_name in st.session_state.selected_repos:
                st.session_state.selected_repos.discard(full_name)

            st.caption(f"{description} • {visibility}")

        with col2:
            st.link_button("View on GitHub", repo["url"])

    # Show selected repositories
    st.divider()
    if st.session_state.selected_repos:
        st.subheader(f"Selected repositories ({len(st.session_state.selected_repos)})")
        for repo_name in sorted(st.session_state.selected_repos):
            st.write(f"- {repo_name}")
    else:
        st.info("No repositories selected. Select repositories above to monitor them.")


if __name__ == "__main__":
    main()
