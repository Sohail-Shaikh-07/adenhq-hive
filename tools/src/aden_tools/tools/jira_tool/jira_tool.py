"""
Jira Tool - Interact with Jira issues, projects, and comments.

Supports:
- Jira Cloud Authentication (Email + API Token)
- Issue Management (Create, Read, Update, Comment)
- JQL Search

API Reference: https://developer.atlassian.com/cloud/jira/platform/rest/v3/intro/
"""

from __future__ import annotations

import base64
import os
from typing import TYPE_CHECKING, Any

import httpx
from fastmcp import FastMCP

if TYPE_CHECKING:
    from aden_tools.credentials import CredentialStoreAdapter


def _sanitize_error_message(error: Exception) -> str:
    """
    Sanitize error messages to prevent token leaks.
    """
    error_str = str(error)
    # Remove any Basic Auth headers
    if "Authorization" in error_str or "Basic" in error_str:
        return "Network error occurred (credentials hidden)"
    return f"Network error: {error_str}"


class _JiraClient:
    """Internal client wrapping Jira REST API v3 calls."""

    def __init__(self, email: str, token: str, domain: str):
        self._email = email
        self._token = token
        # Ensure domain is a full URL
        if not domain.startswith("http"):
            domain = f"https://{domain}"
        # Remove trailing slash
        self._base_url = domain.rstrip("/")

        # Create Basic Auth header
        auth_str = f"{email}:{token}"
        auth_bytes = auth_str.encode("ascii")
        base64_auth = base64.b64encode(auth_bytes).decode("ascii")

        self._headers = {
            "Authorization": f"Basic {base64_auth}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _handle_response(self, response: httpx.Response) -> dict[str, Any]:
        """Handle Jira API response format."""
        if response.status_code == 401:
            return {
                "error": "Invalid or expired Jira credentials (check Email/API Token)"
            }
        if response.status_code == 403:
            return {"error": "Forbidden - check permissions or IP allowlist"}
        if response.status_code == 404:
            return {"error": "Resource not found (check Issue ID or URL)"}
        if response.status_code >= 400:
            try:
                # Jira error messages are usually in errorMessages or errors
                data = response.json()
                messages = data.get("errorMessages", [])
                errors = data.get("errors", {})
                detail = "; ".join(messages)
                if errors:
                    detail += " " + str(errors)
                if not detail:
                    detail = response.text
            except Exception:
                detail = response.text
            return {"error": f"Jira API error (HTTP {response.status_code}): {detail}"}

        try:
            if response.status_code == 204:
                return {"success": True}
            return response.json()
        except Exception:
            return {"success": True, "data": {}}

    def get_issue(self, issue_key: str) -> dict[str, Any]:
        """Get issue details."""
        url = f"{self._base_url}/rest/api/3/issue/{issue_key}"
        response = httpx.get(url, headers=self._headers, timeout=30.0)
        return self._handle_response(response)

    def search_issues(self, jql: str, max_results: int = 20) -> dict[str, Any]:
        """Search issues using JQL."""
        url = f"{self._base_url}/rest/api/3/search"
        params = {
            "jql": jql,
            "maxResults": min(max_results, 100),
            "fields": "summary,status,assignee,priority,created",
        }
        response = httpx.get(url, headers=self._headers, params=params, timeout=30.0)
        return self._handle_response(response)

    def create_issue(
        self,
        project_key: str,
        summary: str,
        description: str | None = None,
        issuetype: str = "Task",
    ) -> dict[str, Any]:
        """Create a new issue."""
        url = f"{self._base_url}/rest/api/3/issue"

        # Construct ADF (Atlassian Document Format) for description if valid
        # For simplicity, we fallback to simple string if complex ADF is needed later
        # But v3 requires ADF. We'll use a simple paragraph block.
        description_adf = None
        if description:
            description_adf = {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": description}],
                    }
                ],
            }

        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary,
                "issuetype": {"name": issuetype},
            }
        }
        if description_adf:
            payload["fields"]["description"] = description_adf

        response = httpx.post(url, headers=self._headers, json=payload, timeout=30.0)
        return self._handle_response(response)

    def add_comment(self, issue_key: str, comment: str) -> dict[str, Any]:
        """Add a comment to an issue."""
        url = f"{self._base_url}/rest/api/3/issue/{issue_key}/comment"

        # ADF for comment body
        body_adf = {
            "type": "doc",
            "version": 1,
            "content": [
                {"type": "paragraph", "content": [{"type": "text", "text": comment}]}
            ],
        }

        payload = {"body": body_adf}
        response = httpx.post(url, headers=self._headers, json=payload, timeout=30.0)
        return self._handle_response(response)

    def transition_issue(self, issue_key: str, transition_id: str) -> dict[str, Any]:
        """Transition an issue (e.g. To Do -> Done)."""
        url = f"{self._base_url}/rest/api/3/issue/{issue_key}/transitions"
        payload = {"transition": {"id": transition_id}}
        response = httpx.post(url, headers=self._headers, json=payload, timeout=30.0)
        return self._handle_response(response)

    def get_transitions(self, issue_key: str) -> dict[str, Any]:
        """Get available transitions for an issue."""
        url = f"{self._base_url}/rest/api/3/issue/{issue_key}/transitions"
        response = httpx.get(url, headers=self._headers, timeout=30.0)
        return self._handle_response(response)

    def find_users(self, query: str) -> dict[str, Any]:
        """Find users by name or email."""
        url = f"{self._base_url}/rest/api/3/user/search"
        params = {"query": query}
        response = httpx.get(url, headers=self._headers, params=params, timeout=30.0)
        return self._handle_response(response)

    def assign_issue(self, issue_key: str, account_id: str) -> dict[str, Any]:
        """Assign an issue to a user."""
        url = f"{self._base_url}/rest/api/3/issue/{issue_key}/assignee"
        payload = {"accountId": account_id}
        response = httpx.put(url, headers=self._headers, json=payload, timeout=30.0)
        return self._handle_response(response)

    def add_attachment(self, issue_key: str, file_path: str) -> dict[str, Any]:
        """Upload an attachment to an issue."""
        url = f"{self._base_url}/rest/api/3/issue/{issue_key}/attachments"

        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}

        # Jira requires this header for attachments to bypass XSRF checks
        headers = self._headers.copy()
        headers["X-Atlassian-Token"] = "no-check"
        # Remove Content-Type so httpx can set it to multipart/form-data with boundary
        headers.pop("Content-Type", None)

        try:
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                response = httpx.post(url, headers=headers, files=files, timeout=60.0)
            return self._handle_response(response)
        except Exception as e:
            return {"error": f"Failed to upload file: {str(e)}"}

    def get_attachment(self, attachment_id: str) -> dict[str, Any]:
        """Get attachment metadata."""
        url = f"{self._base_url}/rest/api/3/attachment/{attachment_id}"
        response = httpx.get(url, headers=self._headers, timeout=30.0)
        return self._handle_response(response)

    def get_all_boards(
        self, start_at: int = 0, max_results: int = 50
    ) -> dict[str, Any]:
        """Get all boards."""
        url = f"{self._base_url}/rest/agile/1.0/board"
        params = {"startAt": start_at, "maxResults": max_results}
        response = httpx.get(url, headers=self._headers, params=params, timeout=30.0)
        return self._handle_response(response)

    def get_sprints(self, board_id: int, state: str | None = None) -> dict[str, Any]:
        """Get sprints for a board."""
        url = f"{self._base_url}/rest/agile/1.0/board/{board_id}/sprint"
        params = {}
        if state:
            params["state"] = state  # active, future, closed
        response = httpx.get(url, headers=self._headers, params=params, timeout=30.0)
        return self._handle_response(response)

    def add_issue_to_sprint(
        self, sprint_id: int, issue_keys: list[str]
    ) -> dict[str, Any]:
        """Move issues to a sprint."""
        url = f"{self._base_url}/rest/agile/1.0/sprint/{sprint_id}/issue"
        payload = {"issues": issue_keys}
        response = httpx.post(url, headers=self._headers, json=payload, timeout=30.0)
        return self._handle_response(response)


def register_tools(
    mcp: FastMCP,
    credentials: CredentialStoreAdapter | None = None,
) -> None:
    """Register Jira tools with the MCP server."""

    # ... (Start of register_tools function remains the same, skipping to new tool definitions)

    # ... (existing MCP tools)

    @mcp.tool()
    def jira_get_all_boards() -> dict:
        """
        Get a list of all Agile boards.
        Use this to find board IDs for sprint planning.
        """
        client = _get_client()
        if isinstance(client, dict):
            return client
        try:
            return client.get_all_boards()
        except httpx.TimeoutException:
            return {"error": "Request timed out"}
        except httpx.RequestError as e:
            return {"error": _sanitize_error_message(e)}

    @mcp.tool()
    def jira_get_sprints(board_id: int, state: str = "active,future") -> dict:
        """
        Get sprints for a specific board.

        Args:
            board_id: The ID of the board (from jira_get_all_boards)
            state: Filter by state (e.g., "active", "future", "closed")
        """
        client = _get_client()
        if isinstance(client, dict):
            return client
        try:
            return client.get_sprints(board_id, state)
        except httpx.TimeoutException:
            return {"error": "Request timed out"}
        except httpx.RequestError as e:
            return {"error": _sanitize_error_message(e)}

    @mcp.tool()
    def jira_add_issue_to_sprint(sprint_id: int, issue_key: str) -> dict:
        """
        Move an issue into a sprint.

        Args:
            sprint_id: The ID of the sprint (from jira_get_sprints)
            issue_key: The issue key (e.g., "PROJ-123")
        """
        client = _get_client()
        if isinstance(client, dict):
            return client
        try:
            # We wrap the single issue key in a list as our client expects a list
            return client.add_issue_to_sprint(sprint_id, [issue_key])
        except httpx.TimeoutException:
            return {"error": "Request timed out"}
        except httpx.RequestError as e:
            return {"error": _sanitize_error_message(e)}

    # ... (Start of register_tools function remains the same, skipping to new tool definitions)

    # ... (existing MCP tools)

    @mcp.tool()
    def jira_assign_issue(issue_key: str, account_id: str) -> dict:
        """
        Assign an issue to a user.

        Args:
            issue_key: The issue key (e.g., "PROJ-123")
            account_id: The Jira accountId of the user (get this from jira_find_user)
        """
        client = _get_client()
        if isinstance(client, dict):
            return client
        try:
            return client.assign_issue(issue_key, account_id)
        except httpx.TimeoutException:
            return {"error": "Request timed out"}
        except httpx.RequestError as e:
            return {"error": _sanitize_error_message(e)}

    @mcp.tool()
    def jira_add_attachment(issue_key: str, file_path: str) -> dict:
        """
        Upload a file attachment to a Jira issue.

        Args:
            issue_key: The issue key (e.g., "PROJ-123")
            file_path: Absolute path to the file to upload
        """
        client = _get_client()
        if isinstance(client, dict):
            return client
        try:
            return client.add_attachment(issue_key, file_path)
        except httpx.TimeoutException:
            return {"error": "Request timed out"}
        except httpx.RequestError as e:
            return {"error": _sanitize_error_message(e)}

    @mcp.tool()
    def jira_get_attachment(attachment_id: str) -> dict:
        """
        Get metadata for a specific attachment.
        Note: Content download is not yet supported in this version.

        Args:
            attachment_id: The ID of the attachment
        """
        client = _get_client()
        if isinstance(client, dict):
            return client
        try:
            return client.get_attachment(attachment_id)
        except httpx.TimeoutException:
            return {"error": "Request timed out"}
        except httpx.RequestError as e:
            return {"error": _sanitize_error_message(e)}

    def _get_client() -> _JiraClient | dict[str, str]:
        """Get authenticated Jira client."""
        # 1. Try Credential Store
        if credentials:
            email = credentials.get("jira_email")
            token = credentials.get("jira_token")
            domain = credentials.get("jira_domain")  # e.g. "myco.atlassian.net"
        else:
            email = None
            token = None
            domain = None

        # 2. Fallback to Env Vars
        if not email:
            email = os.getenv("JIRA_EMAIL")
        if not token:
            token = os.getenv("JIRA_API_TOKEN")
        if not domain:
            domain = os.getenv("JIRA_DOMAIN")

        if not (email and token and domain):
            return {
                "error": "Jira credentials not configured",
                "help": (
                    "Set JIRA_EMAIL, JIRA_API_TOKEN, and JIRA_DOMAIN environment variables "
                    "or configure via credential store."
                ),
            }

        return _JiraClient(email, token, domain)

    @mcp.tool()
    def jira_get_issue(issue_key: str) -> dict:
        """
        Get details of a Jira issue.

        Args:
            issue_key: The issue key (e.g., "PROJ-123")
        """
        client = _get_client()
        if isinstance(client, dict):
            return client
        try:
            return client.get_issue(issue_key)
        except httpx.TimeoutException:
            return {"error": "Request timed out"}
        except httpx.RequestError as e:
            return {"error": _sanitize_error_message(e)}

    @mcp.tool()
    def jira_search_issues(jql: str, max_results: int = 10) -> dict:
        """
        Search for issues using JQL (Jira Query Language).

        Args:
            jql: The JQL query string (e.g. "project = PROJ AND status = 'To Do'")
            max_results: Max number of issues to return (default 10)
        """
        client = _get_client()
        if isinstance(client, dict):
            return client
        try:
            return client.search_issues(jql, max_results)
        except httpx.TimeoutException:
            return {"error": "Request timed out"}
        except httpx.RequestError as e:
            return {"error": _sanitize_error_message(e)}

    @mcp.tool()
    def jira_create_issue(
        project_key: str,
        summary: str,
        description: str | None = None,
        issuetype: str = "Task",
    ) -> dict:
        """
        Create a new Jira issue.

        Args:
            project_key: The project key (e.g., "PROJ")
            summary: Brief summary of the issue
            description: Detailed description
            issuetype: Type of issue (Task, Bug, Story, etc.)
        """
        client = _get_client()
        if isinstance(client, dict):
            return client
        try:
            return client.create_issue(project_key, summary, description, issuetype)
        except httpx.TimeoutException:
            return {"error": "Request timed out"}
        except httpx.RequestError as e:
            return {"error": _sanitize_error_message(e)}

    @mcp.tool()
    def jira_add_comment(issue_key: str, comment: str) -> dict:
        """
        Add a comment to a Jira issue.

        Args:
            issue_key: The issue key (e.g., "PROJ-123")
            comment: The comment text
        """
        client = _get_client()
        if isinstance(client, dict):
            return client
        try:
            return client.add_comment(issue_key, comment)
        except httpx.TimeoutException:
            return {"error": "Request timed out"}
        except httpx.RequestError as e:
            return {"error": _sanitize_error_message(e)}

    @mcp.tool()
    def jira_get_transitions(issue_key: str) -> dict:
        """
        Get available status transitions for an issue.
        Use this to find the ID needed for jira_transition_issue.

        Args:
            issue_key: The issue key (e.g., "PROJ-123")
        """
        client = _get_client()
        if isinstance(client, dict):
            return client
        try:
            return client.get_transitions(issue_key)
        except httpx.TimeoutException:
            return {"error": "Request timed out"}
        except httpx.RequestError as e:
            return {"error": _sanitize_error_message(e)}

    @mcp.tool()
    def jira_transition_issue(issue_key: str, transition_id: str) -> dict:
        """
        Move an issue to a different status (e.g. To Do -> Done).

        Args:
            issue_key: The issue key (e.g., "PROJ-123")
            transition_id: The ID of the transition (get this from jira_get_transitions)
        """
        client = _get_client()
        if isinstance(client, dict):
            return client
        try:
            return client.transition_issue(issue_key, transition_id)
        except httpx.TimeoutException:
            return {"error": "Request timed out"}
        except httpx.RequestError as e:
            return {"error": _sanitize_error_message(e)}

    @mcp.tool()
    def jira_find_user(query: str) -> dict:
        """
        Find a Jira user by name or email.
        Use this to get the 'accountId' needed for assignment.

        Args:
            query: Name or email address to search for
        """
        client = _get_client()
        if isinstance(client, dict):
            return client
        try:
            return client.find_users(query)
        except httpx.TimeoutException:
            return {"error": "Request timed out"}
        except httpx.RequestError as e:
            return {"error": _sanitize_error_message(e)}
