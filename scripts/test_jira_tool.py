"""
Test script for Jira Tool.

Prerequisites:
- Set JIRA_EMAIL, JIRA_API_TOKEN, JIRA_DOMAIN, and JIRA_PROJECT_KEY env vars.
"""

import os
import sys
from aden_tools.tools.jira_tool.jira_tool import _JiraClient


def main():
    email = os.getenv("JIRA_EMAIL")
    token = os.getenv("JIRA_API_TOKEN")
    domain = os.getenv("JIRA_DOMAIN")
    project = os.getenv("JIRA_PROJECT_KEY", "TEST")  # Default to TEST project

    if not (email and token and domain):
        print("Error: Missing JIRA credentials in environment.")
        print("Please set JIRA_EMAIL, JIRA_API_TOKEN, JIRA_DOMAIN")
        sys.exit(1)

    print(f"Connecting to Jira: {domain} as {email}...")
    client = _JiraClient(email, token, domain)

    # 1. Create Issue
    print(f"\n[1] Creating test issue in project {project}...")
    issue = client.create_issue(
        project_key=project,
        summary="Test Issue from Hive Agent",
        description="This is an automated test issue created by the Jira Tool.",
        issuetype="Task",
    )
    if "error" in issue:
        print(f"Failed to create issue: {issue['error']}")
        sys.exit(1)

    key = issue["key"]
    print(f"✅ Created issue: {key} (ID: {issue['id']})")
    print(f"View at: {domain}/browse/{key}")

    # 2. Add Comment
    print(f"\n[2] Adding comment to {key}...")
    comment = client.add_comment(key, "This is a test comment from the script.")
    if "error" in comment:
        print(f"Failed to add comment: {comment['error']}")
    else:
        print("✅ Comment added.")

    # 3. Find User (Self)
    print(f"\n[3] Searching for user '{email}'...")
    users = client.find_users(email)
    if "error" in users:
        print(f"Failed to search users: {users['error']}")
    elif isinstance(users, list) and len(users) > 0:
        myself = users[0]
        account_id = myself["accountId"]
        print(f"✅ Found user: {myself['displayName']} ({account_id})")

        # 4. Assign Issue
        print(f"\n[4] Assigning {key} to {myself['displayName']}...")
        assign = client.assign_issue(key, account_id)
        if "error" in assign:
            print(f"Failed to assign: {assign['error']}")
        else:
            print("✅ Issue assigned successfully.")
    else:
        print("⚠️ User not found, skipping assignment test.")

    # 5. Get Transitions
    print(f"\n[5] Getting transitions for {key}...")
    transitions = client.get_transitions(key)
    if "error" in transitions:
        print(f"Failed to get transitions: {transitions['error']}")
    else:
        t_list = transitions.get("transitions", [])
        print(
            f"✅ Available transitions: {[t['name'] + ' (ID: ' + t['id'] + ')' for t in t_list]}"
        )

    print("\n✅ Test Complete!")


if __name__ == "__main__":
    main()
