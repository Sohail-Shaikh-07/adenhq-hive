# Jira Tool

Interact with the Jira Cloud REST API (v3).

## Requirements

- **Jira Cloud Account** (Free tier works)
- **API Token**: Generated from [Atlassian Security Settings](https://id.atlassian.com/manage-profile/security/api-tokens).
- **Email**: The email address associated with your Atlassian account.

## Configuration

Set the following environment variables or use the Credential Store:

```bash
export JIRA_EMAIL="your-email@example.com"
export JIRA_API_TOKEN="your-api-token"
export JIRA_DOMAIN="https://your-domain.atlassian.net"
```

## Available Tools

- `jira_get_issue(issue_key)`: Get details of an issue.
- `jira_search_issues(jql)`: Search using JQL.
- `jira_create_issue(project_key, summary, description)`: Create a new Task.
- `jira_add_comment(issue_key, comment)`: Add a comment.
- `jira_transition_issue(issue_key, transition_id)`: Change status (e.g., To Do -> Done).
- `jira_get_transitions(issue_key)`: List available status options.
- `jira_find_user(query)`: Find a user by name or email.
- `jira_assign_issue(issue_key, account_id)`: Assign an issue.
- `jira_add_attachment(issue_key, file_path)`: Upload a file (log, screenshot).
- `jira_get_attachment(attachment_id)`: Get attachment metadata.
- `jira_get_all_boards()`: List Agile boards.
- `jira_get_sprints(board_id)`: List sprints for a board.
- `jira_add_issue_to_sprint(sprint_id, issue_key)`: Move an issue into a sprint.
- `jira_get_components(project_key)`: List project components.
- `jira_set_component(issue_key, component_id)`: Set component for an issue.
- `jira_create_version(project_key, name)`: Create a new release version.
