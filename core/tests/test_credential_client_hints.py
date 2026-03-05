"""Tests for client-aware credential guidance messaging."""

from framework.credentials.client_hints import (
    detect_client_environment,
    get_credential_fix_guidance_lines,
)
from framework.credentials.validation import CredentialStatus, CredentialValidationResult


def _clear_client_env(monkeypatch) -> None:
    monkeypatch.delenv("HIVE_CLIENT", raising=False)


def _build_missing_result(env_var: str) -> CredentialValidationResult:
    status = CredentialStatus(
        credential_name="test_credential",
        credential_id="test_credential",
        env_var=env_var,
        description="",
        help_url="",
        api_key_instructions="",
        tools=["llm_generate"],
        node_types=[],
        available=False,
        valid=None,
        validation_message=None,
        aden_supported=False,
        direct_api_key_supported=True,
        credential_key="api_key",
        aden_not_connected=False,
    )
    return CredentialValidationResult(credentials=[status], has_aden_key=False)


def test_detect_client_environment_defaults_to_generic(monkeypatch):
    _clear_client_env(monkeypatch)
    assert detect_client_environment() == "generic"


def test_detect_client_environment_honors_override(monkeypatch):
    _clear_client_env(monkeypatch)
    monkeypatch.setenv("HIVE_CLIENT", "codex")
    assert detect_client_environment() == "codex"


def test_detect_client_environment_supports_antigravity_alias(monkeypatch):
    _clear_client_env(monkeypatch)
    monkeypatch.setenv("HIVE_CLIENT", "gemini")
    assert detect_client_environment() == "antigravity"


def test_guidance_is_generic_when_client_unknown(monkeypatch):
    _clear_client_env(monkeypatch)

    guidance = "\n".join(get_credential_fix_guidance_lines())
    assert "Claude Code" not in guidance
    assert "/hive-credentials" not in guidance
    assert "set the missing environment variables" in guidance


def test_guidance_includes_skill_hint_for_known_client(monkeypatch):
    _clear_client_env(monkeypatch)
    monkeypatch.setenv("HIVE_CLIENT", "cursor")

    guidance = "\n".join(get_credential_fix_guidance_lines())
    assert "/hive-credentials" in guidance


def test_format_error_message_is_client_agnostic_by_default(monkeypatch):
    _clear_client_env(monkeypatch)

    message = _build_missing_result("OPENAI_API_KEY").format_error_message()
    assert "Claude Code" not in message
    assert "/hive-credentials" not in message
    assert "OPENAI_API_KEY" in message


def test_format_error_message_can_include_skill_hint(monkeypatch):
    _clear_client_env(monkeypatch)
    monkeypatch.setenv("HIVE_CLIENT", "claude")

    message = _build_missing_result("ANTHROPIC_API_KEY").format_error_message()
    assert "/hive-credentials" in message
