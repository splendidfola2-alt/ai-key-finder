import re

from scanner import (
    is_placeholder_secret,
    is_excluded_path,
    score_secret,
)


def test_placeholder_examples_are_rejected():
    assert is_placeholder_secret('demo') is True
    assert is_placeholder_secret('your_api_key') is True
    assert is_placeholder_secret('sk-test-12345') is True
    assert is_placeholder_secret('api03') is True
    assert is_placeholder_secret('OPENAI_API_KEY=demo') is True


def test_docs_and_examples_are_excluded():
    assert is_excluded_path('README.md') is True
    assert is_excluded_path('docs/setup.md') is True
    assert is_excluded_path('examples/sample.env') is True
    assert is_excluded_path('js/help-system.js') is True
    assert is_excluded_path('src/app.py') is False


def test_valid_openai_project_key_is_accepted():
    secret = 'sk-proj-' + 'A' * 60
    result = score_secret(secret, 'OPENAI_API_KEY', 'src/.env')
    assert result is not None
    provider, confidence = result
    assert provider == 'openai-proj'
    assert confidence >= 60


def test_placeholder_env_value_is_rejected():
    result = score_secret('demo', 'OPENAI_API_KEY', 'src/.env')
    assert result is None


def test_openai_key_in_docs_is_rejected():
    secret = 'sk-proj-' + 'A' * 60
    result = score_secret(secret, 'OPENAI_API_KEY', 'docs/usage.md')
    assert result is None


def test_valid_gemini_key_is_accepted():
    secret = 'AIza' + 'A' * 39
    result = score_secret(secret, 'GEMINI_API_KEY', 'config/app.env')
    assert result is not None
    provider, confidence = result
    assert provider == 'gemini'
    assert confidence >= 60


def test_valid_anthropic_key_is_accepted():
    secret = 'sk-ant-' + 'B' * 90
    result = score_secret(secret, 'ANTHROPIC_API_KEY', '.env.production')
    assert result is not None
    provider, confidence = result
    assert provider == 'anthropic'
    assert confidence >= 60


def test_keys_outside_provider_length_bounds_are_rejected():
    long_secret = 'sk-ant-' + 'X' * 500
    result = score_secret(long_secret, 'ANTHROPIC_API_KEY', 'src/.env')
    assert result is None

    short_secret = 'sk-proj-' + 'A' * 10
    result = score_secret(short_secret, 'OPENAI_API_KEY', 'src/.env')
    assert result is None
