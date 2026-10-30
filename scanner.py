#!/usr/bin/env python3
"""
High-confidence AI API Key Exposure Scanner

This version is intentionally conservative and optimized for a POC:
- it does NOT download full repo tarballs
- it scans only the files returned by the GitHub search results
- it validates the provider-specific key pattern before reporting
- it excludes docs/examples/tests and rejects placeholders/demo values
- it applies strict provider-specific length checks and suspicious pattern guards
"""

import os
import re
import json
import base64
import time
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, asdict

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


PLACEHOLDER_TOKENS = (
    'demo', 'example', 'sample', 'placeholder', 'replace_me', 'your_api_key',
    'your_key', 'changeme', 'dummy', 'fake', 'test', 'testing', 'sample_key',
    'sk-test', 'sk-example', 'sk-demo', 'api_key', 'apikey', 'api03', 'api04', 'api05',
    'mock', 'mock_key', 'mock_api', 'your-key', 'secret-key', 'token-key'
)

NEGATIVE_VALUE_PATTERNS = (
    r'(?i)(demo|example|sample|placeholder|test|fake|dummy|changeme|mock|api03|api04|api05|replace_me)'
)

EXCLUDED_PATH_PATTERNS = (
    '/docs/', '/doc/', '/examples/', '/example/', '/tests/', '/test/',
    '/fixtures/', '/samples/', '/sample/', '/mock/', '/mocks/', '/templates/',
    '/help/', '/helpers/', '/demo/', '/sandbox/', '/examples/', '/docs/',
    '.env.example', '.example', '.sample', '.template', 'README',
)

PROVIDER_RULES = {
    'openai-proj': {
        'regex': re.compile(r'^sk-proj-[A-Za-z0-9_-]{48,}$'),
        'min_length': 48,
        'max_length': 256,
    },
    'openai-legacy': {
        'regex': re.compile(r'^sk-[A-Za-z0-9]{48,}$'),
        'min_length': 48,
        'max_length': 256,
    },
    'anthropic': {
        'regex': re.compile(r'^sk-ant-[A-Za-z0-9_-]{80,}$'),
        'min_length': 80,
        'max_length': 256,
    },
    'gemini': {
        'regex': re.compile(r'^AIza[0-9A-Za-z\-_]{35}$'),
        'min_length': 39,
        'max_length': 100,
    },
    'groq': {
        'regex': re.compile(r'^gsk_[A-Za-z0-9_-]{20,}$'),
        'min_length': 20,
        'max_length': 128,
    },
    'huggingface': {
        'regex': re.compile(r'^(?:hf_[A-Za-z0-9_\-]{20,}|huggingfacehub_[A-Za-z0-9_\-]{20,})$'),
        'min_length': 20,
        'max_length': 256,
    },
    'deepseek': {
        'regex': re.compile(r'^sk-[A-Za-z0-9_-]{20,}$'),
        'min_length': 20,
        'max_length': 256,
    },
    'azure-openai': {
        'regex': re.compile(r'^[A-Za-z0-9._-]{30,}$'),
        'min_length': 30,
        'max_length': 200,
    },
    'mistral': {
        'regex': re.compile(r'^[A-Za-z0-9_-]{32,}$'),
        'min_length': 32,
        'max_length': 256,
    },
    'perplexity': {
        'regex': re.compile(r'^[A-Za-z0-9_-]{32,}$'),
        'min_length': 32,
        'max_length': 256,
    },
}

ENV_KEY_PATTERNS = [
    re.compile(r'(?i)\b(OPENAI_API_KEY|CODEX_API_KEY|CHATGPT_API_KEY|GPT_API_KEY|GPT3_API_KEY|GPT4_API_KEY|GPT35_API_KEY|DALLE_API_KEY|AI_API_KEY|LLM_API_KEY|LANGUAGE_MODEL_API_KEY)\b\s*(?:=|:)\s*["\'`]?([A-Za-z0-9_\-]+)["\'`]?'),
    re.compile(r'(?i)\b(ANTHROPIC_API_KEY|CLAUDE_API_KEY)\b\s*(?:=|:)\s*["\'`]?([A-Za-z0-9_\-]+)["\'`]?'),
    re.compile(r'(?i)\b(GEMINI_API_KEY|GOOGLE_API_KEY|GOOGLE_CREDENTIALS)\b\s*(?:=|:)\s*["\'`]?([A-Za-z0-9_\-]+)["\'`]?'),
    re.compile(r'(?i)\b(GROQ_API_KEY)\b\s*(?:=|:)\s*["\'`]?([A-Za-z0-9_\-]+)["\'`]?'),
    re.compile(r'(?i)\b(HUGGINGFACE_API_KEY|HF_API_KEY)\b\s*(?:=|:)\s*["\'`]?([A-Za-z0-9_\-]+)["\'`]?'),
    re.compile(r'(?i)\b(DEEPSEEK_API_KEY)\b\s*(?:=|:)\s*["\'`]?([A-Za-z0-9_\-]+)["\'`]?'),
    re.compile(r'(?i)\b(AZURE_OPENAI_API_KEY)\b\s*(?:=|:)\s*["\'`]?([A-Za-z0-9_\-]+)["\'`]?'),
    re.compile(r'(?i)\b(MISTRAL_API_KEY|PERPLEXITY_API_KEY|PPLX_API_KEY)\b\s*(?:=|:)\s*["\'`]?([A-Za-z0-9_\-]+)["\'`]?'),
]

RAW_KEY_PATTERN = re.compile(
    r'(?i)(?<![A-Za-z0-9_-])('
    r'sk-proj-[A-Za-z0-9_-]{48,}'
    r'|sk-ant-[A-Za-z0-9_-]{80,}'
    r'|gsk_[A-Za-z0-9_-]{20,}'
    r'|AIza[0-9A-Za-z\-_]{35}'
    r'|hf_[A-Za-z0-9_\-]{20,}'
    r'|huggingfacehub_[A-Za-z0-9_\-]{20,}'
    r')(?!(?:[A-Za-z0-9_-]))'
)


def normalize_secret_value(value: str) -> str:
    if not value:
        return ''
    cleaned = value.strip().strip('"\'`')
    return cleaned.rstrip(';').rstrip(',').strip()


def has_repeated_pattern(value: str) -> bool:
    if not value:
        return True
    if re.fullmatch(r'(.)\1{8,}', value):
        return True
    if re.fullmatch(r'([A-Za-z0-9])\1{12,}', value):
        return True
    if re.search(r'(?:[A-Za-z0-9])\1{5,}', value):
        return True
    return False


def is_placeholder_secret(value: str) -> bool:
    val = value.lower()
    if not val:
        return True
    if any(token in val for token in PLACEHOLDER_TOKENS):
        return True
    if re.search(NEGATIVE_VALUE_PATTERNS[0], val):
        return True
    if has_repeated_pattern(val):
        return True
    if re.search(r'(?i)(?:^|[^A-Za-z])(demo|temp|sample|test|mock|fake|dummy|placeholder)(?:$|[^A-Za-z])', val):
        return True
    return False


def is_excluded_path(file_path: str) -> bool:
    lower = (file_path or '').lower()
    for token in EXCLUDED_PATH_PATTERNS:
        if token.lower() in lower:
            return True
    if lower.endswith(('.env.example', '.sample', '.template')):
        return True
    if re.search(r'(?i)(/help/|/demo/|/sample/|/examples/|/tests/|/mock/|/fixtures/|/sandbox/)', lower):
        return True
    return False


def detect_provider(secret: str, env_var_name: Optional[str] = None) -> Optional[str]:
    value = normalize_secret_value(secret)
    if not value:
        return None

    upper_name = (env_var_name or '').upper()

    if any(v in upper_name for v in ('OPENAI', 'CODEX', 'CHATGPT', 'GPT', 'DALLE')):
        if value.startswith('sk-proj-'):
            return 'openai-proj'
        if value.startswith('sk-') and len(value) >= 48:
            return 'openai-legacy'

    if 'ANTHROPIC' in upper_name or value.startswith('sk-ant-'):
        return 'anthropic'

    if any(v in upper_name for v in ('GEMINI', 'GOOGLE')) or value.startswith('AIza'):
        return 'gemini'

    if 'GROQ' in upper_name or value.startswith('gsk_'):
        return 'groq'

    if any(v in upper_name for v in ('HUGGINGFACE', 'HF_')) or value.startswith('hf_') or value.startswith('huggingfacehub_'):
        return 'huggingface'

    if 'DEEPSEEK' in upper_name or (value.startswith('sk-') and len(value) >= 20):
        return 'deepseek'

    if 'AZURE' in upper_name:
        return 'azure-openai'

    if value.startswith('sk-proj-'):
        return 'openai-proj'
    if value.startswith('sk-ant-'):
        return 'anthropic'
    if value.startswith('gsk_'):
        return 'groq'
    if value.startswith('hf_') or value.startswith('huggingfacehub_'):
        return 'huggingface'
    if value.startswith('AIza'):
        return 'gemini'
    if value.startswith('sk-') and len(value) >= 48:
        return 'openai-legacy'
    if value.startswith('sk-') and len(value) >= 20:
        return 'deepseek'

    return None


def validate_secret_format(secret: str, provider: Optional[str]) -> bool:
    if not provider:
        return False

    value = normalize_secret_value(secret)
    if not value:
        return False
    if is_placeholder_secret(value):
        return False
    if has_repeated_pattern(value):
        return False

    rules = PROVIDER_RULES.get(provider)
    if not rules:
        return False
    if len(value) < rules['min_length'] or len(value) > rules['max_length']:
        return False

    return bool(rules['regex'].fullmatch(value))


def score_secret(value: str, env_var_name: Optional[str], file_path: str) -> Optional[Tuple[str, int]]:
    secret = normalize_secret_value(value)
    if not secret or is_placeholder_secret(secret):
        return None
    if is_excluded_path(file_path):
        return None

    provider = detect_provider(secret, env_var_name)
    if provider is None:
        return None
    if not validate_secret_format(secret, provider):
        return None

    score = 25 if env_var_name else 0
    score += 30
    score += min(len(secret) // 10, 20)
    score += 10 if secret.startswith(('sk-proj-', 'sk-ant-', 'gsk_', 'hf_', 'huggingfacehub_', 'AIza')) else 0
    score += 15 if file_path and not is_excluded_path(file_path) else 0

    return provider, score


@dataclass
class ExposedKeyFinding:
    repository: str
    file_path: str
    file_url: str
    commit_sha: Optional[str]
    discovered_at: str
    key_type: str
    key_preview: str
    confidence: int = 0


class GitHubScanner:
    """Scanner for finding exposed AI API keys on GitHub."""

    RATE_LIMIT_DELAY = 3
    JITTER_RANGE = (0, 1)
    MAX_REQUESTS_PER_SCAN = 10
    MAX_PAGES = 1

    def __init__(self, token: str):
        self.token = token
        self.session = self._create_session()
        self.findings: List[ExposedKeyFinding] = []
        self.requests_made = 0
        self.analyzed_files: Set[str] = set()
        self._budget_warning_shown = False

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'AIKeyFinder/1.0'
        })

        retry_strategy = Retry(
            total=2,
            backoff_factor=3,
            status_forcelist=[429, 500, 502, 503, 504],
            respect_retry_after_header=True,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount('https://', adapter)
        session.mount('http://', adapter)
        return session

    def _wait_if_needed(self):
        jitter = random.uniform(*self.JITTER_RANGE)
        time.sleep(self.RATE_LIMIT_DELAY + jitter)

    def _check_budget(self) -> bool:
        if self.requests_made >= self.MAX_REQUESTS_PER_SCAN:
            if not self._budget_warning_shown:
                print(f'  ⚠️ Request budget exhausted ({self.MAX_REQUESTS_PER_SCAN})')
                self._budget_warning_shown = True
            return False
        return True

    def _scan_text_for_findings(self, content: str, file_path: str, repo_name: str, file_url: str, commit_sha: Optional[str]) -> List[ExposedKeyFinding]:
        findings: List[ExposedKeyFinding] = []
        seen: Set[Tuple[str, str, str]] = set()

        for pattern in ENV_KEY_PATTERNS:
            for match in pattern.finditer(content):
                var_name = match.group(1).upper()
                secret = normalize_secret_value(match.group(2))
                result = score_secret(secret, var_name, file_path)
                if result is None:
                    continue

                provider, confidence = result
                if confidence < 60:
                    continue

                key_id = (file_path, provider, secret[:24])
                if key_id in seen:
                    continue
                seen.add(key_id)

                findings.append(ExposedKeyFinding(
                    repository=repo_name,
                    file_path=file_path,
                    file_url=file_url,
                    commit_sha=commit_sha,
                    discovered_at=datetime.now(timezone.utc).isoformat(),
                    key_type=provider,
                    key_preview=secret[:12] + '***' if len(secret) > 12 else secret[:8] + '***',
                    confidence=confidence,
                ))

        for match in RAW_KEY_PATTERN.finditer(content):
            secret = normalize_secret_value(match.group(1))
            result = score_secret(secret, None, file_path)
            if result is None:
                continue

            provider, confidence = result
            if confidence < 60:
                continue

            key_id = (file_path, provider, secret[:24])
            if key_id in seen:
                continue
            seen.add(key_id)

            findings.append(ExposedKeyFinding(
                repository=repo_name,
                file_path=file_path,
                file_url=file_url,
                commit_sha=commit_sha,
                discovered_at=datetime.now(timezone.utc).isoformat(),
                key_type=provider,
                key_preview=secret[:12] + '***' if len(secret) > 12 else secret[:8] + '***',
                confidence=confidence,
            ))

        return findings

    def fetch_file_contents(self, item: Dict[str, Any]) -> Optional[Tuple[str, str, str, Optional[str], str]]:
        """Download a single matched file only (no repo tarball)."""
        if not self._check_budget():
            return None

        repo_name = item.get('repository', {}).get('full_name', 'unknown')
        file_path = item.get('path', 'unknown')
        file_url = item.get('html_url', '')
        contents_url = item.get('url')
        if not contents_url:
            return None

        file_id = f"{repo_name}:{file_path}"
        if file_id in self.analyzed_files:
            return None
        self.analyzed_files.add(file_id)

        try:
            response = self.session.get(contents_url, timeout=20)
            self.requests_made += 1

            if response.status_code in [403, 429]:
                return None
            if response.status_code != 200:
                return None

            data = response.json()
            content = data.get('content', '')
            if data.get('encoding') == 'base64':
                try:
                    decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                except Exception:
                    return None
            else:
                decoded = content

            return repo_name, file_path, file_url, item.get('sha'), decoded
        except Exception:
            return None

    def search_code(self, query: str, per_page: int = 30) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        page = 1

        print(f'  Query: {query}')
        print(f'  Budget: {self.requests_made}/{self.MAX_REQUESTS_PER_SCAN} requests used')

        while page <= self.MAX_PAGES:
            if not self._check_budget():
                break

            url = 'https://api.github.com/search/code'
            params = {
                'q': query,
                'per_page': per_page,
                'page': page,
                'sort': 'indexed',
                'order': 'desc'
            }

            try:
                response = self.session.get(url, params=params, timeout=30)
                self.requests_made += 1

                if response.status_code == 403:
                    reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
                    wait_time = max(reset_time - int(time.time()), 60)
                    print(f'  ⏳ Rate limited. Waiting {wait_time}s...')
                    time.sleep(wait_time)
                    continue

                if response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', 60))
                    print(f'  ⏳ 429 received. Waiting {retry_after}s...')
                    time.sleep(retry_after)
                    continue

                if response.status_code == 422:
                    print('  ⚠️ Invalid query')
                    break

                if response.status_code != 200:
                    print(f'  ⚠️ HTTP {response.status_code}')
                    break

                data = response.json()
                items = data.get('items', [])
                if not items:
                    break

                results.extend(items)
                print(f'  Page {page}: {len(items)} results (total: {len(results)})')
                page += 1

                if page <= self.MAX_PAGES:
                    self._wait_if_needed()

            except requests.exceptions.RequestException as e:
                print(f'  ⚠️ Request error: {e}')
                break

        return results

    def scan_search_results(self, results: List[Dict[str, Any]]) -> List[ExposedKeyFinding]:
        findings: List[ExposedKeyFinding] = []

        for item in results:
            if not self._check_budget():
                break

            fetched = self.fetch_file_contents(item)
            if fetched is None:
                continue

            repo_name, file_path, file_url, commit_sha, content = fetched
            findings.extend(self._scan_text_for_findings(content, file_path, repo_name, file_url, commit_sha))

        return findings

    def _get_query_for_this_slot(self) -> tuple:
        slots = [
            ('sk-proj- filename:.env', 'sk-proj-env'),
            ('sk-proj- extension:py', 'sk-proj-py'),
            ('sk-proj- extension:js', 'sk-proj-js'),
            ('sk-proj- extension:ts', 'sk-proj-ts'),
            ('sk-proj- extension:json', 'sk-proj-json'),
            ('sk-proj- extension:yml', 'sk-proj-yml'),
        ]
        current_10min_slot = (datetime.now(timezone.utc).hour * 6 + datetime.now(timezone.utc).minute // 10) % len(slots)
        return slots[current_10min_slot]

    def scan_for_keys(self) -> List[ExposedKeyFinding]:
        query, _ = self._get_query_for_this_slot()
        results = self.search_code(query, per_page=30)
        if not results:
            return []
        return self.scan_search_results(results)

    def save_findings(self, findings: List[ExposedKeyFinding], output_dir: Path):
        output_dir.mkdir(parents=True, exist_ok=True)

        latest_file = output_dir / 'latest.json'
        existing_findings = []
        if latest_file.exists():
            try:
                with open(latest_file) as f:
                    data = json.load(f)
                    existing_findings = [ExposedKeyFinding(**f) for f in data.get('findings', [])]
            except Exception:
                pass

        seen_urls = {f.file_url for f in existing_findings}
        for f in findings:
            if f.file_url not in seen_urls:
                existing_findings.append(f)
                seen_urls.add(f.file_url)

        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        output_file = output_dir / f'scan_{timestamp}.json'

        data = {
            'scan_timestamp': datetime.now(timezone.utc).isoformat(),
            'total_findings': len(existing_findings),
            'requests_made': self.requests_made,
            'findings': [asdict(f) for f in existing_findings],
        }

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)

        with open(latest_file, 'w') as f:
            json.dump(data, f, indent=2)

        return output_file, existing_findings


def generate_readme(findings: List[ExposedKeyFinding], scan_time: datetime, requests_made: int) -> str:
    total_findings = len(findings)
    by_type: Dict[str, int] = {}
    by_repo: Dict[str, int] = {}

    for f in findings:
        by_type[f.key_type] = by_type.get(f.key_type, 0) + 1
        by_repo[f.repository] = by_repo.get(f.repository, 0) + 1

    readme = f'''# High-Confidence AI API Key Exposure Monitor

> Security research project for detecting high-confidence AI API key leaks in public GitHub repos.

This tool is intentionally conservative. It prefers low false positives over broad keyword-only matches.

## Latest Scan Results

**Last Updated**: {scan_time.strftime('%Y-%m-%d %H:%M:%S UTC')}
**API Requests Made**: {requests_made}
**Total Unique Findings**: {total_findings}

### Summary Statistics

| Metric | Count |
|--------|-------|
| **Key Types Detected** | {len(by_type)} |
| **Affected Repositories** | {len(by_repo)} |

### By Key Type

| Key Pattern | Count |
|-------------|-------|
'''

    for key_type, count in sorted(by_type.items(), key=lambda x: -x[1]):
        readme += f'| `{key_type}` | {count} |\n'

    readme += '''
### Recent Findings

| Repository | File Path | Key Type | Preview | Discovered |
|------------|-----------|----------|---------|------------|
'''

    recent_findings = sorted(findings, key=lambda x: x.discovered_at, reverse=True)[:100]
    for f in recent_findings:
        repo_short = f.repository[:30] + '...' if len(f.repository) > 30 else f.repository
        file_short = f.file_path[:35] + '...' if len(f.file_path) > 35 else f.file_path
        readme += f'| `{repo_short}` | `{file_short}` | `{f.key_type}` | `{f.key_preview}` | {f.discovered_at[:10]} |\n'

    readme += '''

---

## How this project reduces false positives

- Identifies likely provider and exact issuer prefix
- Validates against provider-specific secret formats and strict length bounds
- Rejects known placeholder/demo/test values and repeated/simple patterns
- Ignores docs/examples/tests/fixtures paths
- Applies a confidence scoring threshold before reporting a hit
- Scans only files returned by GitHub search results instead of downloading full repos

---

## Legal and Ethical Notice

This project only analyzes publicly available code and does not store or log actual secrets.
'''

    return readme


def main():
    token = os.environ.get('GITHUB_TOKEN')
    if not token:
        print('❌ Error: GITHUB_TOKEN environment variable not set')
        return 1

    scanner = GitHubScanner(token)
    findings = scanner.scan_for_keys()

    output_dir = Path('data')
    output_file, all_findings = scanner.save_findings(findings, output_dir)

    scan_time = datetime.now(timezone.utc)
    readme = generate_readme(all_findings, scan_time, scanner.requests_made)

    with open('README.md', 'w') as f:
        f.write(readme)

    print(f'\nScan complete! Total unique findings: {len(all_findings)}')
    print(f'Data file: {output_file}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

# License: MIT
# This repository is for security research and awareness purposes.
