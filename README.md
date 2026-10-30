# High-Confidence AI API Key Exposure Monitor

A stricter GitHub secret scanner focused on reducing false positives.

## Overview

This project is designed to monitor publicly visible GitHub repositories for likely leaked AI API keys using a conservative detection model instead of broad keyword-only scans.

## Core design goals

- Identify the likely provider and exact expected prefix
- Validate against the real secret format
- Reject placeholder/test/demo strings
- Exclude docs/examples/test fixtures
- Only alert when the score passes a confidence threshold

## Example providers handled

- OpenAI / Codex
- Anthropic
- Gemini / Google AI
- Groq
- Hugging Face
- DeepSeek
- Azure OpenAI
- Mistral
- Perplexity

## Run

```bash
pip install -r requirements.txt
export GITHUB_TOKEN=YOUR_GITHUB_TOKEN
python scanner.py
```

## Notes

This tool is built for security research and awareness. It does not store real keys, only metadata about candidate findings.

## License

MIT
