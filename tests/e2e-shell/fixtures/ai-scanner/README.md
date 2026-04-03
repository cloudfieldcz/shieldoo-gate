## AI Scanner Test Fixtures

This directory contains test fixtures for the AI scanner E2E tests.

### Malicious .pth file (LiteLLM-style attack)

The E2E test dynamically creates a minimal wheel containing a `.pth` file
with executable code (double base64-encoded payload simulation). This
tests the AI scanner's ability to detect the same attack vector used in
the LiteLLM/TeamPCP incident (March 2026).

Expected AI scanner verdict: **MALICIOUS** (confidence >= 0.85)
