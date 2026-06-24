#!/bin/bash
# SecretSniff pre-commit hook
# Scans staged files for secrets before commit
# Install: python main.py install-hook

set -e

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null)

if [ -z "$STAGED_FILES" ]; then
    exit 0
fi

echo ""
echo "========================================"
echo "  SecretSniff - Pre-commit Scan"
echo "========================================"
echo ""

# Create temp file with staged content
TEMPFILE=$(mktemp /tmp/secretsniff_staged_XXXXXX)
trap "rm -f $TEMPFILE" EXIT

for f in $STAGED_FILES; do
    git show ":$f" >> "$TEMPFILE" 2>/dev/null || true
done

# Run secretsniff on staged content
python -m main.py scan --stdin --no-disclaimer < "$TEMPFILE"
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "  [BLOCKED] Secrets detected in staged files!"
    echo "  Revoke the exposed key, remove it from your code, then retry."
    echo "  To bypass (NOT recommended): git commit --no-verify"
    echo ""
    exit 1
fi

echo ""
echo "  [OK] No secrets detected in staged files."
echo ""
exit 0
