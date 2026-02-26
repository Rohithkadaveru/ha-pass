#!/bin/bash
set -e
BASE="${1:-http://localhost:5880}"

# 1. Health check returns 200 or 503 (not 500/crash)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/health")
[[ "$STATUS" == "200" || "$STATUS" == "503" ]] || { echo "FAIL: /health returned $STATUS"; exit 1; }

# 2. Admin page returns 200
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/admin/dashboard")
[[ "$STATUS" == "200" || "$STATUS" == "302" ]] || { echo "FAIL: /admin/dashboard returned $STATUS"; exit 1; }

# 3. CSP header present
CSP=$(curl -s -I "$BASE/admin/dashboard" | grep -i "content-security-policy")
[[ -n "$CSP" ]] || { echo "FAIL: No CSP header"; exit 1; }

# 4. No inline handlers in guest templates (admin migration deferred to Phase 2)
grep 'onclick=\|onchange=\|oninput=' templates/guest_pwa.html && { echo "FAIL: Inline handlers in guest_pwa.html"; exit 1; } || true
grep 'onclick=\|onchange=\|oninput=' templates/expired.html && { echo "FAIL: Inline handlers in expired.html"; exit 1; } || true

# 5. Static files accessible
for f in theme.js util.js dist.css qrcode.min.js; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/static/$f")
  [[ "$STATUS" == "200" ]] || { echo "FAIL: /static/$f returned $STATUS"; exit 1; }
done

echo "ALL SMOKE TESTS PASSED"
