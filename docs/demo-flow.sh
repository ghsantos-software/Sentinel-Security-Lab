#!/usr/bin/env bash
# Full demo flow — register → login → target → scan → dashboard → report
# Run with: bash docs/demo-flow.sh
# Requires the app running on localhost:8080 and postgres on 5433

BASE="http://localhost:8080"

echo "=== 1. Register ==="
curl -s -X POST "$BASE/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"demo","email":"demo@lab.local","password":"Demo@1234"}' | cat

echo -e "\n\n=== 2. Login ==="
RESPONSE=$(curl -s -X POST "$BASE/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"demo","password":"Demo@1234"}')
echo "$RESPONSE" | cat
TOKEN=$(echo "$RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

echo -e "\n\n=== 3. Register target ==="
curl -s -X POST "$BASE/api/targets" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Sentinel Self-Scan","baseUrl":"http://localhost:8080","description":"Self-scan do Sentinel","environment":"LOCAL"}' | cat

echo -e "\n\n=== 4. Run full scan ==="
curl -s -X POST "$BASE/api/scans/full/1" \
  -H "Authorization: Bearer $TOKEN" | cat

echo -e "\n\n=== 5. Dashboard (findings grouped by severity) ==="
curl -s "$BASE/api/scans/1/dashboard" \
  -H "Authorization: Bearer $TOKEN" | cat

echo -e "\n\n=== 6. Generate report ==="
curl -s -X POST "$BASE/api/reports/generate/1" \
  -H "Authorization: Bearer $TOKEN" | cat

echo -e "\n\n=== 7. Analyze a JWT ==="
curl -s -X POST "$BASE/api/scans/analyze-token" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"token\":\"$TOKEN\"}" | cat

echo -e "\n\nDone."
