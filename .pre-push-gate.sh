#!/usr/bin/env bash
# pre-push gate — run before every `git push`
# Fails if: no README.md / LICENSE / BENCHMARK.md / AC_TEST_MAP.md
#          OR tests fail
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

GATE_LOG="/tmp/pre-push-gate-$(date +%s).log"
exec > "$GATE_LOG" 2>&1

echo "=== pre-push gate: rfc-9741-pure ==="
echo "Branch: $(git branch --show-current)"
echo "Commit: $(git log -1 --oneline)"
echo ""

PASS=true

# ── Required files ──────────────────────────────────────────────────────────
for f in README.md LICENSE benchmarks/BENCHMARK.md AC_TEST_MAP.md; do
    if [[ -f "$f" ]]; then
        echo -e "${GREEN}  [PASS]${NC} $f exists"
    else
        echo -e "${RED}  [FAIL]${NC} MISSING: $f"
        PASS=false
    fi
done

# ── deps=[] check ───────────────────────────────────────────────────────────
if grep -q '^dependencies\s*=\s*\[\]' pyproject.toml; then
    echo -e "${GREEN}  [PASS]${NC} dependencies = []"
else
    echo -e "${RED}  [FAIL]${NC} pyproject.toml deps not empty"
    PASS=false
fi

# ── Tests ───────────────────────────────────────────────────────────────────
echo ""
echo "Running pytest..."
if python3 -m pytest tests/ -q --tb=short; then
    echo -e "${GREEN}  [PASS]${NC} all tests pass"
else
    echo -e "${RED}  [FAIL]${NC} pytest failed"
    PASS=false
fi

# ── Benchmark ───────────────────────────────────────────────────────────────
echo ""
echo "Running benchmark..."
if python3 benchmarks/run_benchmark.py > /dev/null 2>&1; then
    echo -e "${GREEN}  [PASS]${NC} benchmark completes"
else
    echo -e "${RED}  [FAIL]${NC} benchmark failed"
    PASS=false
fi

echo ""
echo "=== VERDICT ===" | tee -a "$GATE_LOG"
if $PASS; then
    echo -e "${GREEN}VERDICT: SHIP${NC}"
    echo "Log: $GATE_LOG"
    exit 0
else
    echo -e "${RED}VERDICT: HOLD${NC}  (see log for failures)"
    echo "Log: $GATE_LOG"
    exit 1
fi
