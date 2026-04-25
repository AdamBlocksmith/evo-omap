#!/bin/bash
# EVO-OMAP Test Runner for macOS
# Logs all output to ~/Desktop/test_results.txt
# Usage: ./run_tests_mac.sh  (run from anywhere)

# Wrap everything in main() so bash reads the full script before any rm -rf
main() {

OUTPUT="$HOME/Desktop/test_results.txt"
REPO_URL="https://github.com/AdamBlocksmith/evo-omap.git"
REPO_DIR="$HOME/Desktop/EVO-OMAP"
SCRIPT_START=$SECONDS

# ── Log setup: tee stdout+stderr to file and terminal ─────────────────────────
exec > >(tee "$OUTPUT") 2>&1

# ── Timing helpers ────────────────────────────────────────────────────────────
if command -v gdate &>/dev/null; then
    now_ms()      { gdate +%s%3N; }
    TIMING_INFO="millisecond precision (gdate)"
else
    now_ms()      { echo "$(date +%s)000"; }
    TIMING_INFO="second precision (install coreutils for ms: brew install coreutils)"
fi

elapsed_str() {
    local ms=$1
    if   (( ms < 1000  )); then printf '%dms'      "$ms"
    elif (( ms < 60000 )); then
        printf '%d.%03ds' "$(( ms / 1000 ))" "$(( ms % 1000 ))"
    else
        printf '%dm %ds' "$(( ms / 60000 ))" "$(( (ms % 60000) / 1000 ))"
    fi
}

# ── Step tracking ─────────────────────────────────────────────────────────────
STEP_NAMES=()
STEP_STATUS=()
record_step() { STEP_NAMES+=("$1"); STEP_STATUS+=("$2"); }

# ── Helpers ───────────────────────────────────────────────────────────────────
HR()      { echo ""; printf '%.0s─' {1..66}; echo ""; }
section() { echo ""; printf '%.0s═' {1..66}; echo ""; printf '  %s\n' "$1"; printf '%.0s═' {1..66}; echo ""; echo ""; }
ts()      { date '+%H:%M:%S'; }

# ── Initialise state vars so summary is always defined ───────────────────────
NONCE_D1="" NONCE_D5="" NONCE_D10="" NONCE_D20=""
VERIFY_FULL_OK=false VERIFY_LIGHT_OK=false INVALID_REJECTED=false
BUILD_OK=false

# ═══════════════════════════════════════════════════════════════════════════════
echo ""
printf '%.0s═' {1..66}; echo ""
echo "  EVO-OMAP Test Runner for macOS"
echo "  Started : $(date '+%Y-%m-%d %H:%M:%S')"
echo "  Log file: $OUTPUT"
echo "  Timing  : $TIMING_INFO"
printf '%.0s═' {1..66}; echo ""

# ═══════════════════════════════════════════════════════════════════════════════
section "Hardware Info"

# Apple Silicon reports chip via sysctl on arm64; Intel via machdep.cpu.brand_string
CHIP=$(sysctl -n machdep.cpu.brand_string 2>/dev/null)
if [[ -z "$CHIP" ]]; then
    CHIP=$(system_profiler SPHardwareDataType 2>/dev/null \
        | awk -F': ' '/^\s*(Chip|Model Name):/{gsub(/^[[:space:]]+/,"",$2); print $2; exit}')
fi
RAM=$(system_profiler SPHardwareDataType 2>/dev/null \
    | awk -F': ' '/^\s*Memory:/{gsub(/^[[:space:]]+/,"",$2); print $2}')
PHYS_CORES=$(sysctl -n hw.physicalcpu 2>/dev/null)
LOGI_CORES=$(sysctl -n hw.logicalcpu  2>/dev/null)
ARCH=$(uname -m)
MACOS=$(sw_vers -productVersion 2>/dev/null)

printf '  %-22s %s\n' "Chip:"          "${CHIP:-unknown}"
printf '  %-22s %s\n' "Architecture:"  "$ARCH"
printf '  %-22s %s\n' "RAM:"           "${RAM:-unknown}"
printf '  %-22s %s physical / %s logical\n' "CPU cores:" \
    "${PHYS_CORES:-?}" "${LOGI_CORES:-?}"
printf '  %-22s %s\n' "macOS:"         "${MACOS:-unknown}"

# ═══════════════════════════════════════════════════════════════════════════════
section "Dependency Checks"

DEPS_OK=true
check_dep() {
    local cmd="$1" hint="$2"
    if command -v "$cmd" &>/dev/null; then
        local ver; ver=$("$cmd" --version 2>&1 | head -1)
        printf '  ✓  %-8s %s\n' "$cmd" "$ver"
    else
        printf '  ✗  %-8s NOT FOUND\n' "$cmd"
        printf '         Install: %s\n' "$hint"
        DEPS_OK=false
    fi
}

check_dep git    "xcode-select --install"
check_dep cargo  "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
check_dep rustc  "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"

if [[ "$DEPS_OK" != true ]]; then
    echo ""
    echo "  ABORT — missing dependencies listed above. Install them and re-run."
    record_step "Dependency check" "FAIL"
    echo ""
    printf '%.0s═' {1..66}; echo ""
    echo "  OVERALL: FAIL (aborted — missing dependencies)"
    printf '%.0s═' {1..66}; echo ""
    osascript -e 'display notification "EVO-OMAP Tests FAILED — missing dependencies" with title "EVO-OMAP Test Runner"' 2>/dev/null || true
    exit 1
fi
record_step "Dependency check" "PASS"

# ═══════════════════════════════════════════════════════════════════════════════
section "Clone Repository"

echo "  [$(ts)] Removing $REPO_DIR"
rm -rf "$REPO_DIR"

echo "  [$(ts)] Cloning $REPO_URL"
if git clone "$REPO_URL" "$REPO_DIR" 2>&1; then
    echo ""
    echo "  [$(ts)] Clone succeeded"
    record_step "Clone repo" "PASS"
else
    echo ""
    echo "  [$(ts)] ERROR: clone failed"
    record_step "Clone repo" "FAIL"
    echo "  ABORT — clone failed"
    exit 1
fi

cd "$REPO_DIR" || { echo "ERROR: cannot cd into $REPO_DIR"; exit 1; }
echo "  [$(ts)] Working directory: $(pwd)"

# ═══════════════════════════════════════════════════════════════════════════════
section "cargo build --release"

echo "  [$(ts)] Build started"
echo ""
T0=$(now_ms)
if cargo build --release 2>&1; then
    T1=$(now_ms)
    echo ""
    echo "  [$(ts)] Build PASSED — $(elapsed_str $(( T1 - T0 )))"
    record_step "cargo build --release" "PASS"
    BUILD_OK=true
else
    T1=$(now_ms)
    echo ""
    echo "  [$(ts)] Build FAILED — $(elapsed_str $(( T1 - T0 )))"
    record_step "cargo build --release" "FAIL"
fi

# ═══════════════════════════════════════════════════════════════════════════════
section "cargo test --release"

if [[ "$BUILD_OK" != true ]]; then
    echo "  (skipped — build failed)"
    record_step "cargo test --release" "SKIP"
    record_step "cargo test --release -- --ignored" "SKIP"
else
    echo "  [$(ts)] Tests started"
    echo ""
    T0=$(now_ms)
    TEST_OUT=$(cargo test --release 2>&1)
    TEST_RC=$?
    T1=$(now_ms)
    echo "$TEST_OUT"
    echo ""

    # Parse counts from "test result: ok. N passed; M failed; K ignored"
    TPASS=$(echo "$TEST_OUT" | awk '/^test result:/{for(i=1;i<=NF;i++) if($i=="passed;") print $(i-1)}' | tail -1)
    TFAIL=$(echo "$TEST_OUT" | awk '/^test result:/{for(i=1;i<=NF;i++) if($i=="failed;") print $(i-1)}' | tail -1)
    TIGN=$(echo  "$TEST_OUT" | awk '/^test result:/{for(i=1;i<=NF;i++) if($i=="ignored;") print $(i-1)}' | tail -1)
    TPASS=${TPASS:-0}; TFAIL=${TFAIL:-0}; TIGN=${TIGN:-0}

    echo "  [$(ts)] Tests finished — $(elapsed_str $(( T1 - T0 )))"
    printf '         Passed: %s   Failed: %s   Ignored: %s\n' "$TPASS" "$TFAIL" "$TIGN"

    if [[ $TEST_RC -eq 0 ]]; then
        record_step "cargo test --release ($TPASS passed, $TFAIL failed)" "PASS"
    else
        record_step "cargo test --release ($TPASS passed, $TFAIL failed)" "FAIL"
    fi

    # ── Ignored tests ──────────────────────────────────────────────────────────
    HR
    echo "  cargo test --release -- --ignored"
    HR
    echo ""
    echo "  [$(ts)] Ignored tests started"
    echo ""
    T0=$(now_ms)
    IGN_OUT=$(cargo test --release -- --ignored 2>&1)
    IGN_RC=$?
    T1=$(now_ms)
    echo "$IGN_OUT"
    echo ""

    IPASS=$(echo "$IGN_OUT" | awk '/^test result:/{for(i=1;i<=NF;i++) if($i=="passed;") print $(i-1)}' | tail -1)
    IFAIL=$(echo "$IGN_OUT" | awk '/^test result:/{for(i=1;i<=NF;i++) if($i=="failed;") print $(i-1)}' | tail -1)
    IPASS=${IPASS:-0}; IFAIL=${IFAIL:-0}

    echo "  [$(ts)] Ignored tests finished — $(elapsed_str $(( T1 - T0 )))"
    printf '         Passed: %s   Failed: %s\n' "$IPASS" "$IFAIL"

    if [[ $IGN_RC -eq 0 ]]; then
        record_step "cargo test -- --ignored ($IPASS passed)" "PASS"
    else
        record_step "cargo test -- --ignored ($IPASS passed, $IFAIL failed)" "FAIL"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Benchmark helpers
# ═══════════════════════════════════════════════════════════════════════════════

# Temp dir for nonce capture files; cleaned up on exit
TMPDIR_EVOMAP=$(mktemp -d)
trap 'rm -rf "$TMPDIR_EVOMAP"' EXIT

# run_bench: prints a timestamp before/after and the elapsed time.
# Returns the exit code of the command.
run_bench() {
    local label="$1"; shift
    echo ""
    echo "  ── $label"
    echo "  [$(ts)] START: $*"
    local T0 T1 rc
    T0=$(now_ms)
    "$@" 2>&1
    rc=$?
    T1=$(now_ms)
    echo "  [$(ts)] END  : $(elapsed_str $(( T1 - T0 ))) (exit $rc)"
    return $rc
}

# mine_bench: runs mine, prints output, and saves found nonce to a temp file.
mine_bench() {
    local diff=$1 max=$2
    local outfile="$TMPDIR_EVOMAP/nonce_d${diff}.txt"
    echo ""
    echo "  ── mine 00 0 $diff $max"
    echo "  [$(ts)] START: ./target/release/evo-omap mine 00 0 $diff $max"
    local T0 T1 output rc nonce
    T0=$(now_ms)
    output=$(./target/release/evo-omap mine 00 0 "$diff" "$max" 2>&1)
    rc=$?
    T1=$(now_ms)
    echo "$output"
    nonce=$(echo "$output" | grep 'Found valid nonce:' | awk '{print $NF}')
    echo "  [$(ts)] END  : $(elapsed_str $(( T1 - T0 ))) (exit $rc)"
    [[ -n "$nonce" ]] && printf '  Nonce captured: %s\n' "$nonce"
    # Write nonce (possibly empty) to file for later capture
    printf '%s' "$nonce" > "$outfile"
    return $rc
}

# ═══════════════════════════════════════════════════════════════════════════════
if [[ "$BUILD_OK" != true ]]; then
    section "Benchmarks (SKIPPED — build failed)"
    record_step "Benchmarks" "SKIP"
else

    # ── Hash benchmarks ─────────────────────────────────────────────────────────
    section "Benchmarks — hash"
    run_bench "hash 00 0 0"       ./target/release/evo-omap hash 00       0 0
    run_bench "hash ff 0 0"       ./target/release/evo-omap hash ff       0 0
    run_bench "hash deadbeef 0 0" ./target/release/evo-omap hash deadbeef 0 0

    # ── Seed commands ───────────────────────────────────────────────────────────
    section "Benchmarks — seed"
    run_bench "seed 0"    ./target/release/evo-omap seed 0
    run_bench "seed 1023" ./target/release/evo-omap seed 1023
    run_bench "seed 1024" ./target/release/evo-omap seed 1024

    record_step "hash + seed benchmarks" "PASS"

    # ── Mine benchmarks ─────────────────────────────────────────────────────────
    section "Benchmarks — mine"
    mine_bench  1   100
    mine_bench  5  1000
    mine_bench 10  1000
    mine_bench 20  1000

    NONCE_D1=$(cat  "$TMPDIR_EVOMAP/nonce_d1.txt"  2>/dev/null)
    NONCE_D5=$(cat  "$TMPDIR_EVOMAP/nonce_d5.txt"  2>/dev/null)
    NONCE_D10=$(cat "$TMPDIR_EVOMAP/nonce_d10.txt" 2>/dev/null)
    NONCE_D20=$(cat "$TMPDIR_EVOMAP/nonce_d20.txt" 2>/dev/null)

    echo ""
    echo "  Nonce summary:"
    printf '    %-30s %s\n' "difficulty  1 (max   100):" "${NONCE_D1:-NOT FOUND}"
    printf '    %-30s %s\n' "difficulty  5 (max  1000):" "${NONCE_D5:-NOT FOUND}"
    printf '    %-30s %s\n' "difficulty 10 (max  1000):" "${NONCE_D10:-NOT FOUND}"
    printf '    %-30s %s\n' "difficulty 20 (max  1000):" "${NONCE_D20:-NOT FOUND}"

    if [[ -n "$NONCE_D1" || -n "$NONCE_D5" || -n "$NONCE_D10" || -n "$NONCE_D20" ]]; then
        record_step "Mine benchmarks" "PASS"
    else
        record_step "Mine benchmarks (no nonces found in any run)" "FAIL"
    fi

    # ── Verify real nonce ───────────────────────────────────────────────────────
    section "Verify — real nonce (difficulty 1)"

    if [[ -n "$NONCE_D1" ]]; then
        run_bench "verify 00 0 $NONCE_D1 1 (full)" \
            ./target/release/evo-omap verify 00 0 "$NONCE_D1" 1
        [[ $? -eq 0 ]] && VERIFY_FULL_OK=true

        run_bench "verify 00 0 $NONCE_D1 1 light" \
            ./target/release/evo-omap verify 00 0 "$NONCE_D1" 1 light
        [[ $? -eq 0 ]] && VERIFY_LIGHT_OK=true
    else
        echo "  (skipped — no nonce was found at difficulty 1 in 100 attempts)"
    fi

    if [[ "$VERIFY_FULL_OK" == true && "$VERIFY_LIGHT_OK" == true ]]; then
        record_step "verify + verify_light agree VALID (nonce $NONCE_D1)" "PASS"
    else
        record_step "verify + verify_light agree VALID (nonce $NONCE_D1)" "FAIL"
    fi

    # ── Verify invalid nonce ────────────────────────────────────────────────────
    section "Verify — invalid nonce 999999"

    run_bench "verify 00 0 999999 1" ./target/release/evo-omap verify 00 0 999999 1
    # verify exits 1 for INVALID — that is the expected/correct result here
    if [[ $? -ne 0 ]]; then
        INVALID_REJECTED=true
        record_step "Invalid nonce 999999 correctly rejected" "PASS"
    else
        record_step "Invalid nonce 999999 was NOT rejected (bug!)" "FAIL"
    fi

fi  # end BUILD_OK block

# ═══════════════════════════════════════════════════════════════════════════════
# Final Summary
# ═══════════════════════════════════════════════════════════════════════════════

TOTAL_SECS=$(( SECONDS - SCRIPT_START ))
TOTAL_MIN=$(( TOTAL_SECS / 60 ))
TOTAL_REM=$(( TOTAL_SECS % 60 ))

echo ""
echo ""
printf '%.0s═' {1..66}; echo ""
echo "  FINAL SUMMARY"
printf '%.0s═' {1..66}; echo ""
echo ""
echo "  Completed : $(date '+%Y-%m-%d %H:%M:%S')"
echo "  Total time: ${TOTAL_MIN}m ${TOTAL_REM}s"
echo ""
echo "  Hardware:"
printf '    %-22s %s\n' "Chip:"          "${CHIP:-unknown}"
printf '    %-22s %s\n' "Architecture:"  "$ARCH"
printf '    %-22s %s\n' "RAM:"           "${RAM:-unknown}"
printf '    %-22s %s physical / %s logical\n' "Cores:" \
    "${PHYS_CORES:-?}" "${LOGI_CORES:-?}"
printf '    %-22s %s\n' "macOS:"         "${MACOS:-unknown}"
echo ""
echo "  Step results:"

OVERALL_PASS=true
for (( i=0; i<${#STEP_NAMES[@]}; i++ )); do
    case "${STEP_STATUS[$i]}" in
        PASS) printf '    [PASS] %s\n' "${STEP_NAMES[$i]}" ;;
        SKIP) printf '    [SKIP] %s\n' "${STEP_NAMES[$i]}" ;;
        FAIL) printf '    [FAIL] %s\n' "${STEP_NAMES[$i]}"; OVERALL_PASS=false ;;
    esac
done

echo ""
echo "  Nonces found:"
printf '    %-32s %s\n' "difficulty  1 (max   100):" "${NONCE_D1:-NOT FOUND}"
printf '    %-32s %s\n' "difficulty  5 (max  1000):" "${NONCE_D5:-NOT FOUND}"
printf '    %-32s %s\n' "difficulty 10 (max  1000):" "${NONCE_D10:-NOT FOUND}"
printf '    %-32s %s\n' "difficulty 20 (max  1000):" "${NONCE_D20:-NOT FOUND}"

echo ""
echo "  Verification (difficulty 1, nonce=${NONCE_D1:-N/A}):"
if [[ -n "$NONCE_D1" ]]; then
    printf '    %-22s %s\n' "Full verify:" \
        "$( [[ "$VERIFY_FULL_OK"  == true ]] && echo 'VALID ✓' || echo 'INVALID ✗ (bug!)')"
    printf '    %-22s %s\n' "Light verify:" \
        "$( [[ "$VERIFY_LIGHT_OK" == true ]] && echo 'VALID ✓' || echo 'INVALID ✗ (bug!)')"
    printf '    %-22s %s\n' "Full == Light:" \
        "$( [[ "$VERIFY_FULL_OK" == true && "$VERIFY_LIGHT_OK" == true ]] \
            && echo 'Yes ✓' || echo 'No ✗ (bug!)')"
else
    echo "    (no nonce found at difficulty 1 — cannot run verify)"
fi

echo ""
printf '    %-22s %s\n' "Invalid nonce 999999:" \
    "$( [[ "$INVALID_REJECTED" == true ]] \
        && echo 'Correctly INVALID ✓' || echo 'NOT rejected ✗ (bug!)')"

echo ""
printf '%.0s─' {1..66}; echo ""
if [[ "$OVERALL_PASS" == true ]]; then
    echo "  ✓  OVERALL RESULT: PASS"
else
    echo "  ✗  OVERALL RESULT: FAIL"
fi
printf '%.0s─' {1..66}; echo ""
echo ""
echo "  Full output saved to: $OUTPUT"
echo ""

# ── macOS notification ─────────────────────────────────────────────────────────
osascript -e 'display notification "EVO-OMAP Tests Complete — check Desktop for results" with title "EVO-OMAP Test Runner"' 2>/dev/null || true

}  # end main()

main "$@"
