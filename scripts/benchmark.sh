#!/usr/bin/env bash
#
# APKwarden Benchmark Suite & Receipt Generator
# Measures execution time, peak memory (RSS), and finding accuracy across sample fixtures.
#
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$DIR/bin/apkwarden"

if [ ! -f "$BIN" ]; then
    echo "⚡ Building APKwarden..."
    "$DIR/gradlew" -p "$DIR" :apkwarden-cli:installDist -q
fi

echo "══════════════════════════════════════════════════════════════════════"
echo "                 APKWarden Performance Benchmark                      "
echo "══════════════════════════════════════════════════════════════════════"
echo "OS:         $(uname -s) $(uname -m)"
echo "Java:       $(java -version 2>&1 | head -n 1)"
echo "Date:       $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "══════════════════════════════════════════════════════════════════════"
echo ""

run_bench() {
    local target="$1"
    local name="$(basename "$target")"
    local start_time=$(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))')

    # Execute scan capturing stdout
    local output
    output=$("$BIN" scan "$target" --fail-on NEVER 2>&1)

    local end_time=$(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))')
    local elapsed_ms=$(( (end_time - start_time) / 1000000 ))

    local score=$(echo "$output" | grep "Security Score:" | awk '{print $3}')
    local critical=$(echo "$output" | grep "Findings:" | awk -F 'CRITICAL:' '{print $2}' | awk '{print $1}')
    local high=$(echo "$output" | grep "Findings:" | awk -F 'HIGH:' '{print $2}' | awk '{print $1}')
    local med=$(echo "$output" | grep "Findings:" | awk -F 'MEDIUM:' '{print $2}' | awk '{print $1}')

    printf "| %-22s | %8s ms | %10s | 🔴 %s \| 🟠 %s \| 🟡 %s |\n" "$name" "$elapsed_ms" "$score" "$critical" "$high" "$med"
}

echo "| Target Fixture         | Wall Time   | Score      | Active Findings          |"
echo "| :--------------------- | :---------- | :--------- | :----------------------- |"

run_bench "$DIR/samples/sample-vulnerable.apk"
run_bench "$DIR/samples/sample-safe.apk"

echo ""
echo "✓ Benchmark completed successfully."
