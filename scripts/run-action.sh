#!/usr/bin/env bash
#
# APKwarden GitHub Action Execution Wrapper
#
set -e

ACTION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

TARGET="${INPUT_TARGET}"
COMMAND="${INPUT_COMMAND:-scan}"
SARIF_FILE="${INPUT_SARIF_FILE:-apkwarden-results.sarif}"
BASELINE_FILE="${INPUT_BASELINE_FILE}"
LOCKFILE="${INPUT_LOCKFILE}"
GIT_REF="${INPUT_GIT_REF}"
FAIL_ON="${INPUT_FAIL_ON:-HIGH}"
FAIL_ON_BREAKING="${INPUT_FAIL_ON_BREAKING:-true}"
VERSION="${INPUT_VERSION:-v0.1.0}"
USE_LOCAL_BUILD="${INPUT_USE_LOCAL_BUILD:-false}"

if [ -z "$TARGET" ]; then
    echo "::error::'target' input is required (path to APK, AAB, split set, or lockfile)."
    exit 1
fi

# 1. Verify Java 17+ is installed
if ! command -v java >/dev/null 2>&1; then
    echo "::error::'java' command not found. Java 17 or higher is required to run APKwarden. Please add 'actions/setup-java@v4' with 'java-version: 17' to your workflow before this step."
    exit 1
fi

JAVA_VER=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}' | awk -F '.' '{print $1}')
if [ -n "$JAVA_VER" ] && [ "$JAVA_VER" -lt 17 ] 2>/dev/null; then
    echo "::error::Found Java version $JAVA_VER. APKwarden requires Java 17 or higher. Please use 'actions/setup-java@v4' with 'java-version: 17'."
    exit 1
fi

# 2. Locate APKwarden runner
JAR_FILE=""
if [ "$USE_LOCAL_BUILD" = "true" ] && [ -f "$ACTION_DIR/bin/apkwarden" ]; then
    RUNNER_CMD=("$ACTION_DIR/bin/apkwarden")
elif [ -f "$ACTION_DIR/apkwarden-all.jar" ]; then
    RUNNER_CMD=("java" "-jar" "$ACTION_DIR/apkwarden-all.jar")
elif [ -f "$ACTION_DIR/apkwarden-cli/build/libs/apkwarden-0.1.0-SNAPSHOT-all.jar" ]; then
    RUNNER_CMD=("java" "-jar" "$ACTION_DIR/apkwarden-cli/build/libs/apkwarden-0.1.0-SNAPSHOT-all.jar")
else
    # Download standalone fat JAR from release into persistent cache
    CACHE_DIR="$HOME/.apkwarden/cache"
    mkdir -p "$CACHE_DIR"
    JAR_PATH="$CACHE_DIR/apkwarden-$VERSION-all.jar"
    if [ ! -f "$JAR_PATH" ]; then
        echo "⬇️ Downloading APKwarden $VERSION standalone executable..."
        DOWNLOAD_URL="https://github.com/shaurya/apkwarden/releases/download/$VERSION/apkwarden-$VERSION-all.jar"
        SUMS_URL="https://github.com/shaurya/apkwarden/releases/download/$VERSION/SHA256SUMS"
        TMP_JAR="${JAR_PATH}.tmp"
        if curl -sSL -f "$DOWNLOAD_URL" -o "$TMP_JAR"; then
            # Verify checksum if SHA256SUMS is available
            if curl -sSL -f "$SUMS_URL" -o "${CACHE_DIR}/SHA256SUMS" 2>/dev/null; then
                EXPECTED_HASH=$(grep "apkwarden-$VERSION-all.jar" "${CACHE_DIR}/SHA256SUMS" | awk '{print $1}')
                if [ -n "$EXPECTED_HASH" ]; then
                    ACTUAL_HASH=$(shasum -a 256 "$TMP_JAR" 2>/dev/null | awk '{print $1}' || sha256sum "$TMP_JAR" | awk '{print $1}')
                    if [ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]; then
                        echo "::error::Checksum verification failed for downloaded APKwarden JAR (expected $EXPECTED_HASH, got $ACTUAL_HASH)."
                        rm -f "$TMP_JAR"
                        exit 1
                    fi
                    echo "✓ Verified SHA256 checksum ($ACTUAL_HASH)"
                fi
            fi
            mv "$TMP_JAR" "$JAR_PATH"
        else
            echo "::warning::Failed to download pre-built release from $DOWNLOAD_URL. Checking local Gradle..."
            if [ -f "$ACTION_DIR/gradlew" ]; then
                "$ACTION_DIR/gradlew" -p "$ACTION_DIR" :apkwarden-cli:fatJar -q
                JAR_PATH="$ACTION_DIR/apkwarden-cli/build/libs/apkwarden-0.1.0-SNAPSHOT-all.jar"
            else
                echo "::error::Unable to locate or download APKwarden executable."
                exit 1
            fi
        fi
    fi
    RUNNER_CMD=("java" "-jar" "$JAR_PATH")
fi

# 3. Handle shallow clone ref fetching for diff command
if [ "$COMMAND" = "diff" ] && [ -n "$GIT_REF" ]; then
    BASE_REF="${GIT_REF%%:*}"
    if ! git rev-parse --verify "$BASE_REF" >/dev/null 2>&1; then
        echo "ℹ️ Base ref '$BASE_REF' not found in local shallow clone. Attempting git fetch..."
        git fetch origin "${BASE_REF#origin/}" --depth=1 2>/dev/null || true
    fi
fi

# 4. Construct command arguments safely
ARGS=("$COMMAND" "$TARGET")

case "$COMMAND" in
    scan)
        if [ -n "$SARIF_FILE" ]; then
            ARGS+=("--sarif" "$SARIF_FILE")
        fi
        if [ -n "$BASELINE_FILE" ]; then
            ARGS+=("--baseline" "$BASELINE_FILE")
        fi
        if [ -n "$FAIL_ON" ]; then
            ARGS+=("--fail-on" "$FAIL_ON")
        fi
        ;;
    diff)
        if [ -n "$LOCKFILE" ]; then
            ARGS+=("-b" "$LOCKFILE")
        fi
        if [ -n "$GIT_REF" ]; then
            ARGS+=("--git-ref" "$GIT_REF")
        fi
        if [ "$FAIL_ON_BREAKING" = "false" ]; then
            ARGS+=("--no-fail-on-breaking")
        fi
        ;;
    lock)
        if [ -n "$LOCKFILE" ]; then
            ARGS+=("-o" "$LOCKFILE")
        fi
        ;;
    *)
        ;;
esac

echo "🚀 Executing APKwarden: ${RUNNER_CMD[*]} ${ARGS[*]}"
# Run and capture exit code safely
set +e
"${RUNNER_CMD[@]}" "${ARGS[@]}"
EXIT_CODE=$?
set -e

exit $EXIT_CODE
