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

# Auto-detect target if omitted or not found on disk
if [ -z "$TARGET" ] || [ ! -e "$TARGET" ]; then
    if [ -n "$TARGET" ]; then
        echo "::warning::Specified target '$TARGET' not found. Searching for built APK/AAB artifacts..."
    fi
    # Search for standard release APK first, then release bundle, then any APK in build outputs
    AUTO_TARGET=$(find . -type f -name "*.apk" -not -path "*/.*" -not -name "*unaligned*" | grep -E "release" | head -n 1 || true)
    if [ -z "$AUTO_TARGET" ]; then
        AUTO_TARGET=$(find . -type f -name "*.aab" -not -path "*/.*" | grep -E "release" | head -n 1 || true)
    fi
    if [ -z "$AUTO_TARGET" ]; then
        AUTO_TARGET=$(find . -type f -name "*.apk" -not -path "*/.*" -not -name "*unaligned*" | head -n 1 || true)
    fi

    if [ -n "$AUTO_TARGET" ] && [ -f "$AUTO_TARGET" ]; then
        echo "ℹ️ Auto-detected build artifact for analysis: $AUTO_TARGET"
        TARGET="$AUTO_TARGET"
    elif [ -z "$TARGET" ]; then
        echo "::error::'target' was not specified and no .apk or .aab was found in workspace. Run assembleRelease before this step or pass 'target: path/to/app.apk'."
        exit 1
    else
        echo "::error::Target '$TARGET' does not exist and no fallback .apk/.aab was found."
        exit 1
    fi
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
LOCAL_CLI_JAR=$(find "$ACTION_DIR/apkwarden-cli/build/libs" -name "apkwarden-*-all.jar" 2>/dev/null | head -n 1 || true)

if [ "$USE_LOCAL_BUILD" = "true" ] && [ -f "$ACTION_DIR/bin/apkwarden" ]; then
    RUNNER_CMD=("$ACTION_DIR/bin/apkwarden")
elif [ -f "$ACTION_DIR/apkwarden-all.jar" ]; then
    RUNNER_CMD=("java" "-jar" "$ACTION_DIR/apkwarden-all.jar")
elif [ -n "$LOCAL_CLI_JAR" ] && [ -f "$LOCAL_CLI_JAR" ]; then
    RUNNER_CMD=("java" "-jar" "$LOCAL_CLI_JAR")
else
    # Download standalone fat JAR from release into persistent cache
    CACHE_DIR="$HOME/.apkwarden/cache"
    mkdir -p "$CACHE_DIR"
    JAR_PATH="$CACHE_DIR/apkwarden-$VERSION-all.jar"
    if [ ! -f "$JAR_PATH" ]; then
        echo "⬇️ Downloading APKwarden $VERSION standalone executable..."
        if [ "$VERSION" = "latest" ]; then
            DOWNLOAD_URL="https://github.com/no-hup/apkwarden/releases/latest/download/apkwarden-all.jar"
            SUMS_URL="https://github.com/no-hup/apkwarden/releases/latest/download/SHA256SUMS"
        else
            DOWNLOAD_URL="https://github.com/no-hup/apkwarden/releases/download/$VERSION/apkwarden-$VERSION-all.jar"
            SUMS_URL="https://github.com/no-hup/apkwarden/releases/download/$VERSION/SHA256SUMS"
        fi
        TMP_JAR="${JAR_PATH}.tmp"
        if curl -sSL -f --connect-timeout 15 --max-time 90 "$DOWNLOAD_URL" -o "$TMP_JAR"; then
            # Verify checksum if SHA256SUMS is available
            if curl -sSL -f --connect-timeout 10 "$SUMS_URL" -o "${CACHE_DIR}/SHA256SUMS" 2>/dev/null; then
                EXPECTED_HASH=$(grep -E "apkwarden-.*all\.jar" "${CACHE_DIR}/SHA256SUMS" | head -n 1 | awk '{print $1}')
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
                JAR_PATH=$(find "$ACTION_DIR/apkwarden-cli/build/libs" -name "apkwarden-*-all.jar" 2>/dev/null | head -n 1 || true)
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
