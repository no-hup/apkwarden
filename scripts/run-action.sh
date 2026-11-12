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

if [ -z "$TARGET" ]; then
    echo "::error::'target' input is required (path to APK, AAB, split set, or lockfile)."
    exit 1
fi

# Locate APKwarden runner
RUNNER=""
if [ -f "$ACTION_DIR/bin/apkwarden" ]; then
    RUNNER="$ACTION_DIR/bin/apkwarden"
elif [ -f "$ACTION_DIR/apkwarden-all.jar" ]; then
    RUNNER="java -jar $ACTION_DIR/apkwarden-all.jar"
elif [ -f "$ACTION_DIR/apkwarden-cli/build/libs/apkwarden-0.1.0-SNAPSHOT-all.jar" ]; then
    RUNNER="java -jar $ACTION_DIR/apkwarden-cli/build/libs/apkwarden-0.1.0-SNAPSHOT-all.jar"
else
    # Download standalone fat JAR from release
    CACHE_DIR="$HOME/.apkwarden/cache"
    mkdir -p "$CACHE_DIR"
    JAR_PATH="$CACHE_DIR/apkwarden-$VERSION-all.jar"
    if [ ! -f "$JAR_PATH" ]; then
        echo "⬇️ Downloading APKwarden $VERSION..."
        DOWNLOAD_URL="https://github.com/shaurya/apkwarden/releases/download/$VERSION/apkwarden-$VERSION-all.jar"
        if ! curl -sSL -f "$DOWNLOAD_URL" -o "$JAR_PATH"; then
            echo "::warning::Failed to download pre-built release from $DOWNLOAD_URL. Attempting local build via Gradle..."
            if [ -f "$ACTION_DIR/gradlew" ]; then
                "$ACTION_DIR/gradlew" -p "$ACTION_DIR" :apkwarden-cli:installDist -q
                RUNNER="$ACTION_DIR/apkwarden-cli/build/install/apkwarden/bin/apkwarden"
            else
                echo "::error::Unable to locate or download APKwarden executable."
                exit 1
            fi
        fi
    fi
    if [ -z "$RUNNER" ] && [ -f "$JAR_PATH" ]; then
        RUNNER="java -jar $JAR_PATH"
    fi
fi

# Construct command arguments
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

echo "🚀 Executing: $RUNNER ${ARGS[*]}"
# Run and capture exit code
set +e
$RUNNER "${ARGS[@]}"
EXIT_CODE=$?
set -e

exit $EXIT_CODE
