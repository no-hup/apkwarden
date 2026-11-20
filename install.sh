#!/usr/bin/env bash
#
# APKwarden Standalone Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/no-hup/apkwarden/main/install.sh | bash
#
# Environment Variables:
#   APKWARDEN_VERSION   Release version tag to install (default: v0.1.0)
#   INSTALL_DIR         Directory where the 'apkwarden' launcher is installed (default: $HOME/.local/bin)
#   SHARE_DIR           Directory where the standalone JAR is cached (default: $HOME/.local/share/apkwarden)
#   APKWARDEN_SHARE_DIR Runtime override for locating the standalone JAR in the launcher
#
set -e

REPO="no-hup/apkwarden"
VERSION="${APKWARDEN_VERSION:-v0.1.0}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
SHARE_DIR="${SHARE_DIR:-$HOME/.local/share/apkwarden}"

echo "🛡️ Installing APKwarden ($VERSION)..."

# 1. Check for Java 17+
if ! command -v java >/dev/null 2>&1; then
    echo "⚠️ Warning: 'java' was not found in PATH. Java 17 or higher is required to run APKwarden."
else
    JAVA_VER=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}' | awk -F '.' '{print $1}')
    if [ -n "$JAVA_VER" ] && [ "$JAVA_VER" -lt 17 ] 2>/dev/null; then
        echo "⚠️ Warning: Found Java $JAVA_VER. APKwarden requires Java 17 or higher."
    fi
fi

mkdir -p "$INSTALL_DIR" "$SHARE_DIR"

JAR_URL="https://github.com/$REPO/releases/download/$VERSION/apkwarden-$VERSION-all.jar"
SUMS_URL="https://github.com/$REPO/releases/download/$VERSION/SHA256SUMS"
TARGET_JAR="$SHARE_DIR/apkwarden-all.jar"
TMP_JAR="${TARGET_JAR}.tmp"

echo "⬇️ Downloading standalone executable..."
if curl -sSL -f --connect-timeout 15 --max-time 90 "$JAR_URL" -o "$TMP_JAR"; then
    if curl -sSL -f --connect-timeout 10 "$SUMS_URL" -o "${SHARE_DIR}/SHA256SUMS" 2>/dev/null; then
        EXPECTED_HASH=$(grep -E "apkwarden-.*all\.jar" "${SHARE_DIR}/SHA256SUMS" | head -n 1 | awk '{print $1}')
        if [ -n "$EXPECTED_HASH" ]; then
            ACTUAL_HASH=$(shasum -a 256 "$TMP_JAR" 2>/dev/null | awk '{print $1}' || sha256sum "$TMP_JAR" | awk '{print $1}')
            if [ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]; then
                echo "❌ Checksum verification failed for downloaded APKwarden JAR (expected $EXPECTED_HASH, got $ACTUAL_HASH)." >&2
                rm -f "$TMP_JAR"
                exit 1
            fi
            echo "✓ Verified SHA256 checksum ($ACTUAL_HASH)"
        fi
    fi
    mv "$TMP_JAR" "$TARGET_JAR"
else
    echo "❌ Failed to download APKwarden executable from $JAR_URL" >&2
    exit 1
fi

# 2. Create launcher script
LAUNCHER="$INSTALL_DIR/apkwarden"
cat << 'EOF' > "$LAUNCHER"
#!/usr/bin/env bash
SHARE_DIR="${APKWARDEN_SHARE_DIR:-$HOME/.local/share/apkwarden}"
JAR_PATH="$SHARE_DIR/apkwarden-all.jar"

if [ ! -f "$JAR_PATH" ]; then
    echo "Error: APKwarden JAR not found at $JAR_PATH. Re-run installer." >&2
    exit 1
fi

exec java -jar "$JAR_PATH" "$@"
EOF

chmod +x "$LAUNCHER"
chmod +x "$TARGET_JAR"

echo "✓ Successfully installed apkwarden to $LAUNCHER"

case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) echo "💡 Add $INSTALL_DIR to your PATH by adding this to your ~/.zshrc or ~/.bashrc:"
       echo "   export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac

echo ""
echo "Try running:"
echo "  apkwarden --help"
