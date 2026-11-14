#!/usr/bin/env bash
#
# APKwarden Standalone Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/no-hup/apkwarden/main/install.sh | bash
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
TARGET_JAR="$SHARE_DIR/apkwarden-all.jar"

echo "⬇️ Downloading standalone executable..."
curl -sSL --connect-timeout 15 --max-time 90 "$JAR_URL" -o "$TARGET_JAR"

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
