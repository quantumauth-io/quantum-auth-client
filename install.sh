#!/usr/bin/env bash
set -euo pipefail

APP_NAME="quantum-auth-client"
INSTALL_DIR="$HOME/.local/bin"
DESKTOP_DIR="$HOME/.local/share/applications"
DESKTOP_FILE="$DESKTOP_DIR/${APP_NAME}.desktop"

echo "[QuantumAuth] Installing..."

# 1) Ensure dirs
mkdir -p "$INSTALL_DIR" "$DESKTOP_DIR"

# 2) Install binary from current directory
if [[ ! -f "./${APP_NAME}" ]]; then
  echo "Error: ./{$APP_NAME} binary not found next to install.sh"
  exit 1
fi

cp "./${APP_NAME}" "$INSTALL_DIR/$APP_NAME"
chmod +x "$INSTALL_DIR/$APP_NAME"
echo "[QuantumAuth] Binary installed to $INSTALL_DIR/$APP_NAME"

# 3) Create .desktop entry (qa:// handler)
cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Name=QuantumAuth Client
Comment=QuantumAuth local signing client
Exec=${INSTALL_DIR}/${APP_NAME} %u
Terminal=true
Type=Application
Categories=Security;Network;
MimeType=x-scheme-handler/qa;
EOF

echo "[QuantumAuth] Desktop file created at $DESKTOP_FILE"

# 4) Register qa:// scheme
xdg-mime default "${APP_NAME}.desktop" x-scheme-handler/qa || true
update-desktop-database "$DESKTOP_DIR" || true

echo "[QuantumAuth] qa:// URL scheme registered"

# 5) Optional: remind user to add ~/.local/bin to PATH
case ":$PATH:" in
  *":$HOME/.local/bin:"*) ;;
  *)
    echo ""
    echo "[QuantumAuth] Note: $HOME/.local/bin is not in your PATH."
    echo "Add this to your shell config (e.g. ~/.bashrc or ~/.zshrc):"
    echo "  export PATH=$HOME/.local/bin:$PATH"
    ;;
esac

echo ""
echo "[QuantumAuth] Install complete."
echo "Try opening this in your browser: qa://test"
