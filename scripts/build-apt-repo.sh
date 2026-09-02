#!/usr/bin/env bash
# build-apt-repo.sh — build a GPG-SIGNED flat apt repository for AgentTrace.
#
# Only the holder of the private GPG key can produce a valid, verifiable repo,
# so users can trust that updates come from you and no one else.
#
# Usage:
#   scripts/build-apt-repo.sh <GPG_KEY_ID_OR_EMAIL> [output_dir]
#
# Example:
#   scripts/build-apt-repo.sh you@example.com apt-repo
#
# Produces in <output_dir>:
#   agentdfir_<ver>_all.deb
#   Packages, Packages.gz
#   Release                              (repo metadata)
#   Release.gpg                          (detached signature)
#   InRelease                            (inline-signed metadata)
#   agenttrace-archive-keyring.asc       (your PUBLIC key, for users)
#
# Requires: fakeroot, dpkg-deb, dpkg-scanpackages, gpg. No root needed to build.
set -euo pipefail

KEY="${1:?Usage: build-apt-repo.sh <GPG_KEY_ID_OR_EMAIL> [output_dir]}"
OUT="${2:-apt-repo}"
VERSION="0.1.0-1"
PKG="agentdfir"

# Resolve the project root (this script lives in <root>/scripts).
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> Building .deb (fakeroot + dpkg-deb)"
STAGE="$(mktemp -d)/${PKG}_${VERSION}_all"
PYSITE="$STAGE/usr/lib/python3/dist-packages"
mkdir -p "$PYSITE" "$STAGE/usr/bin" "$STAGE/DEBIAN"

cp -r agenttrace "$PYSITE/"
find "$PYSITE" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true

cat > "$STAGE/usr/bin/agenttrace" <<'EOF'
#!/usr/bin/python3
import sys
from agenttrace.cli import main
if __name__ == "__main__":
    sys.exit(main())
EOF
chmod 755 "$STAGE/usr/bin/agenttrace"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: ${PKG}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: all
Depends: python3 (>= 3.10)
Maintainer: Piyush Kumar <piyush@example.invalid>
Homepage: https://github.com/rakshanex/agenttrace
Description: Forensic reconstruction for AI-agent security incidents (DFIR)
 Provides the "agenttrace" command. Defensive, authorized use only.
EOF

fakeroot dpkg-deb --build --root-owner-group "$STAGE" >/dev/null
DEB="$STAGE.deb"

echo "==> Assembling repo at: $OUT"
rm -rf "$OUT"; mkdir -p "$OUT"
cp "$DEB" "$OUT/"
cd "$OUT"

echo "==> Generating Packages + Packages.gz"
dpkg-scanpackages --multiversion . /dev/null > Packages 2>/dev/null
gzip -9c Packages > Packages.gz

echo "==> Generating Release"
cat > Release <<EOF
Origin: AgentTrace
Label: AgentTrace
Suite: stable
Codename: stable
Architectures: all
Components: main
Description: AgentTrace apt repository
Date: $(date -Ru)
EOF
# add checksums of Packages files to Release
{
  echo "MD5Sum:"
  for f in Packages Packages.gz; do
    printf " %s %d %s\n" "$(md5sum "$f" | cut -d' ' -f1)" "$(stat -c%s "$f")" "$f"
  done
  echo "SHA256:"
  for f in Packages Packages.gz; do
    printf " %s %d %s\n" "$(sha256sum "$f" | cut -d' ' -f1)" "$(stat -c%s "$f")" "$f"
  done
} >> Release

echo "==> Signing Release with GPG key: $KEY"
rm -f Release.gpg InRelease
gpg --default-key "$KEY" --armor --detach-sign --output Release.gpg Release
gpg --default-key "$KEY" --clearsign --output InRelease Release

echo "==> Exporting your PUBLIC key for users"
gpg --armor --export "$KEY" > agenttrace-archive-keyring.asc

echo ""
echo "DONE. Signed repo is in: $OUT"
echo "  - InRelease / Release.gpg : signed metadata (verifiable)"
echo "  - agenttrace-archive-keyring.asc : PUBLIC key to share with users"
echo ""
echo "Verify the signature yourself with:"
echo "  gpg --verify $OUT/Release.gpg $OUT/Release"
