# Debian / Kali packaging guide

This document explains how to build a `.deb` for AgentTrace, install it, host a
personal `apt` repository, and (optionally) pursue official inclusion in the
Kali / Debian archives.

> For most users, **`pipx install agentdfir`** is the simplest path on
> Kali/Debian/Ubuntu (see README). The `.deb`/`apt` route below is for people who
> specifically want system packaging.

The packaging metadata lives in `debian/`:

```
debian/
  control        # source + binary package, deps, description
  rules          # build (dh + pybuild against pyproject.toml)
  changelog      # Debian-format version history (0.1.0-1)
  copyright      # Apache-2.0, machine-readable
  source/format  # 3.0 (quilt)
```

---

## ✅ Verified quick build (no debhelper / no sudo to build)

This is the exact, tested path used to validate the package on Ubuntu 24.04 with
only `fakeroot` + `dpkg-deb` (present by default). It produces a real `.deb`
without needing `debhelper`/`dh-python` or root to *build* (root is only needed to
*install*, like any package). A prebuilt repo already lives in `apt-repo/`.

```bash
cd <project root>
STAGE=/tmp/agentdfir_0.1.0-1_all
PYSITE="$STAGE/usr/lib/python3/dist-packages"
mkdir -p "$PYSITE" "$STAGE/usr/bin" "$STAGE/DEBIAN"

cp -r agenttrace "$PYSITE/"
find "$PYSITE" -name __pycache__ -type d -prune -exec rm -rf {} +

cat > "$STAGE/usr/bin/agenttrace" <<'EOF'
#!/usr/bin/python3
import sys
from agenttrace.cli import main
if __name__ == "__main__":
    sys.exit(main())
EOF
chmod 755 "$STAGE/usr/bin/agenttrace"

cat > "$STAGE/DEBIAN/control" <<'EOF'
Package: agentdfir
Version: 0.1.0-1
Section: utils
Priority: optional
Architecture: all
Depends: python3 (>= 3.10)
Maintainer: Piyush Kumar <piyush@example.invalid>
Homepage: https://github.com/rakshanex/agenttrace
Description: Forensic reconstruction for AI-agent security incidents (DFIR)
 Provides the "agenttrace" command. Defensive, authorized use only.
EOF

fakeroot dpkg-deb --build --root-owner-group "$STAGE"
# -> /tmp/agentdfir_0.1.0-1_all.deb
```

**Install the .deb (needs root, like any package):**
```bash
sudo apt install /tmp/agentdfir_0.1.0-1_all.deb
agenttrace --version        # -> agenttrace 0.1.0
```

## ✅ Verified local apt repository

A ready-made flat repo is generated at `apt-repo/` (`.deb` + `Packages` +
`Packages.gz` + `Release`). Install FROM it with apt:

```bash
echo "deb [trusted=yes] file:///media/hdd/projects/agenttrace/apt-repo ./" \
    | sudo tee /etc/apt/sources.list.d/agenttrace-local.list
sudo apt update
sudo apt install agentdfir
agenttrace --version
```

For a **hosted** apt repo, upload the same `apt-repo/` directory to any static
host (e.g. GitHub Pages) and replace the `file://` path with the URL. For anything
public, sign the `Release` with GPG and drop `[trusted=yes]`.

---

## Standard route (debhelper) — for official-style packaging

```bash
sudo apt update
sudo apt install -y build-essential debhelper dh-python \
    python3-all python3-setuptools devscripts
```

## 2. Build the .deb

From the project root (the directory that contains `debian/`):

```bash
dpkg-buildpackage -us -uc -b
# or, equivalently:
# debuild -us -uc -b
```

On success the package is written to the **parent** directory, e.g.:

```
../agentdfir_0.1.0-1_all.deb
```

## 3. Install / test the .deb locally

```bash
sudo apt install ../agentdfir_0.1.0-1_all.deb   # resolves deps automatically
# or:
sudo dpkg -i ../agentdfir_0.1.0-1_all.deb && sudo apt -f install

agenttrace --version    # should print: agenttrace 0.1.0
```

Remove it with `sudo apt remove agentdfir`.

## 4. (Optional) Host your own apt repository

This lets users `apt install` after adding your repo. A simple flat repo works:

```bash
mkdir -p apt-repo
cp ../agentdfir_0.1.0-1_all.deb apt-repo/
cd apt-repo
dpkg-scanpackages . /dev/null | gzip -9c > Packages.gz
# (optionally also produce a Release file and sign it with gpg for security)
```

Host `apt-repo/` anywhere static (e.g. GitHub Pages). Users then run:

```bash
echo "deb [trusted=yes] https://rakshanex.github.io/apt-repo ./" \
    | sudo tee /etc/apt/sources.list.d/agenttrace.list
sudo apt update
sudo apt install agentdfir
```

> `[trusted=yes]` skips signature checks — fine for testing, but for anything
> real you should sign the repo with GPG and have users add your public key.

## 5. (Optional) Official Kali / Debian inclusion

Getting into the official archives (so plain `sudo apt install` works on every
Kali box, no custom repo) is a **maintainer-review process**, not a self-serve
upload. Honest expectations:

- The tool should be **mature, useful to the security community, and ideally have
  real adoption** (users, activity). Brand-new tools are usually asked to wait.
- **Kali:** request/track tool packaging via Kali's GitLab
  (`gitlab.com/kalilinux`) — the "tools" / package request workflow. The Kali team
  reviews, packages, and decides.
- **Debian:** the package must meet Debian Policy; typically you find a Debian
  Developer to sponsor the upload, or go through the mentors.debian.net process.
- Expect iteration and review time (weeks to months), and no guarantee of
  acceptance — it is at the maintainers' discretion.

Until then, `pipx install agentdfir` (or your own apt repo above) gives Kali users
a working install today.

## Notes on consistency

- Package version (`debian/changelog` → `0.1.0-1`) tracks the upstream version in
  `pyproject.toml` (`0.1.0`). Bump both together on a new release.
- The binary package installs the `agenttrace` console script defined in
  `pyproject.toml`.
- Python ≥ 3.10 is required (declared in both `pyproject.toml` and `debian/control`).
