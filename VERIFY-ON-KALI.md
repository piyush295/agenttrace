# Verifying AgentTrace on a real Kali / Debian box

This is a step-by-step checklist to validate the package on an actual
Kali/Debian/Ubuntu machine (things that could not be fully checked in the
development environment — notably `lintian` and a real `apt install`).

Run these on the target box. Expected output is shown after each step.

---

## 1. Get the source

```bash
git clone https://github.com/rakshanex/agenttrace.git
cd agenttrace
```

## 2. Install build tooling + linters

```bash
sudo apt update
sudo apt install -y build-essential debhelper dh-python \
    python3-all python3-setuptools devscripts lintian pipx
```

## 3. Build the .deb (standard debhelper route)

```bash
dpkg-buildpackage -us -uc -b
```
Expected: builds without error; the package appears in the parent dir:
```
../agentdfir_0.1.0-1_all.deb
```
If build-deps are missing, `dpkg-buildpackage` will name them — install and retry.

## 4. Run lintian (Debian policy check)

```bash
lintian ../agentdfir_0.1.0-1_all.deb
# or, more thorough, against the .changes:
lintian -i -I ../agentdfir_0.1.0-1_*.changes
```
Expected: no `E:` (errors). Some `W:`/`I:` (warnings/info) are common for a first
package — read them with `lintian -i` (it explains each) and address the ones that
matter for your submission. Note any that remain and why.

## 5. Install the .deb and run it

```bash
sudo apt install ../agentdfir_0.1.0-1_all.deb
agenttrace --version           # -> agenttrace 0.1.0
man agenttrace                 # manpage should open

# quick functional check on synthetic data
python3 -m tests.synthetic /tmp/demo
agenttrace detect /tmp/demo/*.json /tmp/demo/*.jsonl
```
Expected: version prints, manpage opens, and `detect` reports attack patterns.

Remove afterwards if you like: `sudo apt remove agentdfir`.

## 6. Test the signed apt repo end-to-end

```bash
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://rakshanex.github.io/apt/agenttrace-archive-keyring.asc \
  | sudo gpg --dearmor -o /etc/apt/keyrings/agenttrace.gpg

echo "deb [signed-by=/etc/apt/keyrings/agenttrace.gpg] https://rakshanex.github.io/apt ./" \
  | sudo tee /etc/apt/sources.list.d/agenttrace.list

sudo apt update
sudo apt install agentdfir
agenttrace --version
```
Expected: `apt update` succeeds with **no signature/GPG errors** (proves the repo
signature verifies against the published key), then `agentdfir` installs.

Cleanup:
```bash
sudo rm /etc/apt/sources.list.d/agenttrace.list /etc/apt/keyrings/agenttrace.gpg
sudo apt update
```

## 7. (Optional) pipx path

```bash
pipx install agentdfir
agenttrace --version
```

---

## Troubleshooting

- **`apt update` GPG error (NO_PUBKEY / not signed):** the key wasn't added to
  `/etc/apt/keyrings/agenttrace.gpg`, or `signed-by=` path is wrong. Re-run step 6.
- **`error: externally-managed-environment` on `pip install`:** use `pipx` (step 7)
  or the apt/.deb route — this is expected on modern Debian/Kali (PEP 668).
- **lintian errors:** run `lintian -i ../agentdfir_0.1.0-1_*.changes` for detailed
  explanations; fix `E:` entries before an official submission.
- **`dpkg-buildpackage: Unmet build dependencies`:** install the listed packages
  (see step 2) and rebuild.

## What this confirms

Passing steps 3–6 confirms the package builds cleanly, is policy-checked by
lintian, installs via both a direct `.deb` and the signed `apt` repository, and
the `agenttrace` command works — i.e. the full distribution path is real on Kali.
