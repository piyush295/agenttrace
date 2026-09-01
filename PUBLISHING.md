# Publishing AgentTrace

Publishing to PyPI makes the tool installable with `pip install agenttrace` and
indexes it on PyPI (a major discoverability channel). **You** run these steps —
they require your own PyPI account and API token, which should never be shared.

## 1. Prerequisites (one time)

- A PyPI account: https://pypi.org/account/register/
- A PyPI API token: https://pypi.org/manage/account/token/ (scope: entire account
  for the first upload, or project-scoped afterwards)
- Build/upload tooling:

```bash
python3 -m pip install --upgrade build twine
```

> Note: the package name `agenttrace` must be available on PyPI. If it is taken,
> pick a unique name (e.g. `agenttrace-dfir`) and update `name` in `pyproject.toml`.

## 2. Build the distributions

```bash
cd /path/to/agenttrace
rm -rf dist build *.egg-info
python3 -m build          # produces dist/*.whl and dist/*.tar.gz
```

## 3. Check the artifacts

```bash
python3 -m twine check dist/*
```

## 4. (Recommended) Upload to TestPyPI first

```bash
python3 -m twine upload --repository testpypi dist/*
# then verify install:
python3 -m pip install --index-url https://test.pypi.org/simple/ agenttrace
```

## 5. Upload to PyPI

```bash
python3 -m twine upload dist/*
```

When prompted:
- Username: `__token__`
- Password: your PyPI API token (starts with `pypi-...`) — paste it in the
  terminal only, never in chat or a file committed to git.

## 6. Verify

```bash
pip install agenttrace
agenttrace --version
```

## Releasing a new version

1. Bump `version` in `pyproject.toml` and `agenttrace/__init__.py`.
2. Add a `CHANGELOG.md` entry.
3. Tag and create a GitHub release: `gh release create vX.Y.Z`.
4. Rebuild and `twine upload dist/*`.
