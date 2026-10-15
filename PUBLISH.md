# Publishing Sleuth to PyPI

Everything is prepared — `pyproject.toml`, the `sleuth` console command,
and the built `dist/` files. The actual upload needs **your** PyPI account,
so these last steps are yours (about 5 minutes).

## Step 1 — Create a PyPI account

Go to **https://pypi.org/account/register/** and sign up.
Then go to **Account settings → API tokens → Add API token**:
- Token name: `sleuth-upload`
- Scope: **Entire account** (first release) — you can narrow it later.
- **Copy the token now** — PyPI shows it only once. It starts with `pypi-`.

## Step 2 — Install twine

```
pip install twine
```

## Step 3 — Build fresh dist files

From the `sleuth` project folder:

```
python -m build
```

This recreates `dist/sleuth_sec-0.4.0.tar.gz` and
`dist/sleuth_sec-0.4.0-py3-none-any.whl`.

## Step 4 — Upload (token, never password)

```
twine upload dist/*
```

When asked for a username, type `__token__` (literally, with underscores).
When asked for a password, paste your API token (`pypi-...`).
Never use your real PyPI password here.

After upload, your package lives at:
**https://pypi.org/project/sleuth-sec/**
and anyone can install it with:

```
pip install sleuth-sec
```

## Step 5 — If something goes wrong

**Name conflict** ("This project already exists"):
PyPI names are first-come-first-served. Pick a new name in
`pyproject.toml` (`name = "..."`), rebuild (`python -m build`),
and upload again. Check availability first:
`https://pypi.org/pypi/<name>/json` — a **404** means it's free.

**Version bump** (releasing 0.4.1, 0.5.0, ...):
PyPI never lets you re-upload the same version number.
Change `version = "0.4.1"` in `pyproject.toml`, rebuild, upload.

**Upload failed midway**: safe to just run `twine upload dist/*` again —
already-uploaded files are skipped.

## Optional: test on TestPyPI first (recommended for the first release)

```
twine upload --repository testpypi dist/*
pip install --index-url https://test.pypi.org/simple/ sleuth-sec
```

This publishes to the sandbox https://test.pypi.org so you can verify the
install works before going live. Needs a separate free account on
test.pypi.org and a second API token.
