# Install

K.O.D.A. is distributed on PyPI as `koda-security` (the plain `koda` name
is held by an unrelated project). The import name and CLI command are
both `koda`.

## Recommended — pipx or uv

```bash
pipx install koda-security
# or
uv tool install koda-security
```

Both give you an isolated install with the `koda` command on your `PATH`.

## From source

```bash
git clone https://github.com/PabloTheThinker/K.O.D.A..git
cd K.O.D.A.
pip install -e ".[dev]"
```

## One-liner (installer script)

```bash
curl -fsSL https://raw.githubusercontent.com/PabloTheThinker/K.O.D.A./main/install.sh | sh
```

The installer supports `--update` and `--uninstall`. Inspect the script
before piping to `sh` if you're running on a production box.

## First run

```bash
koda setup        # provider + engagement + approval tier wizard
koda doctor       # sanity-check your install
koda              # start the REPL
```

## Requirements

- Python 3.11+
- At least one LLM provider: local Ollama, or an API key for Anthropic,
  OpenAI, Groq, Gemini, etc. (11 supported)
- Optional: the scanner binaries you plan to wrap (semgrep, trivy,
  gitleaks, nmap, etc.). K.O.D.A. auto-detects what's installed.

## Troubleshooting

If pytest or Python refuses to start with a `PYTHONHASHSEED` fatal error,
your shell exports a stale value:

```bash
env -u PYTHONHASHSEED koda doctor
```

Add `unset PYTHONHASHSEED` to your shell rc to make it permanent.
