#!/usr/bin/env bash
# K.O.D.A. smoke test — verifies install + core subsystems end to end.
# Safe to run on any branch; uses an isolated temp KODA_HOME so nothing
# touches the operator's real profile. Exits non-zero on first failure.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

TMP_HOME="$(mktemp -d -t koda-smoke-XXXXXX)"
trap 'rm -rf "$TMP_HOME"' EXIT

export KODA_HOME="$TMP_HOME"
export PYTHONHASHSEED=""
unset PYTHONHASHSEED

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 not found" >&2
    exit 1
fi

# We don't need a venv — run the source tree in place. This mirrors what a
# developer would do, and avoids pulling anthropic/httpx for a smoke that
# exercises stdlib-only subsystems.
export PYTHONPATH="$REPO_ROOT:${PYTHONPATH:-}"

fail() { echo "✗ $1" >&2; exit 1; }
ok()   { echo "✓ $1"; }

# --- 1. Import graph intact --------------------------------------------------
python3 -c "
import koda.cli, koda.audit, koda.auth, koda.evidence, koda.intel
from koda.security.scanners.registry import _SCANNER_MAP
from koda.security.sarif.parser import SarifLog
from koda.session.store import SessionStore
assert set(_SCANNER_MAP) >= {'semgrep','trivy','bandit','gitleaks','nuclei','osv-scanner','nmap','grype','sarif'}, _SCANNER_MAP
" || fail "import graph broken"
ok "import graph intact (core + scanners + SARIF)"

# --- 2. Engagement isolation -------------------------------------------------
python3 <<'PY' || { echo "✗ engagement isolation failed"; exit 1; }
from pathlib import Path
import os
from koda.session.store import SessionStore
from koda.audit import AuditLogger
from koda.auth import CredentialBroker, CredentialError

root = Path(os.environ["KODA_HOME"])
audit = AuditLogger(profile="smoke")
sess = SessionStore(root / "sessions.db")
creds = CredentialBroker(audit=audit)

a = sess.create(title="a", engagement="engA")
b = sess.create(title="b", engagement="engB")
assert len(sess.list_sessions(engagement="engA")) == 1
assert len(sess.list_sessions(engagement="engB")) == 1

creds.add(credential_id="api", name="A", kind="api_key",
          value="sk-live-aaaa1111bbbb2222", engagement="engA")
creds.add(credential_id="api", name="B", kind="api_key",
          value="sk-live-cccc3333dddd4444", engagement="engB")
va = creds.get_value("api", engagement="engA")
vb = creds.get_value("api", engagement="engB")
assert va != vb

try:
    creds.get_value("api", engagement="engC")
    raise SystemExit("leaked to engC")
except CredentialError:
    pass

line = "call with sk-live-aaaa1111bbbb2222 and sk-live-cccc3333dddd4444"
red = creds.redact(line)
assert "sk-live" not in red, red
audit.close()
PY
ok "engagement isolation (sessions + credentials + redaction)"

# --- 3. Evidence chain -------------------------------------------------------
python3 <<'PY' || { echo "✗ evidence chain failed"; exit 1; }
import os
from koda.evidence import EvidenceStore
store = EvidenceStore()
a1 = store.capture("alpha", tool="scan.run", engagement="engA",
                   session_id="s1", target="host.local", content_type="text")
a2 = store.capture("bravo", tool="scan.run", engagement="engA",
                   session_id="s1", target="host.local", content_type="text")
assert a1.artifact_id and a2.artifact_id, "artifacts not captured"
rep = store.verify_chain(engagement="engA")
assert rep.ok, f"chain broken: {rep.issues}"
PY
ok "evidence chain verifies"

# --- 4. SARIF + scanner registry parity -------------------------------------
python3 <<'PY' || { echo "✗ SARIF/scanner parity failed"; exit 1; }
from koda.security.scanners.registry import ScannerRegistry, _SCANNER_MAP
reg = ScannerRegistry()
detected = set(reg.installed().keys())
registered = set(_SCANNER_MAP) - {"sarif"}
missing = detected - registered
assert not missing, f"detected-but-unregistered: {missing}"
PY
ok "SARIF + scanner registry parity"

# --- 5. CLI help path compiles ----------------------------------------------
python3 -m koda --help >/dev/null || fail "koda --help failed"
ok "koda --help works"

echo ""
echo "✓ all smoke checks passed"
