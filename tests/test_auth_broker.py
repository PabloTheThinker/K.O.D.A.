"""Unit tests for koda.auth.broker — per-engagement credential vault."""
from __future__ import annotations

import time

import pytest

from koda.auth.broker import (
    CredentialBroker,
    CredentialError,
    looks_like_placeholder,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def broker(tmp_path):
    """Fresh broker backed by a temp directory."""
    b = CredentialBroker(path=tmp_path / "creds")
    yield b
    b.close()


def _add(broker: CredentialBroker, *, cred_id: str = "k1", engagement: str = "eng-a") -> str:
    """Helper: store a real-looking API key and return the cred_id."""
    broker.add(
        credential_id=cred_id,
        name="Test Key",
        kind="api_key",
        value="supersecretkey-ABCDEF123456",
        engagement=engagement,
    )
    return cred_id


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_add_and_get_roundtrip(broker):
    """Stored credential is retrievable with matching metadata."""
    cred = broker.add(
        credential_id="mykey",
        name="My Key",
        kind="bearer",
        value="verylongandsecretbearertoken12345",
        engagement="eng-x",
        metadata={"scope": "read"},
    )
    assert cred.credential_id == "mykey"
    assert cred.kind == "bearer"
    assert cred.engagement == "eng-x"
    assert cred.metadata["scope"] == "read"

    fetched = broker.get("mykey", "eng-x")
    assert fetched.credential_id == cred.credential_id
    assert fetched.name == "My Key"


def test_get_value_returns_secret(broker):
    """get_value() returns the exact secret that was stored."""
    secret = "supersecretkey-ABCDEF123456"
    broker.add(
        credential_id="k1",
        name="K1",
        kind="api_key",
        value=secret,
        engagement="eng-a",
    )
    assert broker.get_value("k1", "eng-a") == secret


# ---------------------------------------------------------------------------
# Placeholder detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "your-api-key-here",
        "YOUR_API_KEY_HERE",
        "XXXXXXXXXXXXXXXXXX",
        "000000000000000000",
        "xxxxxxxxxxxxxxxxxxxx",
        "<replace-me>",
        "placeholder",
        "none",
        "short",          # under _MIN_KEY_LENGTH
        "   ",            # whitespace only
    ],
)
def test_looks_like_placeholder_true(value: str):
    assert looks_like_placeholder(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "supersecretkey-ABCDEF123456",
        "sk-proj-REALTOKEN12345678901",
        "eyJhbGciOiJIUzI1NiJ9.real.token",
    ],
)
def test_looks_like_placeholder_false(value: str):
    assert looks_like_placeholder(value) is False


def test_add_rejects_placeholder(broker):
    """Storing a placeholder value raises CredentialError."""
    with pytest.raises(CredentialError, match="placeholder"):
        broker.add(
            credential_id="bad",
            name="Bad",
            kind="api_key",
            value="your-api-key-here",
            engagement="eng-a",
        )


# ---------------------------------------------------------------------------
# Cooldown / failure path
# ---------------------------------------------------------------------------


def test_mark_broken_blocks_get_value(broker):
    """After mark_broken, get_value raises CredentialError for the cooldown window."""
    _add(broker, cred_id="k1", engagement="eng-a")
    broker.mark_broken("k1", "eng-a", cooldown_seconds=9999, detail="auth rejected")

    with pytest.raises(CredentialError, match="cooldown"):
        broker.get_value("k1", "eng-a")


def test_healthy_false_while_cooling(broker):
    """healthy() reports False while the cred is in cooldown."""
    _add(broker)
    broker.mark_broken("k1", "eng-a", cooldown_seconds=9999)
    assert broker.healthy("k1", "eng-a") is False


def test_healthy_true_after_expiry(broker):
    """healthy() returns True once the cooldown window passes (minimal window = 1s)."""
    _add(broker)
    # Set cooldown_seconds=1 and backdoor the internal time by setting a past deadline.
    broker.mark_broken("k1", "eng-a", cooldown_seconds=1)
    # Force expiry by writing a past timestamp directly.
    broker._cooldowns[("eng-a", "k1")] = time.time() - 1
    assert broker.healthy("k1", "eng-a") is True


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


def test_redact_masks_secret_in_output(broker):
    """redact() replaces the literal secret with a label in transcript text."""
    secret = "supersecretkey-ABCDEF123456"
    _add(broker)  # default uses this secret
    # Calling get_value registers the secret for redaction.
    broker.get_value("k1", "eng-a")
    transcript = f"nmap -sV --api-key={secret} target.example.com"
    redacted = broker.redact(transcript)
    assert secret not in redacted
    assert "[REDACTED" in redacted


def test_redact_no_op_when_secret_absent(broker):
    """redact() leaves innocent text untouched when no secrets are registered."""
    # get_value is never called, so no redactions are registered.
    text = "open ports: 22, 80, 443"
    assert broker.redact(text) == text


def test_register_redaction_manual(broker):
    """Manually registered literals are also scrubbed by redact()."""
    broker.register_redaction("MYTOKEN1234567890", "[REDACTED manual-token]")
    out = broker.redact("Authorization: Bearer MYTOKEN1234567890")
    assert "MYTOKEN1234567890" not in out


# ---------------------------------------------------------------------------
# Engagement isolation
# ---------------------------------------------------------------------------


def test_engagement_isolation(broker):
    """A credential stored under eng-a is not visible from eng-b."""
    broker.add(
        credential_id="shared-name",
        name="Client A Key",
        kind="api_key",
        value="clientAsecretkey-XYZ1234567890",
        engagement="eng-a",
    )
    broker.add(
        credential_id="shared-name",
        name="Client B Key",
        kind="api_key",
        value="clientBsecretkey-XYZ1234567890",
        engagement="eng-b",
    )

    val_a = broker.get_value("shared-name", "eng-a")
    val_b = broker.get_value("shared-name", "eng-b")
    assert val_a != val_b
    assert "clientA" in val_a
    assert "clientB" in val_b


def test_missing_cred_raises(broker):
    """Requesting an unknown credential raises CredentialError."""
    with pytest.raises(CredentialError):
        broker.get("no-such-key", "eng-a")
