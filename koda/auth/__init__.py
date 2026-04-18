"""Credential broker — per-engagement auth vault with redaction + cooldown."""
from .broker import (
    Credential,
    CredentialBroker,
    CredentialError,
    CredentialHealth,
    NullCredentialBroker,
    default_credentials_path,
    looks_like_placeholder,
)

__all__ = [
    "Credential",
    "CredentialBroker",
    "CredentialError",
    "CredentialHealth",
    "NullCredentialBroker",
    "default_credentials_path",
    "looks_like_placeholder",
]
