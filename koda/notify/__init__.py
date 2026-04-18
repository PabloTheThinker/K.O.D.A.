"""Alert channels for K.O.D.A. — push notifications for scan results,
critical findings, and session events.

Stdlib-only. Channels are opt-in via the setup wizard and read their
credentials from ~/.koda/secrets.env.
"""
from .telegram import TelegramNotifier, send_telegram

__all__ = ["TelegramNotifier", "send_telegram"]
