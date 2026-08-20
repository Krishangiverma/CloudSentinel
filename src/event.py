"""
Compatibility module for CloudSentinel.

The main SecurityEvent model is defined in:
src/models/event.py

This module re-exports it so older imports such as
'from event import SecurityEvent' continue to work.
"""

from models.event import SecurityEvent

__all__ = ["SecurityEvent"]
