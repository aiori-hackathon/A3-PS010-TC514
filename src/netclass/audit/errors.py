"""Error type of the audit package.

An ``AuditError`` always means "the audit history could not be read or written".
Its message is written by this package (or is a redacted, clipped description of a
lower-level error) and never contains record contents.
"""
from __future__ import annotations


class AuditError(Exception):
    """The audit database is unusable, refused, or an operation on it failed."""
