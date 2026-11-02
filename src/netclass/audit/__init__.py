"""SQLite audit history (Stage 5): opt-in, append-only, privacy-conscious.

Nothing here is imported by the classification path; see ``store`` for the guarantees.
"""
from .errors import AuditError
from .retention import DEFAULT_RETENTION_DAYS
from .store import AuditStore, PurgeReport, SaveReceipt

__all__ = ["AuditError", "AuditStore", "DEFAULT_RETENTION_DAYS", "PurgeReport", "SaveReceipt"]
