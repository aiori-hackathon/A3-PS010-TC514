"""UI-free logic for the Stage 6 dashboard. No Streamlit import lives here.

This module is a thin layer over the existing Stage 5 APIs. It contains NO classification rule:
labels, reason codes and explanations always come from ``ClassificationService``.

Guarantees (pinned by tests/test_dashboard_*.py)
    * Importing this module touches no network, file or database. Heavy modules (pydantic-based
      models, the service) are imported lazily inside the functions that need them.
    * ``check_ip_input`` validates with the standard-library ``ipaddress`` module (through the
      project's own ``assess_address``) before anything else happens.
    * ``run_classification`` builds a FRESH service for every call (no shared state, no cache of
      results). Auditing happens only when ``AuditChoice.confirmed`` is True, and only through
      ``ClassificationService.classify_and_record``.
    * History functions open the database read-only and never create it.
    * Every message meant for the screen passes through ``safe_text``: configured secrets and
      token-shaped text are redacted and the length is clipped. Raw response bodies are never read.
"""
from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Optional

from ..address_policy import AddressCategory, assess_address
from ..audit import AuditError, AuditStore
from ..audit.privacy import redact_text
from ..audit.schema import LABELS

PAGE_SIZES = (10, 25, 50, 100)  # all <= the store's MAX_LIST_LIMIT, even with the +1 look-ahead
DEFAULT_PAGE_SIZE = 25
MAX_PAGE_NUMBER = 10_000
MAX_TEXT = 600

LABEL_EXPLANATIONS = {
    "Known Tor exit": (
        "The address appears in a current Tor exit list that covered the observation time."
    ),
    "Known hosted VPN/proxy endpoint": (
        "The address matches a current VPN/proxy endpoint list that covered the observation time."
    ),
    "Unknown": (
        "The available evidence does not support either of the other two labels. This is not a "
        "statement that the address is safe, malicious, or definitely not a VPN, Tor exit or "
        "proxy: sources can be incomplete, stale, unavailable or in conflict."
    ),
}

DISCLAIMER = (
    "Results reflect the evidence and source coverage available at the time of the lookup. They "
    "are not a guarantee about any person's identity or activity."
)

COLLECTION_SKIPPED_NOTE = (
    "This address is outside the globally routable unicast range, so the established policy "
    "excludes it. No evidence source and no optional context service was contacted."
)

IPV6_NOTE = (
    "IPv6 coverage is limited: not every source publishes IPv6 data, so 'Unknown' for an IPv6 "
    "address carries less weight than for IPv4."
)


# ---------------------------------------------------------------------------------------------
# Safe text
# ---------------------------------------------------------------------------------------------
def settings_secrets(settings: Any) -> tuple[str, ...]:
    """The configured secret values (never displayed; used only to redact other text)."""
    values = (
        getattr(settings, "ipinfo_token", None),
        getattr(settings, "vpn_provider_api_key", None),
    )
    return tuple(v for v in values if isinstance(v, str) and v)


def safe_text(value: Any, secrets: tuple[str, ...] = (), limit: int = MAX_TEXT) -> str:
    """Text that is safe to show: redacted, whitespace-collapsed and clipped."""
    text = "" if value is None else str(value)
    text, _ = redact_text(text, secrets)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[:limit] + "...[truncated]"
    return text


def safe_error(exc: BaseException, secrets: tuple[str, ...] = ()) -> str:
    """Exception type plus a redacted, clipped message. Never a traceback."""
    message = safe_text(str(exc), secrets, limit=300)
    return f"{type(exc).__name__}: {message}" if message else type(exc).__name__


def hide_paths(text: str, settings: Any) -> str:
    """Replace the configured database path (as written and resolved) with a neutral name."""
    try:
        raw = Path(settings.db_path)
        variants = {str(raw), str(raw.resolve()), raw.as_posix()}
    except Exception:
        return text
    for variant in sorted(variants, key=len, reverse=True):
        if variant:
            text = text.replace(variant, "<audit database>")
    return text


_ENV_KEY = re.compile(r"^[A-Z][A-Z0-9_]{2,}\b")


def describe_config_error(exc: BaseException) -> str:
    """Name the offending setting without echoing its value (values may be private)."""
    match = _ENV_KEY.match(str(exc).strip())
    if match:
        return (
            f"The setting {match.group(0)} is invalid. Check your .env file "
            "(see .env.example); its value is not shown here."
        )
    return "The configuration is invalid. Check your .env file (see .env.example)."


def load_settings_safely(
    loader: Optional[Callable[[], Any]] = None,
) -> tuple[Any, Optional[str]]:
    """(settings, None) or (None, safe message). Reads configuration only; no network or disk writes."""
    try:
        if loader is None:
            from ..config import load_settings as loader  # lazy: keeps import light
        return loader(), None
    except ImportError as exc:
        name = safe_text(getattr(exc, "name", None) or "unknown module", (), 80)
        return None, (
            f"A required package is not installed ({name}). "
            "Run: python -m pip install -r requirements.txt"
        )
    except ValueError as exc:
        return None, describe_config_error(exc)
    except Exception as exc:
        return None, f"The configuration could not be loaded ({type(exc).__name__})."


# ---------------------------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------------------------
class InputStatus(StrEnum):
    VALID = "VALID"  # globally routable: eligible for collection
    EXCLUDED = "EXCLUDED"  # valid syntax, but excluded by policy: collection is skipped
    INVALID = "INVALID"


@dataclass(frozen=True)
class InputCheck:
    status: InputStatus
    normalized: Optional[str]
    version: Optional[int]
    category: Optional[str]
    message: str

    @property
    def ok_to_collect(self) -> bool:
        return self.status is InputStatus.VALID


def check_ip_input(raw: object) -> InputCheck:
    """Validate and normalise one IPv4/IPv6 address. Never raises, never touches the network."""
    assessment = assess_address(raw if isinstance(raw, str) else "")
    if assessment.category is AddressCategory.INVALID or assessment.normalized is None:
        return InputCheck(InputStatus.INVALID, None, None, None, assessment.message)
    status = InputStatus.VALID if assessment.allowed else InputStatus.EXCLUDED
    return InputCheck(
        status, assessment.normalized, assessment.version, assessment.category.value,
        assessment.message,
    )


# ---------------------------------------------------------------------------------------------
# Audit choice and classification
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class AuditChoice:
    """The user's audit decision for ONE classification. Default: nothing is recorded."""

    wants_recording: bool = False
    acknowledged_privacy: bool = False

    @property
    def confirmed(self) -> bool:
        return self.wants_recording and self.acknowledged_privacy


@dataclass(frozen=True)
class ClassifyOptions:
    include_ripestat: bool = False
    include_ipinfo: bool = False
    audit: AuditChoice = field(default_factory=AuditChoice)


@dataclass(frozen=True)
class DashboardOutcome:
    """What the page shows. ``result`` / ``audit`` are the existing service models, unchanged."""

    check: InputCheck
    result: Any = None  # netclass.service.ServiceResult, or None when no result exists
    audit: Any = None  # netclass.service.AuditOutcome, or None when recording was not requested
    error: Optional[str] = None  # safe, non-sensitive message
    error_kind: Optional[str] = None  # "invalid_input" | "dependency" | "classification"
    collection_skipped: bool = False
    skipped_reason: Optional[str] = None


ServiceFactory = Callable[[Any], Any]


def _default_factory(settings: Any) -> Any:
    from ..service import ClassificationService  # lazy: needs pydantic

    return ClassificationService.from_settings(settings)


def run_classification(
    raw_ip: object,
    options: ClassifyOptions,
    *,
    settings: Any,
    service_factory: Optional[ServiceFactory] = None,
    now: Optional[Callable[[], datetime]] = None,
) -> DashboardOutcome:
    """Validate, then classify through the existing ``ClassificationService``.

    ``settings`` is a ``netclass.config.Settings``. The audit setting is forced to match the
    user's confirmed choice for this call only, so an environment value can never cause a silent
    write and the service never builds an audit store unless the user opted in.
    """
    secrets = settings_secrets(settings)
    check = check_ip_input(raw_ip)
    if check.status is InputStatus.INVALID:
        return DashboardOutcome(
            check, error=safe_text(check.message, secrets), error_kind="invalid_input"
        )

    audit_on = options.audit.confirmed
    run_settings = dataclasses.replace(settings, audit_enabled=audit_on)
    skipped = check.status is InputStatus.EXCLUDED
    # Conservative preflight: an excluded address never asks for optional lookups.
    use_ripestat = options.include_ripestat and not skipped
    use_ipinfo = options.include_ipinfo and not skipped

    try:
        from ..models import Observation  # lazy: needs pydantic
        from ..service import AuditedResult

        observed_at = (now or (lambda: datetime.now(timezone.utc)))()
        observation = Observation(ip=check.normalized, observed_at=observed_at)
        service = (service_factory or _default_factory)(run_settings)
        audit_outcome = None
        if audit_on:
            audited = service.classify_and_record(
                observation, include_ripestat=use_ripestat, include_ipinfo=use_ipinfo
            )
            if not isinstance(audited, AuditedResult):  # defensive: a replacement service
                raise TypeError("unexpected audited result type")
            result, audit_outcome = audited.result, audited.audit
        else:
            result = service.classify(
                observation, include_ripestat=use_ripestat, include_ipinfo=use_ipinfo
            )
    except ImportError as exc:
        return DashboardOutcome(
            check,
            error=(
                "A required package is not installed ("
                f"{safe_text(getattr(exc, 'name', None) or 'unknown module', secrets, 80)}). "
                "Run: python -m pip install -r requirements.txt"
            ),
            error_kind="dependency",
        )
    except Exception as exc:  # classification problems are shown, never turned into evidence
        return DashboardOutcome(
            check,
            error=(
                "The classification could not be completed. No label was produced and nothing "
                f"was inferred from the failure. (error type: {type(exc).__name__}; run "
                "scripts/classify_ip.py for details)"
            ),
            error_kind="classification",
        )

    return DashboardOutcome(
        check,
        result=result,
        audit=audit_outcome,
        collection_skipped=skipped,
        skipped_reason=COLLECTION_SKIPPED_NOTE if skipped else None,
    )


# ---------------------------------------------------------------------------------------------
# Result presentation helpers (plain data for the page; no policy here)
# ---------------------------------------------------------------------------------------------
def evidence_rows(result: Any, secrets: tuple[str, ...] = ()) -> list[dict[str, str]]:
    """One row per evidence record, joined with the classifier's assessment of it."""
    assessments = {
        (a.source_name, a.kind): a for a in result.classification.evidence_assessments
    }
    rows = []
    for record in result.evidence:
        a = assessments.get((record.source_name, record.kind))
        rows.append(
            {
                "Source": safe_text(record.source_name, secrets, 120),
                "Kind": record.kind.value,
                "Status": record.status.value,
                "Applicability": a.applicability.value if a else "",
                "Retrieved (UTC)": record.retrieved_at.isoformat(timespec="seconds"),
                "Assessment": safe_text(a.note if a else "", secrets),
                "Error": safe_text(record.error, secrets),
                "Limitations": safe_text("; ".join(record.limitations), secrets),
            }
        )
    return rows


def ripestat_rows(context: Any, secrets: tuple[str, ...] = ()) -> list[dict[str, str]]:
    """Key facts of a RIPEstat context for display. Context only."""
    if context is None:
        return []
    rows = [{"Field": "Status", "Value": context.status.value}]
    if context.note:
        rows.append({"Field": "Note", "Value": safe_text(context.note, secrets)})
    if context.error:
        rows.append({"Field": "Error", "Value": safe_text(context.error.message, secrets)})
    if context.routing is not None:
        rows.append({"Field": "Routing status", "Value": context.routing.status.value})
        if context.routing.prefix:
            rows.append({"Field": "Prefix", "Value": safe_text(context.routing.prefix, secrets, 80)})
        if context.routing.asns:
            rows.append(
                {"Field": "Origin ASN(s)", "Value": ", ".join(f"AS{n}" for n in context.routing.asns)}
            )
    for holder in context.holders:
        label = f"AS{holder.asn} holder"
        rows.append({"Field": label, "Value": safe_text(holder.holder or "(not reported)", secrets, 200)})
    return rows


def ipinfo_rows(metadata: Any, secrets: tuple[str, ...] = ()) -> list[dict[str, str]]:
    """Key facts of IPinfo Lite metadata for display. Context only."""
    if metadata is None:
        return []
    rows = [{"Field": "Status", "Value": metadata.status.value}]
    if metadata.note:
        rows.append({"Field": "Note", "Value": safe_text(metadata.note, secrets)})
    if metadata.error:
        rows.append({"Field": "Error", "Value": safe_text(metadata.error.message, secrets)})
    for name, value in (
        ("ASN", f"AS{metadata.asn}" if metadata.asn is not None else None),
        ("AS name", metadata.as_name),
        ("AS domain", metadata.as_domain),
        ("Country", metadata.country),
        ("Country code", metadata.country_code),
        ("Continent", metadata.continent),
    ):
        if value:
            rows.append({"Field": name, "Value": safe_text(value, secrets, 200)})
    return rows


def audit_message(audit: Any, settings: Any = None) -> tuple[str, str]:
    """(level, text) for an AuditOutcome. 'success' only when the transaction committed."""
    status = audit.status.value
    if status == "SAVED":
        return "success", f"Saved to the local audit history as run #{audit.run_id}."
    if status == "FAILED":
        return (
            "warning",
            "The classification above is valid, but the audit record was NOT saved. "
            f"Reason: {hide_paths(safe_text(audit.error), settings) if settings else safe_text(audit.error)}",
        )
    return "info", "Audit recording is not active; nothing was written."


# ---------------------------------------------------------------------------------------------
# Audit history (read-only)
# ---------------------------------------------------------------------------------------------
class HistoryState(StrEnum):
    READY = "READY"  # database exists and is readable (it may still contain zero runs)
    NO_DATABASE = "NO_DATABASE"  # file does not exist; nothing was created
    UNAVAILABLE = "UNAVAILABLE"  # exists but cannot be read (wrong format, newer schema, ...)


@dataclass(frozen=True)
class HistoryStatus:
    state: HistoryState
    message: str
    runs: Optional[int] = None
    schema_version: Optional[int] = None


def open_store(settings: Any) -> AuditStore:
    """A store for the configured path. Constructing it touches no file."""
    return AuditStore(settings.db_path, secrets=settings_secrets(settings))


def history_status(settings: Any, store: Optional[AuditStore] = None) -> HistoryStatus:
    """Whether the history can be read. Never creates or modifies the database."""
    store = store or open_store(settings)
    secrets = settings_secrets(settings)
    if not store.path.exists():
        if settings.audit_enabled:
            msg = (
                "No audit database exists yet. NETCLASS_AUDIT_ENABLED is set, but the dashboard "
                "still records nothing until you opt in for a classification."
            )
        else:
            msg = (
                "Audit recording is off and no audit database exists. Nothing has been created. "
                "Opt in when classifying to start a local history."
            )
        return HistoryStatus(HistoryState.NO_DATABASE, msg)
    try:
        info = store.info()
    except AuditError as exc:
        return HistoryStatus(
            HistoryState.UNAVAILABLE,
            f"The audit database cannot be read: {hide_paths(safe_text(exc, secrets, 200), settings)}",
        )
    except Exception as exc:
        return HistoryStatus(
            HistoryState.UNAVAILABLE,
            f"The audit database cannot be read ({type(exc).__name__}).",
        )
    return HistoryStatus(
        HistoryState.READY,
        "Audit database is readable.",
        runs=info.get("runs"),
        schema_version=info.get("schema_version"),
    )


@dataclass(frozen=True)
class HistoryPage:
    state: HistoryState
    message: str
    rows: list[dict[str, Any]] = field(default_factory=list)
    page: int = 1
    page_size: int = DEFAULT_PAGE_SIZE
    has_next: bool = False
    filter_error: Optional[str] = None


def read_history(
    settings: Any,
    *,
    label: Optional[str] = None,
    ip: Optional[str] = None,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    store: Optional[AuditStore] = None,
) -> HistoryPage:
    """One bounded page of runs, newest first. Read-only; filters are exact and parameterised.

    ``label`` must be one of the three labels (or None) and ``ip`` must be a valid address
    (or blank); the store binds both as SQL parameters. Free text never reaches SQL.
    """
    page_size = page_size if page_size in PAGE_SIZES else DEFAULT_PAGE_SIZE
    page = min(max(int(page), 1), MAX_PAGE_NUMBER)
    secrets = settings_secrets(settings)
    store = store or open_store(settings)

    if label is not None and label not in LABELS:
        return HistoryPage(
            HistoryState.READY, "", page=page, page_size=page_size,
            filter_error="Unknown classification label filter.",
        )
    ip_filter: Optional[str] = None
    if ip is not None and ip.strip():
        check = check_ip_input(ip)
        if check.status is InputStatus.INVALID:
            return HistoryPage(
                HistoryState.READY, "", page=page, page_size=page_size,
                filter_error=f"IP filter rejected: {safe_text(check.message, secrets, 200)}",
            )
        ip_filter = check.normalized

    status = history_status(settings, store)
    if status.state is not HistoryState.READY:
        return HistoryPage(status.state, status.message, page=page, page_size=page_size)

    try:
        # One extra row tells us whether a next page exists without a COUNT query.
        runs = store.list_runs(
            ip=ip_filter, label=label, limit=page_size + 1, offset=(page - 1) * page_size
        )
    except AuditError as exc:
        return HistoryPage(
            HistoryState.UNAVAILABLE,
            f"The audit history could not be read: {hide_paths(safe_text(exc, secrets, 200), settings)}",
            page=page, page_size=page_size,
        )
    except Exception as exc:
        return HistoryPage(
            HistoryState.UNAVAILABLE,
            f"The audit history could not be read ({type(exc).__name__}).",
            page=page, page_size=page_size,
        )
    has_next = len(runs) > page_size
    return HistoryPage(
        HistoryState.READY, "", rows=runs[:page_size], page=page, page_size=page_size,
        has_next=has_next,
    )


def history_table(rows: list[dict[str, Any]], secrets: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    return [
        {
            "Run": r["run_id"],
            "Saved (UTC)": safe_text(r["recorded_at"], secrets, 40),
            "Observed (UTC)": safe_text(r["observed_at"], secrets, 40),
            "IP": safe_text(r["ip"], secrets, 60),
            "Label": r["label"],
            "Reason": r["reason_code"],
            "Policy": safe_text(r["policy_version"], secrets, 40),
            "Service": safe_text(r["service_version"], secrets, 40),
            "RIPEstat requested": "yes" if r["ripestat_requested"] else "no",
            "IPinfo requested": "yes" if r["ipinfo_requested"] else "no",
        }
        for r in rows
    ]


def read_run_detail(
    settings: Any, run_id: int, *, store: Optional[AuditStore] = None
) -> Optional[dict[str, Any]]:
    """One full record (evidence and context kept separate), or None. Read-only."""
    store = store or open_store(settings)
    if history_status(settings, store).state is not HistoryState.READY:
        return None
    try:
        return store.get_run(int(run_id))
    except Exception:
        return None


def detail_evidence_rows(detail: dict[str, Any], secrets: tuple[str, ...] = ()) -> list[dict[str, str]]:
    return [
        {
            "Source": safe_text(e["source_name"], secrets, 120),
            "Kind": e["kind"],
            "Status": e["status"],
            "Applicability": e["applicability"] or "",
            "Retrieved (UTC)": safe_text(e["retrieved_at"], secrets, 40),
            "Assessment": safe_text(e["assessment_note"], secrets),
            "Error": safe_text(e["error"], secrets),
        }
        for e in detail.get("evidence", [])
    ]


_CONTEXT_FIELDS = {
    "ripestat": ("status", "note"),
    "ipinfo": ("status", "asn", "as_name", "country_code", "note"),
}


def detail_context_rows(detail: dict[str, Any], secrets: tuple[str, ...] = ()) -> list[dict[str, str]]:
    """A short summary of stored context metadata (whitelisted fields only; never raw JSON)."""
    rows = []
    for item in detail.get("context_metadata", []):
        payload = item.get("payload") or {}
        parts = []
        for key in _CONTEXT_FIELDS.get(item["provider"], ("status",)):
            value = payload.get(key)
            if value not in (None, ""):
                parts.append(f"{key}={safe_text(value, secrets, 120)}")
        if item["provider"] == "ripestat":
            routing = payload.get("routing") or {}
            if routing.get("prefix"):
                parts.append(f"prefix={safe_text(routing['prefix'], secrets, 80)}")
            if routing.get("asns"):
                parts.append("asns=" + ",".join(str(n) for n in routing["asns"][:5]))
        rows.append(
            {
                "Provider": item["provider"],
                "Status": safe_text(item["status"], secrets, 60),
                "Requested (UTC)": safe_text(item["requested_at"], secrets, 40),
                "Summary (context only)": "; ".join(parts),
            }
        )
    return rows


# ---------------------------------------------------------------------------------------------
# Diagnostics (no network, no database creation)
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Diagnostics:
    app_version: str
    policy_version: str
    service_version: str
    enabled_sources: tuple[str, ...]
    ipinfo_configured: bool
    ripestat_available: bool
    audit_env_enabled: bool
    retention_days: int
    retention_note: str
    database_file: str  # file name only
    history: HistoryStatus


def collect_diagnostics(settings: Any, store: Optional[AuditStore] = None) -> Diagnostics:
    from .. import __version__

    try:  # these two live in pydantic-based modules; degrade instead of failing the page
        from ..classifier import POLICY_VERSION as policy
    except ImportError:
        policy = "unavailable (dependency not installed)"
    try:
        from ..service import SERVICE_VERSION as service
    except ImportError:
        service = "unavailable (dependency not installed)"
    keeps_forever = settings.audit_retention_days == 0
    return Diagnostics(
        app_version=__version__,
        policy_version=policy,
        service_version=service,
        enabled_sources=tuple(settings.enabled_sources),
        ipinfo_configured=bool(settings.ipinfo_token),
        ripestat_available=True,
        audit_env_enabled=bool(settings.audit_enabled),
        retention_days=settings.audit_retention_days,
        retention_note=(
            "keep indefinitely"
            if keeps_forever
            else "records older than this are deleted only by the manual purge command"
        ),
        database_file=Path(settings.db_path).name,
        history=history_status(settings, store),
    )
