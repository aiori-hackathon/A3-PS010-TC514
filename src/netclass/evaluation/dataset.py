"""Evaluation dataset: strict schema, loader and validator (standard library only).

A dataset is one JSON file with two kinds of cases, which are NEVER mixed in metrics:

* ``synthetic``: the evidence is a fixture "world" described in the same file, and the
  expected label follows from the documented policy by construction. These cases test policy
  conformance and wiring. They say nothing about real-world accuracy.
* ``reference``: an independently sourced, timestamped label. Every labeled reference case must
  carry complete provenance (source, retrieval time, temporal scope, basis, limitations,
  confidence). Version 1 of the shipped dataset contains NO reference cases.

Validation is strict and reports every problem it finds in one ``DatasetError``:
malformed or duplicate keys, unknown keys, duplicate case ids, invalid labels / reason codes /
IP addresses / timestamps (timezone-aware ISO 8601 only), missing reference provenance, a
reference label taken from one of the evaluated sources (circular), and current-only evidence
presented as historical ground truth.

This module imports no pydantic, no network code and nothing from the audit package.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ..address_policy import AddressCategory, assess_address

SCHEMA_VERSION = "ps010-eval-dataset-1"

# The three labels and the reason codes. Duplicated here only so this module stays free of
# pydantic; tests/test_evaluation_dataset.py pins them to netclass.models.
LABELS = ("Known Tor exit", "Known hosted VPN/proxy endpoint", "Unknown")
REASON_CODES = (
    "TOR_EXIT_MATCH",
    "VPN_PROXY_ENDPOINT_MATCH",
    "UNKNOWN_EXCLUDED_ADDRESS",
    "UNKNOWN_CONFLICTING_EVIDENCE",
    "UNKNOWN_SOURCE_UNAVAILABLE",
    "UNKNOWN_STALE_EVIDENCE",
    "UNKNOWN_PROVIDER_NOT_CONFIGURED",
    "UNKNOWN_HOSTING_ONLY",
    "UNKNOWN_NO_QUALIFYING_MATCH",
)
# Names of the three evidence sources the classifier consumes (pinned to netclass.sources).
CLASSIFIER_SOURCE_NAMES = ("tor-project-bulk-exit-list", "x4bnet-lists-vpn", "az0-vpn-ip")
SOURCE_KEYS = {
    "tor": "tor-project-bulk-exit-list",
    "x4bnet": "x4bnet-lists-vpn",
    "az0": "az0-vpn-ip",
}
# URL fragments of the evaluated sources: a reference label may not be taken from them.
_CIRCULAR_URL_FRAGMENTS = ("check.torproject.org/torbulkexitlist", "x4bnet/lists_vpn", "az0/vpn_ip")
AZ0_FILES = ("expressvpn.txt", "hideme.txt", "hideme_api.txt", "nordvpn_api.txt", "pia.txt")
SOURCE_STATES = ("ok", "http_error", "timeout", "malformed", "empty")
TIERS = ("synthetic", "reference")
CATEGORIES = (
    "known_tor_exit",
    "known_vpn_proxy",
    "no_match",
    "conflicting_evidence",
    "source_unavailable",
    "source_not_configured",
    "stale_or_historical",
    "excluded_address",
    "ipv6_coverage",
    "apple_private_relay",
    "unlabeled",
)
REFERENCE_SOURCE_TYPES = (
    "independent_measurement",
    "operator_attestation",
    "provider_documentation",
    "published_dataset",
)
CONFIDENCE_LEVELS = ("high", "medium", "low", "unstated")
TEMPORAL_SUPPORT = ("current-only", "time-bounded")
# Mirrors classifier.DEFAULT_CURRENT_TOLERANCE (pinned by a test): a current-only statement
# supports an observation only within this distance of its retrieval time.
CURRENT_ONLY_TOLERANCE_SECONDS = 3600
MIN_PREFIX_V4 = 8  # mirrors parsers.MIN_PREFIX_V4 / MIN_PREFIX_V6
MIN_PREFIX_V6 = 16

_CASE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
_WORLD_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,47}$")


class DatasetError(ValueError):
    """The dataset is invalid. ``problems`` lists every problem found."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = list(problems)
        shown = "; ".join(self.problems[:5])
        more = f" (+{len(self.problems) - 5} more)" if len(self.problems) > 5 else ""
        super().__init__(f"invalid evaluation dataset: {shown}{more}")


@dataclass(frozen=True)
class Case:
    case_id: str
    tier: str
    category: str
    ip: str  # as written in the dataset
    ip_normalized: str
    observed_at: datetime  # UTC
    expected_label: Optional[str]  # None = unlabeled: never scored as right or wrong
    expected_reason_code: Optional[str]
    world: Optional[str]
    rationale: Optional[str]
    reference: Optional[dict]
    unlabeled_reason: Optional[str]
    notes: Optional[str]


@dataclass(frozen=True)
class Dataset:
    schema_version: str
    dataset_id: str
    dataset_version: str
    description: str
    evaluation_time: datetime  # UTC; the fixed clock of every offline (replay) run
    limitations: tuple[str, ...]
    worlds: dict
    cases: tuple[Case, ...]  # sorted by case_id
    sha256: str  # of the canonical JSON of the whole file (platform independent)

    def cases_of_tier(self, tier: str) -> tuple[Case, ...]:
        return tuple(c for c in self.cases if c.tier == tier)


# --------------------------------------------------------------------------
# hashing and loading
# --------------------------------------------------------------------------
def canonical_json(obj: Any) -> str:
    """Key-sorted, whitespace-free, ASCII JSON: identical on every platform."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_of_object(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name} is not allowed")


def load_dataset(path: Path | str) -> Dataset:
    """Read and validate a dataset file. Raises DatasetError for anything wrong."""
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise DatasetError([f"cannot read dataset file: {type(exc).__name__}"]) from None
    try:
        text = raw.decode("utf-8-sig")
        obj = json.loads(
            text, object_pairs_hook=_no_duplicate_keys, parse_constant=_reject_constant
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise DatasetError([f"dataset is not valid JSON: {exc}"]) from None
    return parse_dataset(obj)


# --------------------------------------------------------------------------
# field helpers
# --------------------------------------------------------------------------
def _check_keys(obj: Any, *, required: set, optional: set, where: str, problems: list) -> bool:
    if not isinstance(obj, dict):
        problems.append(f"{where}: must be a JSON object")
        return False
    ok = True
    for key in sorted(required - obj.keys()):
        problems.append(f"{where}: missing required field {key!r}")
        ok = False
    for key in sorted(obj.keys() - required - optional):
        problems.append(f"{where}: unknown field {key!r}")
        ok = False
    return ok


def _text(value: Any, where: str, problems: list, *, allow_none: bool = False) -> Optional[str]:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or not value.strip():
        problems.append(f"{where}: must be a non-empty string")
        return None
    return value


def _timestamp(value: Any, where: str, problems: list) -> Optional[datetime]:
    if not isinstance(value, str):
        problems.append(f"{where}: timestamp must be a string")
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        problems.append(f"{where}: {value!r} is not an ISO 8601 timestamp")
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        problems.append(f"{where}: {value!r} has no UTC offset (naive timestamps are rejected)")
        return None
    return parsed.astimezone(timezone.utc)


def _string_list(value: Any, where: str, problems: list, *, min_items: int = 1) -> list:
    if not isinstance(value, list) or len(value) < min_items:
        problems.append(f"{where}: must be a list with at least {min_items} item(s)")
        return []
    out = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            problems.append(f"{where}[{index}]: must be a non-empty string")
        else:
            out.append(item)
    return out


# --------------------------------------------------------------------------
# worlds (fixture evidence for synthetic cases)
# --------------------------------------------------------------------------
def _check_addresses(items: list, where: str, problems: list) -> None:
    for index, item in enumerate(items):
        try:
            ipaddress.ip_address(item)
        except ValueError:
            problems.append(f"{where}[{index}]: {item!r} is not an IP address")


def _check_cidrs(items: list, where: str, problems: list, family: Optional[int]) -> None:
    for index, item in enumerate(items):
        try:
            net = ipaddress.ip_network(item, strict=True)
        except ValueError:
            problems.append(f"{where}[{index}]: {item!r} is not a valid CIDR (strict)")
            continue
        if family is not None and net.version != family:
            problems.append(f"{where}[{index}]: {item!r} is not an IPv{family} range")
        floor = MIN_PREFIX_V4 if net.version == 4 else MIN_PREFIX_V6
        if net.prefixlen < floor:
            problems.append(f"{where}[{index}]: {item!r} is broader than /{floor}")


def _check_state(spec: dict, key: str, where: str, problems: list) -> Optional[str]:
    state = spec.get(key)
    if state not in SOURCE_STATES:
        problems.append(f"{where}.{key}: must be one of {', '.join(SOURCE_STATES)}")
        return None
    return state


def _validate_world(name: str, world: Any, problems: list) -> None:
    where = f"worlds[{name!r}]"
    if not _WORLD_ID_RE.match(name):
        problems.append(f"{where}: world id must match {_WORLD_ID_RE.pattern}")
    if not _check_keys(
        world,
        required={"description"},
        optional={"enabled_sources", "tor", "x4bnet", "az0"},
        where=where,
        problems=problems,
    ):
        return
    _text(world["description"], f"{where}.description", problems)
    enabled = world.get("enabled_sources", list(CLASSIFIER_SOURCE_NAMES))
    names = _string_list(enabled, f"{where}.enabled_sources", problems)
    for entry in names:
        if entry not in CLASSIFIER_SOURCE_NAMES:
            problems.append(f"{where}.enabled_sources: unknown source {entry!r}")
    if len(set(names)) != len(names):
        problems.append(f"{where}.enabled_sources: contains duplicates")

    for key, full in SOURCE_KEYS.items():
        spec = world.get(key)
        if full not in names:
            if spec is not None:
                problems.append(f"{where}.{key}: given but source {full!r} is not enabled")
            continue
        if spec is None:
            problems.append(f"{where}.{key}: required because source {full!r} is enabled")
            continue
        if key == "tor":
            _validate_tor(spec, f"{where}.tor", problems)
        elif key == "x4bnet":
            _validate_x4(spec, f"{where}.x4bnet", problems)
        else:
            _validate_az0(spec, f"{where}.az0", problems)


def _validate_tor(spec: Any, where: str, problems: list) -> None:
    if not _check_keys(
        spec, required={"state"}, optional={"entries", "last_modified"}, where=where, problems=problems
    ):
        return
    state = _check_state(spec, "state", where, problems)
    if "last_modified" in spec:
        _timestamp(spec["last_modified"], f"{where}.last_modified", problems)
    if state == "ok":
        _check_addresses(_string_list(spec.get("entries"), f"{where}.entries", problems), f"{where}.entries", problems)
    elif "entries" in spec:
        problems.append(f"{where}: entries must be absent when state is {state!r}")


def _validate_x4(spec: Any, where: str, problems: list) -> None:
    if not _check_keys(
        spec,
        required={"state", "apple_state"},
        optional={"ipv4", "ipv6", "apple"},
        where=where,
        problems=problems,
    ):
        return
    state = _check_state(spec, "state", where, problems)
    apple_state = _check_state(spec, "apple_state", where, problems)
    for key, family in (("ipv4", 4), ("ipv6", 6)):
        if state == "ok":
            items = _string_list(spec.get(key), f"{where}.{key}", problems)
            _check_cidrs(items, f"{where}.{key}", problems, family)
        elif key in spec:
            problems.append(f"{where}: {key} must be absent when state is {state!r}")
    if apple_state == "ok":
        items = _string_list(spec.get("apple"), f"{where}.apple", problems)
        _check_cidrs(items, f"{where}.apple", problems, None)
    elif "apple" in spec:
        problems.append(f"{where}: apple must be absent when apple_state is {apple_state!r}")


def _validate_az0(spec: Any, where: str, problems: list) -> None:
    if not _check_keys(spec, required={"state"}, optional={"files"}, where=where, problems=problems):
        return
    state = _check_state(spec, "state", where, problems)
    if state == "ok":
        files = spec.get("files")
        if not isinstance(files, dict) or set(files) != set(AZ0_FILES):
            problems.append(f"{where}.files: must be an object with exactly {', '.join(AZ0_FILES)}")
            return
        for name in AZ0_FILES:
            items = _string_list(files[name], f"{where}.files[{name!r}]", problems)
            _check_addresses(items, f"{where}.files[{name!r}]", problems)
    elif "files" in spec:
        problems.append(f"{where}: files must be absent when state is {state!r}")


# --------------------------------------------------------------------------
# cases
# --------------------------------------------------------------------------
_CASE_REQUIRED = {"case_id", "tier", "category", "ip", "observed_at", "expected_label"}
_CASE_OPTIONAL = {
    "expected_reason_code", "world", "rationale", "reference", "unlabeled_reason", "notes"
}
_REFERENCE_REQUIRED = {
    "source", "source_type", "retrieved_at", "temporal_support", "label_basis",
    "confidence", "limitations", "independent_of_classifier_sources",
}
_REFERENCE_OPTIONAL = {"source_url", "valid_from", "valid_to"}


def _reason_matches_label(label: str, reason: str) -> bool:
    if label == "Known Tor exit":
        return reason == "TOR_EXIT_MATCH"
    if label == "Known hosted VPN/proxy endpoint":
        return reason == "VPN_PROXY_ENDPOINT_MATCH"
    return reason.startswith("UNKNOWN_")


def _validate_reference(ref: Any, observed_at: Optional[datetime], where: str, problems: list) -> Optional[dict]:
    if not _check_keys(ref, required=_REFERENCE_REQUIRED, optional=_REFERENCE_OPTIONAL, where=where, problems=problems):
        return None
    source = _text(ref["source"], f"{where}.source", problems)
    if source is not None and source.strip().lower() in CLASSIFIER_SOURCE_NAMES:
        problems.append(
            f"{where}.source: {source!r} is one of the evaluated sources; a reference label "
            "must be independent of them (circular)"
        )
    if ref["source_type"] not in REFERENCE_SOURCE_TYPES:
        problems.append(f"{where}.source_type: must be one of {', '.join(REFERENCE_SOURCE_TYPES)}")
    if "source_url" in ref:
        url = _text(ref["source_url"], f"{where}.source_url", problems)
        if url is not None:
            lowered = url.lower()
            if not lowered.startswith("https://"):
                problems.append(f"{where}.source_url: must be an https URL")
            if any(fragment in lowered for fragment in _CIRCULAR_URL_FRAGMENTS):
                problems.append(f"{where}.source_url: points at an evaluated source (circular)")
    if ref["independent_of_classifier_sources"] is not True:
        problems.append(f"{where}.independent_of_classifier_sources: must be true")
    retrieved = _timestamp(ref["retrieved_at"], f"{where}.retrieved_at", problems)
    _text(ref["label_basis"], f"{where}.label_basis", problems)
    _string_list(ref["limitations"], f"{where}.limitations", problems)
    if ref["confidence"] not in CONFIDENCE_LEVELS:
        problems.append(f"{where}.confidence: must be one of {', '.join(CONFIDENCE_LEVELS)}")
    scope = ref["temporal_support"]
    if scope not in TEMPORAL_SUPPORT:
        problems.append(f"{where}.temporal_support: must be one of {', '.join(TEMPORAL_SUPPORT)}")
    valid_from = _timestamp(ref["valid_from"], f"{where}.valid_from", problems) if "valid_from" in ref else None
    valid_to = _timestamp(ref["valid_to"], f"{where}.valid_to", problems) if "valid_to" in ref else None

    if observed_at is not None:
        if scope == "current-only":
            if "valid_from" in ref or "valid_to" in ref:
                problems.append(f"{where}: a current-only reference must not carry a validity interval")
            if retrieved is not None:
                gap = abs((observed_at - retrieved).total_seconds())
                if gap > CURRENT_ONLY_TOLERANCE_SECONDS:
                    problems.append(
                        f"{where}: current-only evidence retrieved {retrieved.isoformat()} cannot "
                        f"establish ground truth for an observation at {observed_at.isoformat()} "
                        f"({int(gap)}s apart, limit {CURRENT_ONLY_TOLERANCE_SECONDS}s)"
                    )
        elif scope == "time-bounded":
            if valid_from is None or valid_to is None:
                problems.append(f"{where}: a time-bounded reference needs both valid_from and valid_to")
            else:
                if valid_from > valid_to:
                    problems.append(f"{where}: valid_from is after valid_to")
                elif not (valid_from <= observed_at <= valid_to):
                    problems.append(f"{where}: observed_at lies outside the reference validity interval")
    return copy.deepcopy(ref)


def _validate_case(index: int, raw: Any, world_names: set, problems: list) -> Optional[Case]:
    label_for_errors = raw.get("case_id") if isinstance(raw, dict) else None
    where = f"cases[{index}]" + (f" ({label_for_errors})" if isinstance(label_for_errors, str) else "")
    if not _check_keys(raw, required=_CASE_REQUIRED, optional=_CASE_OPTIONAL, where=where, problems=problems):
        return None
    before = len(problems)

    case_id = raw["case_id"]
    if not isinstance(case_id, str) or not _CASE_ID_RE.match(case_id):
        problems.append(f"{where}.case_id: must match {_CASE_ID_RE.pattern}")
    tier = raw["tier"]
    if tier not in TIERS:
        problems.append(f"{where}.tier: must be one of {', '.join(TIERS)}")
    category = raw["category"]
    if category not in CATEGORIES:
        problems.append(f"{where}.category: must be one of {', '.join(CATEGORIES)}")

    ip_text = raw["ip"]
    assessment = assess_address(ip_text) if isinstance(ip_text, str) else None
    ip_normalized = None
    if assessment is None or assessment.category is AddressCategory.INVALID:
        problems.append(f"{where}.ip: {ip_text!r} is not a valid single IP address")
    else:
        ip_normalized = assessment.normalized
        if category == "excluded_address" and assessment.allowed:
            problems.append(f"{where}: category excluded_address needs an address the policy excludes")
        if category != "excluded_address" and not assessment.allowed:
            problems.append(f"{where}: {ip_text!r} is excluded by policy ({assessment.category.value}); use category excluded_address")

    observed_at = _timestamp(raw["observed_at"], f"{where}.observed_at", problems)

    expected = raw["expected_label"]
    if expected is not None and expected not in LABELS:
        problems.append(f"{where}.expected_label: must be null or one of the three labels")
        expected = None
    reason = raw.get("expected_reason_code")
    if reason is not None:
        if reason not in REASON_CODES:
            problems.append(f"{where}.expected_reason_code: unknown reason code {reason!r}")
        elif expected is None:
            problems.append(f"{where}: expected_reason_code needs an expected_label")
        elif not _reason_matches_label(expected, reason):
            problems.append(f"{where}: reason code {reason} is inconsistent with label {expected!r}")
        if tier == "reference":
            problems.append(f"{where}: reference cases carry labels only, not policy reason codes")

    world = raw.get("world")
    rationale = raw.get("rationale")
    reference = None
    unlabeled_reason = raw.get("unlabeled_reason")
    if tier == "synthetic":
        if world not in world_names:
            problems.append(f"{where}.world: unknown world {world!r}")
        _text(rationale, f"{where}.rationale", problems)
        if "reference" in raw:
            problems.append(f"{where}: synthetic cases must not carry reference provenance")
    elif tier == "reference":
        if world is not None:
            problems.append(f"{where}: reference cases must not name a fixture world")
        if expected is not None:
            if "reference" not in raw:
                problems.append(f"{where}: labeled reference case is missing its provenance ('reference')")
            else:
                reference = _validate_reference(raw["reference"], observed_at, f"{where}.reference", problems)
    if expected is None:  # unlabeled handling is explicit in BOTH tiers
        _text(unlabeled_reason, f"{where}.unlabeled_reason", problems)
    if unlabeled_reason is not None and expected is not None:
        problems.append(f"{where}: unlabeled_reason is only valid when expected_label is null")
    if raw.get("notes") is not None:
        _text(raw["notes"], f"{where}.notes", problems)

    if len(problems) != before or observed_at is None or ip_normalized is None:
        return None
    return Case(
        case_id=case_id,
        tier=tier,
        category=category,
        ip=ip_text,
        ip_normalized=ip_normalized,
        observed_at=observed_at,
        expected_label=expected,
        expected_reason_code=reason,
        world=world if tier == "synthetic" else None,
        rationale=rationale if tier == "synthetic" else None,
        reference=reference,
        unlabeled_reason=unlabeled_reason,
        notes=raw.get("notes"),
    )


# --------------------------------------------------------------------------
# whole dataset
# --------------------------------------------------------------------------
def parse_dataset(obj: Any) -> Dataset:
    """Validate an already-parsed JSON object. Raises DatasetError listing every problem."""
    problems: list[str] = []
    if not _check_keys(
        obj,
        required={"schema_version", "dataset_id", "dataset_version", "description",
                  "evaluation_time", "limitations", "worlds", "cases"},
        optional=set(),
        where="dataset",
        problems=problems,
    ):
        raise DatasetError(problems)

    if obj["schema_version"] != SCHEMA_VERSION:
        problems.append(f"dataset.schema_version: must be {SCHEMA_VERSION!r}")
    dataset_id = _text(obj["dataset_id"], "dataset.dataset_id", problems)
    dataset_version = _text(obj["dataset_version"], "dataset.dataset_version", problems)
    description = _text(obj["description"], "dataset.description", problems)
    evaluation_time = _timestamp(obj["evaluation_time"], "dataset.evaluation_time", problems)
    limitations = _string_list(obj["limitations"], "dataset.limitations", problems)

    worlds = obj["worlds"]
    if not isinstance(worlds, dict):
        problems.append("dataset.worlds: must be a JSON object")
        worlds = {}
    for name in sorted(worlds):
        _validate_world(name, worlds[name], problems)

    raw_cases = obj["cases"]
    cases: list[Case] = []
    if not isinstance(raw_cases, list) or not raw_cases:
        problems.append("dataset.cases: must be a non-empty list")
        raw_cases = []
    seen: dict[str, int] = {}
    for index, raw in enumerate(raw_cases):
        case_id = raw.get("case_id") if isinstance(raw, dict) else None
        if isinstance(case_id, str):
            key = case_id.lower()
            if key in seen:
                problems.append(f"cases[{index}]: duplicate case_id {case_id!r} (first at cases[{seen[key]}])")
            else:
                seen[key] = index
        case = _validate_case(index, raw, set(worlds), problems)
        if case is not None:
            cases.append(case)

    used = {c.world for c in cases if c.world}
    for name in sorted(set(worlds) - used):
        # cases that failed validation may have referenced it; only flag when none ever did
        referenced = any(isinstance(r, dict) and r.get("world") == name for r in raw_cases)
        if not referenced:
            problems.append(f"worlds[{name!r}]: defined but never used by any case")

    if problems:
        raise DatasetError(problems)
    assert dataset_id and dataset_version and description and evaluation_time
    return Dataset(
        schema_version=obj["schema_version"],
        dataset_id=dataset_id,
        dataset_version=dataset_version,
        description=description,
        evaluation_time=evaluation_time,
        limitations=tuple(limitations),
        worlds=copy.deepcopy(worlds),
        cases=tuple(sorted(cases, key=lambda c: c.case_id)),
        sha256=sha256_of_object(obj),
    )
