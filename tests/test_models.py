from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from netclass.models import EvidenceKind, EvidenceRecord, EvidenceStatus, NetworkContext, Observation

T0 = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "bad_ip", ["", " ", "not-an-ip", "999.1.1.1", "8.8.8.8/24", "fe80::1%eth0", "8.8.8.8:53"]
)
def test_observation_rejects_malformed_ip(bad_ip):
    with pytest.raises(ValidationError):
        Observation(ip=bad_ip, observed_at=T0)


def test_observation_normalises_ip():
    assert Observation(ip=" 8.8.8.8 ", observed_at=T0).ip == "8.8.8.8"
    assert Observation(ip="::ffff:8.8.8.8", observed_at=T0).ip == "8.8.8.8"


def test_observation_accepts_private_ip_as_valid_input():
    # Exclusion is a classification policy decision, not an input-validation error.
    assert Observation(ip="10.0.0.1", observed_at=T0).ip == "10.0.0.1"


def test_observation_rejects_naive_datetime():
    with pytest.raises(ValidationError):
        Observation(ip="8.8.8.8", observed_at=datetime(2026, 10, 28, 12, 0))


def test_observation_converts_offsets_to_utc():
    ist = timezone(timedelta(hours=5, minutes=30))
    o = Observation(ip="8.8.8.8", observed_at=datetime(2026, 10, 28, 17, 30, tzinfo=ist))
    assert o.observed_at == T0
    assert o.observed_at.utcoffset() == timedelta(0)


def _record(**overrides):
    base = dict(
        source_name="s",
        source_endpoint="https://fixture.invalid/x",
        kind=EvidenceKind.TOR_EXIT,
        status=EvidenceStatus.NO_MATCH,
        retrieved_at=T0,
    )
    base.update(overrides)
    return EvidenceRecord(**base)


def test_evidence_requires_error_text_for_failures():
    with pytest.raises(ValidationError):
        _record(status=EvidenceStatus.SOURCE_UNAVAILABLE)
    with pytest.raises(ValidationError):
        _record(status=EvidenceStatus.NOT_CONFIGURED)
    assert _record(status=EvidenceStatus.SOURCE_UNAVAILABLE, error="timeout").error == "timeout"


def test_evidence_rejects_bad_sha_and_normalises_case():
    with pytest.raises(ValidationError):
        _record(snapshot_sha256="not-a-hash")
    digest = "A" * 64
    assert _record(snapshot_sha256=digest).snapshot_sha256 == "a" * 64


def test_evidence_rejects_inverted_validity_interval():
    with pytest.raises(ValidationError):
        _record(valid_from=T0, valid_to=T0 - timedelta(days=1))


def test_evidence_rejects_naive_datetimes():
    with pytest.raises(ValidationError):
        _record(retrieved_at=datetime(2026, 10, 28, 12, 0))


def test_has_validity_interval_flag():
    assert _record().has_validity_interval is False
    assert _record(valid_from=T0).has_validity_interval is True


def test_hosting_indicator_requires_basis():
    with pytest.raises(ValidationError):
        NetworkContext(hosting_indicator=True)
    assert NetworkContext(hosting_indicator=True, hosting_indicator_basis="x").hosting_indicator
