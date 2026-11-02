import json
import re
from datetime import timedelta

from factories import T0
from netclass.cache import Snapshot, SnapshotStore
from netclass.hashing import sha256_hex

# Contains characters that are illegal in Windows file names (: ? / ).
URL = "https://example.invalid/a:b?c=d/list.txt"


def make_snapshot(body=b"1.2.3.4\n", url=URL, source="src", retrieved_at=T0, stamp=None):
    return Snapshot(
        source_name=source,
        url=url,
        body=body,
        sha256=sha256_hex(body),
        retrieved_at=retrieved_at,
        source_timestamp=stamp,
        from_cache=False,
        headers={"etag": '"v1"'},
    )


def test_roundtrip_preserves_content_hash_times_and_headers(tmp_path):
    store = SnapshotStore(tmp_path)
    stamp = T0 - timedelta(hours=1)
    store.save(make_snapshot(stamp=stamp))
    lookup = store.load("src", URL)
    snap = lookup.snapshot
    assert lookup.problem is None and snap is not None
    assert snap.body == b"1.2.3.4\n" and snap.sha256 == sha256_hex(b"1.2.3.4\n")
    assert snap.retrieved_at == T0 and snap.retrieved_at.utcoffset().total_seconds() == 0
    assert snap.source_timestamp == stamp
    assert snap.from_cache is True
    assert snap.headers == {"etag": '"v1"'}


def test_missing_entry_is_a_plain_miss(tmp_path):
    lookup = SnapshotStore(tmp_path).load("src", URL)
    assert lookup.snapshot is None and lookup.problem is None


def test_tampered_snapshot_fails_sha256_verification(tmp_path):
    store = SnapshotStore(tmp_path)
    snap = make_snapshot()
    store.save(snap)
    (tmp_path / "snapshots" / f"{snap.sha256}.bin").write_bytes(b"9.9.9.9\n")
    lookup = store.load("src", URL)
    assert lookup.snapshot is None
    assert "SHA-256" in lookup.problem


def test_missing_snapshot_file_and_corrupt_index_are_reported(tmp_path):
    store = SnapshotStore(tmp_path)
    snap = make_snapshot()
    store.save(snap)
    (tmp_path / "snapshots" / f"{snap.sha256}.bin").unlink()
    assert "missing" in store.load("src", URL).problem

    index = next((tmp_path / "index").glob("*.json"))
    index.write_text("{not json", encoding="utf-8")
    lookup = store.load("src", URL)
    assert lookup.snapshot is None and "unreadable" in lookup.problem


def test_naive_datetime_in_index_is_rejected(tmp_path):
    store = SnapshotStore(tmp_path)
    store.save(make_snapshot())
    index = next((tmp_path / "index").glob("*.json"))
    data = json.loads(index.read_text(encoding="utf-8"))
    data["retrieved_at"] = "2026-10-28T12:00:00"
    index.write_text(json.dumps(data), encoding="utf-8")
    assert store.load("src", URL).snapshot is None


def test_index_for_a_different_url_is_not_trusted(tmp_path):
    store = SnapshotStore(tmp_path)
    store.save(make_snapshot())
    index = next((tmp_path / "index").glob("*.json"))
    data = json.loads(index.read_text(encoding="utf-8"))
    data["url"] = "https://example.invalid/other"
    index.write_text(json.dumps(data), encoding="utf-8")
    assert store.load("src", URL).snapshot is None


def test_all_cache_file_names_are_windows_safe(tmp_path):
    store = SnapshotStore(tmp_path)
    store.save(make_snapshot(source="source with spaces/and:colons"))
    for path in tmp_path.rglob("*"):
        assert re.fullmatch(r"[A-Za-z0-9._-]+", path.name), path.name


def test_identical_bodies_are_stored_once(tmp_path):
    store = SnapshotStore(tmp_path)
    store.save(make_snapshot(url="https://example.invalid/one"))
    store.save(make_snapshot(url="https://example.invalid/two"))
    assert len(list((tmp_path / "snapshots").glob("*.bin"))) == 1
    assert len(list((tmp_path / "index").glob("*.json"))) == 2


def test_new_snapshot_moves_the_pointer_and_retains_the_old_file(tmp_path):
    store = SnapshotStore(tmp_path)
    old, new = make_snapshot(b"1.1.1.1\n"), make_snapshot(b"2.2.2.2\n", retrieved_at=T0 + timedelta(hours=1))
    store.save(old)
    store.save(new)
    assert store.load("src", URL).snapshot.body == b"2.2.2.2\n"
    assert (tmp_path / "snapshots" / f"{old.sha256}.bin").exists()  # retained for audit


def test_no_temporary_files_are_left_behind(tmp_path):
    store = SnapshotStore(tmp_path)
    store.save(make_snapshot())
    assert not list(tmp_path.rglob(".tmp-*"))
