from netclass.hashing import canonical_json_bytes, sha256_hex, verify_sha256

EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_known_vectors():
    assert sha256_hex(b"") == EMPTY
    assert sha256_hex(b"abc") == ABC


def test_verify_accepts_matching_hash_case_insensitively():
    assert verify_sha256(b"abc", ABC) is True
    assert verify_sha256(b"abc", ABC.upper()) is True


def test_verify_detects_tampering():
    snapshot = b"1.2.3.4\n5.6.7.8\n"
    digest = sha256_hex(snapshot)
    assert verify_sha256(snapshot, digest) is True
    assert verify_sha256(snapshot + b"9.9.9.9\n", digest) is False


def test_verify_rejects_malformed_expected_hash():
    assert verify_sha256(b"abc", "") is False
    assert verify_sha256(b"abc", "xyz") is False
    assert verify_sha256(b"abc", ABC[:-1]) is False
    assert verify_sha256(b"abc", None) is False  # type: ignore[arg-type]


def test_canonical_json_is_key_order_independent():
    assert canonical_json_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    assert canonical_json_bytes({"a": 2, "b": 1}) == canonical_json_bytes({"b": 1, "a": 2})


def test_manifest_hash_is_order_independent_and_content_sensitive():
    from netclass.hashing import manifest_sha256

    a = ("https://example.invalid/a", sha256_hex(b"a"))
    b = ("https://example.invalid/b", sha256_hex(b"b"))
    assert manifest_sha256([a, b]) == manifest_sha256([b, a])
    assert manifest_sha256([a, b]) != manifest_sha256([a])
    changed = ("https://example.invalid/b", sha256_hex(b"B"))
    assert manifest_sha256([a, b]) != manifest_sha256([a, changed])
    assert len(manifest_sha256([a])) == 64
