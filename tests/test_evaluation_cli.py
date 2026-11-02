"""scripts/evaluate.py: exit codes, deterministic files, no side effects, no network."""
import json
import subprocess
import sys

import pytest

from evaluation_support import DATASET_PATH, ROOT, case_of, edited, load_script, with_cases, reference_case

SCRIPT = ROOT / "scripts" / "evaluate.py"
REPORT_FILES = ("evaluation-report.json", "evaluation-report.md")


@pytest.fixture
def evaluate():
    return load_script("evaluate")


def write_dataset(tmp_path, raw, name="dataset.json"):
    path = tmp_path / name
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def test_check_only_validates_without_running(evaluate, capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert evaluate.main(["--check-only"]) == 0
    out = capsys.readouterr().out
    assert "dataset OK: ps010-eval-v1 1.0.0" in out and "synthetic=42 reference=0" in out
    assert len(out.split("sha256=")[1].split()[0]) == 64
    assert list(tmp_path.iterdir()) == []


def test_default_run_prints_json_and_writes_nothing(evaluate, capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert evaluate.main([]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["evaluation"]["evidence_basis"] == "synthetic-fixture-replay"
    assert report["reference_accuracy"]["status"] == "not_evaluated"
    assert list(tmp_path.iterdir()) == []


def test_out_dir_writes_exactly_two_files_with_lf_endings(evaluate, capsys, tmp_path):
    out = tmp_path / "reports" / "nested"
    assert evaluate.main(["--out-dir", str(out)]) == 0
    assert sorted(p.name for p in out.iterdir()) == sorted(REPORT_FILES)
    for name in REPORT_FILES:
        data = (out / name).read_bytes()
        assert b"\r" not in data and data.endswith(b"\n")
    summary = capsys.readouterr().out
    assert "mode=replay basis=synthetic-fixture-replay" in summary and "problems=0" in summary
    assert json.loads((out / REPORT_FILES[0]).read_text(encoding="utf-8"))["dataset"]["id"] == "ps010-eval-v1"


def test_two_runs_write_byte_identical_files(evaluate, tmp_path):
    for name in ("one", "two"):
        assert evaluate.main(["--out-dir", str(tmp_path / name)]) == 0
    for file in REPORT_FILES:
        assert (tmp_path / "one" / file).read_bytes() == (tmp_path / "two" / file).read_bytes()


def test_the_written_files_contain_no_local_path(evaluate, tmp_path):
    out = tmp_path / "private-dir-name-xyz"
    assert evaluate.main(["--out-dir", str(out)]) == 0
    for file in REPORT_FILES:
        text = (out / file).read_text(encoding="utf-8")
        assert "private-dir-name-xyz" not in text and str(ROOT) not in text and str(tmp_path) not in text


def test_invalid_dataset_exits_2_and_lists_every_problem(evaluate, capsys, tmp_path):
    def broken(raw):
        case_of(raw, "syn-tor-001").update(ip="bogus")
        raw["cases"].append(dict(case_of(raw, "syn-tor-002-ipv4-mapped")))
    code = evaluate.main(["--dataset", str(write_dataset(tmp_path, edited(broken)))])
    captured = capsys.readouterr()
    assert code == 2 and captured.out == ""
    assert "Dataset rejected" in captured.err and "bogus" in captured.err and "duplicate case_id" in captured.err


def test_missing_dataset_exits_2(evaluate, capsys, tmp_path):
    assert evaluate.main(["--dataset", str(tmp_path / "nope.json")]) == 2
    assert "Dataset rejected" in capsys.readouterr().err


def test_strict_passes_when_everything_conforms(evaluate, capsys):
    assert evaluate.main(["--strict"]) == 0
    capsys.readouterr()


def test_strict_exits_3_on_a_mismatch_but_still_writes_the_report(evaluate, capsys, tmp_path):
    def wrong(raw):
        case_of(raw, "syn-vpn-001-x4bnet").update(expected_label="Unknown", expected_reason_code="UNKNOWN_NO_QUALIFYING_MATCH")
    path = write_dataset(tmp_path, edited(wrong))
    out = tmp_path / "out"
    assert evaluate.main(["--dataset", str(path), "--out-dir", str(out), "--strict"]) == 3
    assert "problems=1" in capsys.readouterr().out
    report = json.loads((out / REPORT_FILES[0]).read_text(encoding="utf-8"))
    assert [m["case_id"] for m in report["synthetic_policy_conformance"]["mismatches"]] == ["syn-vpn-001-x4bnet"]
    # without --strict the same mismatch is reported but the exit code stays 0
    assert evaluate.main(["--dataset", str(path)]) == 0
    capsys.readouterr()


def test_live_without_reference_cases_exits_2_and_never_invents_ground_truth(evaluate, capsys):
    assert evaluate.main(["--live"]) == 2
    assert "no reference-tier cases" in capsys.readouterr().err


def test_out_dir_that_is_a_file_is_refused(evaluate, capsys, tmp_path):
    target = tmp_path / "a-file"
    target.write_text("x", encoding="utf-8")
    assert evaluate.main(["--out-dir", str(target)]) == 2
    assert target.read_text(encoding="utf-8") == "x"
    capsys.readouterr()


def test_reference_cases_in_a_dataset_are_skipped_offline_and_reported(evaluate, capsys, tmp_path):
    path = write_dataset(tmp_path, with_cases(reference_case()))
    assert evaluate.main(["--dataset", str(path)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert [s["case_id"] for s in report["skipped_cases"]] == ["ref-fixture-001"]


def test_script_runs_as_a_real_process_without_network(tmp_path):
    done = subprocess.run([sys.executable, str(SCRIPT), "--check-only"], capture_output=True, text=True,
                          cwd=tmp_path, timeout=60)
    assert done.returncode == 0 and "dataset OK" in done.stdout and done.stderr == ""
    assert list(tmp_path.iterdir()) == []
