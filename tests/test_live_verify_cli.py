"""The live-verification CLI core, driven with fakes. The real script is never run."""
import json

from factories import T0
from fakes import FakeFetcher, MutableClock
from netclass.live_verify import MAX_REQUESTS_CEILING, cli_main
from test_live_verify import HEALTHY_ROUTES, TARGETS


def drive(argv, tmp_path, routes=HEALTHY_ROUTES):
    messages, made = [], []

    def factory(timeout, retries, budget):
        fetcher = FakeFetcher(routes, MutableClock(T0))
        made.append((timeout, retries, budget))
        return fetcher

    code = cli_main(
        argv + ["--output-dir", str(tmp_path / "out")],
        targets_factory=lambda: TARGETS,
        fetcher_factory=factory,
        clock=MutableClock(T0),
        out=messages.append,
    )
    return code, messages, made


def test_without_live_flag_nothing_runs_and_no_fetcher_is_even_built(tmp_path):
    code, messages, made = drive([], tmp_path)
    assert code == 2 and made == [] and not (tmp_path / "out").exists()
    assert "--live" in messages[0] and "No network request was made" in messages[0]


def test_live_run_writes_timestamped_json_and_markdown_and_exits_zero(tmp_path):
    code, messages, made = drive(["--live"], tmp_path)
    assert code == 0 and made == [(10.0, 2, 30)]
    files = sorted(p.name for p in (tmp_path / "out").iterdir())
    assert files == ["live-verification-20261028T120000Z.json", "live-verification-20261028T120000Z.md"]
    data = json.loads((tmp_path / "out" / files[0]).read_text(encoding="utf-8"))
    assert data["mode"] == "LIVE" and data["request_budget"] == 30
    assert any("LIVE VERIFICATION" in m and "at most 30" in m for m in messages)


def test_unhealthy_source_gives_exit_code_one_and_is_listed(tmp_path):
    routes = {k: v for k, v in HEALTHY_ROUTES.items()}
    routes["https://x4b.invalid/apple.txt"] = (b"<html>oops</html>", {})
    code, messages, _ = drive(["--live"], tmp_path, routes)
    assert code == 1
    assert any("NOT HEALTHY: x4bnet_vpn/apple.txt -> PARSE_FAILURE" in m for m in messages)


def test_an_earlier_report_is_never_overwritten(tmp_path):
    assert drive(["--live"], tmp_path)[0] == 0
    try:
        drive(["--live"], tmp_path)
    except FileExistsError:
        pass
    else:
        raise AssertionError("second run with the same timestamp must not overwrite evidence")


def test_limits_are_enforced_before_any_request(tmp_path):
    for bad in (
        ["--live", "--max-requests", "0"],
        ["--live", "--max-requests", str(MAX_REQUESTS_CEILING + 1)],
        ["--live", "--timeout", "0"],
        ["--live", "--timeout", "31"],
        ["--live", "--retries", "3"],
        ["--live", "--max-source-age", "0"],
    ):
        code, _, made = drive(bad, tmp_path)
        assert code == 2 and made == [], bad
