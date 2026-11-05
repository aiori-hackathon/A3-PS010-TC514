"""CLI contracts: the base commands and output are unchanged; IPinfo flags are opt-in.

In-process tests drive the script `main()` with fakes. The subprocess tests run the real
scripts but only for inputs that need no network (excluded addresses, disabled token).
"""
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from factories import obs
from ipinfo_support import TOKEN, http_error, lite, make as make_ipinfo, url_for
from netclass.collector import classify_with_context, classify_with_evidence
from netclass.config import Settings
from netclass.service import ClassificationService
from ripestat_support import healthy as ripe_healthy
from ripestat_support import make as make_ripestat
from support import CLEAN_IP, TOR_IP, all_adapters, make_stack

ROOT = Path(__file__).resolve().parents[1]
AT = "2026-10-28T12:00:00+00:00"  # == T0, the fixture clock


def load_script(name):
    spec = importlib.util.spec_from_file_location(f"script_{name}", ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def cli(monkeypatch, capsys, tmp_path):
    """Run classify_ip.py main() against a fake world. Returns (code, stdout, stderr, handles)."""

    def run(*argv, ip=CLEAN_IP, token=TOKEN, ipinfo_route=None, with_ripestat=True):
        stack = make_stack(tmp_path / "cli")
        ipinfo_routes = {url_for(ip): ipinfo_route} if ipinfo_route is not None else {}
        ipinfo, ipinfo_fetcher, _ = make_ipinfo(ipinfo_routes, token=token)
        ripestat, ripe_fetcher, _ = make_ripestat()
        ripe_fetcher.routes.update(ripe_healthy(ripestat, ip=ip, holder="RIPE-HOLDER-NAME"))
        service = ClassificationService(
            Settings(), all_adapters(stack), ripestat=ripestat, ipinfo=ipinfo, clock=stack.clock
        )
        monkeypatch.setattr(
            ClassificationService, "from_settings", classmethod(lambda cls, settings, **kw: service)
        )
        script = load_script("classify_ip")
        monkeypatch.setattr(script, "load_settings", lambda: Settings())
        monkeypatch.setattr(sys, "argv", ["classify_ip.py", *argv])
        code = script.main()
        out = capsys.readouterr()
        handles = {"evidence": stack.fetcher, "ipinfo": ipinfo_fetcher, "ripestat": ripe_fetcher}
        return code, out.out, out.err, handles

    return run


def direct(tmp_path, ip=CLEAN_IP):
    stack = make_stack(tmp_path / "direct")
    return classify_with_evidence(obs(ip), all_adapters(stack), Settings())


# ------------------------------------------------------------------ base command contracts
def test_plain_command_prints_exactly_the_result_object(cli, tmp_path):
    code, out, err, _ = cli(CLEAN_IP, "--at", AT)
    result, _records = direct(tmp_path)
    assert code == 0 and err == ""
    assert json.loads(out) == {"result": result.model_dump(mode="json")}


def test_evidence_flag_adds_the_evidence_list(cli, tmp_path):
    code, out, _, _ = cli(CLEAN_IP, "--at", AT, "--evidence")
    result, records = direct(tmp_path)
    doc = json.loads(out)
    assert code == 0 and list(doc) == ["result", "evidence"]
    assert doc["evidence"] == [r.model_dump(mode="json") for r in records]


def test_context_flag_adds_ripestat_context_exactly_as_before(cli, tmp_path):
    code, out, _, _ = cli(CLEAN_IP, "--at", AT, "--context", "--evidence")
    stack = make_stack(tmp_path / "d2")
    ripestat, ripe_fetcher, _ = make_ripestat()
    ripe_fetcher.routes.update(ripe_healthy(ripestat, ip=CLEAN_IP, holder="RIPE-HOLDER-NAME"))
    result, records, ripe = classify_with_context(obs(CLEAN_IP), all_adapters(stack), Settings(), ripestat)
    doc = json.loads(out)
    assert code == 0 and list(doc) == ["result", "ripestat_context", "evidence"]
    assert doc["result"] == result.model_dump(mode="json")
    assert doc["ripestat_context"] == ripe.model_dump(mode="json")


def test_no_ipinfo_output_appears_without_the_ipinfo_flag(cli):
    _, out, _, handles = cli(CLEAN_IP, "--at", AT, "--context", "--evidence", ipinfo_route=lite(CLEAN_IP))
    assert "ipinfo" not in out.lower()
    assert handles["ipinfo"].requested == []  # a configured token alone sends nothing


@pytest.mark.parametrize("argv", [["not-an-ip"], ["8.8.8.8/24"], ["1.2.3.4:80"], [""]])
def test_invalid_ip_exits_with_2_and_prints_nothing_on_stdout(cli, argv):
    code, out, err, _ = cli(*argv)
    assert code == 2 and out == "" and err.startswith("Invalid input:")


def test_naive_timestamp_exits_with_2(cli):
    code, out, err, _ = cli(CLEAN_IP, "--at", "2026-10-28T12:00:00")
    assert code == 2 and out == "" and "Invalid input" in err


def test_ipv6_argument_still_works(cli):
    code, out, _, _ = cli("2001:4860:4860::8888", "--at", AT, ip="2001:4860:4860::8888")
    doc = json.loads(out)
    assert code == 0 and doc["result"]["ip"] == "2001:4860:4860::8888"
    assert doc["result"]["label"] == "Unknown"


# ------------------------------------------------------------------ IPinfo flag
def test_ipinfo_flag_adds_a_separate_section_and_never_changes_the_result(cli):
    _, plain, _, _ = cli(TOR_IP, "--at", AT, ip=TOR_IP)
    code, out, _, handles = cli(
        TOR_IP, "--at", AT, "--ipinfo", "--evidence", ip=TOR_IP, ipinfo_route=lite(TOR_IP)
    )
    doc = json.loads(out)
    assert code == 0 and list(doc) == ["result", "ipinfo_metadata", "evidence"]
    assert doc["result"] == json.loads(plain)["result"]
    assert doc["result"]["label"] == "Known Tor exit"
    assert doc["ipinfo_metadata"]["status"] == "AVAILABLE" and doc["ipinfo_metadata"]["asn"] == 64496
    assert handles["ipinfo"].requested == [url_for(TOR_IP)]
    assert TOKEN not in out


def test_ipinfo_flag_without_a_token_reports_disabled_and_exits_0(cli):
    code, out, _, handles = cli(CLEAN_IP, "--at", AT, "--ipinfo", token=None)
    doc = json.loads(out)
    assert code == 0 and doc["ipinfo_metadata"]["status"] == "DISABLED"
    assert doc["result"]["label"] == "Unknown"
    assert handles["ipinfo"].requested == []


def test_ipinfo_failure_keeps_exit_code_0_and_the_classification(cli):
    code, out, _, _ = cli(
        TOR_IP, "--at", AT, "--ipinfo", ip=TOR_IP, ipinfo_route=http_error(url_for(TOR_IP), 429)
    )
    doc = json.loads(out)
    assert code == 0
    assert doc["result"]["label"] == "Known Tor exit"
    assert doc["ipinfo_metadata"]["status"] == "UNAVAILABLE"
    assert doc["ipinfo_metadata"]["error"]["kind"] == "RATE_LIMITED"


def test_excluded_address_triggers_no_requests_at_all(cli):
    code, out, _, handles = cli("10.0.0.1", "--at", AT, "--context", "--ipinfo", ip="10.0.0.1",
                                ipinfo_route=lite("10.0.0.1"))
    doc = json.loads(out)
    assert code == 0 and doc["result"]["reason_code"] == "UNKNOWN_EXCLUDED_ADDRESS"
    assert doc["ipinfo_metadata"]["status"] == "NOT_QUERIED"
    assert doc["ripestat_context"]["status"] == "NOT_QUERIED"
    assert all(h.requested == [] for h in handles.values())


# ------------------------------------------------------------------ ipinfo_context.py
@pytest.mark.parametrize(
    "ip, token, route, exit_code, status",
    [
        (CLEAN_IP, TOKEN, lite(CLEAN_IP), 0, "AVAILABLE"),
        (CLEAN_IP, TOKEN, http_error(url_for(CLEAN_IP), 401), 1, "UNAVAILABLE"),
        (CLEAN_IP, TOKEN, b'{"ip": "8.8.8.8"}', 1, "EMPTY"),
        ("10.0.0.1", TOKEN, None, 3, "NOT_QUERIED"),
        (CLEAN_IP, None, None, 4, "DISABLED"),
        ("garbage", TOKEN, None, 1, "UNAVAILABLE"),
    ],
)
def test_ipinfo_context_script_exit_codes(monkeypatch, capsys, ip, token, route, exit_code, status):
    service, _, _ = make_ipinfo({url_for(ip): route} if route is not None else {}, token=token)
    script = load_script("ipinfo_context")
    monkeypatch.setattr(script, "load_settings", lambda: Settings())
    monkeypatch.setattr(script, "build_ipinfo_service", lambda settings: service)
    monkeypatch.setattr(sys, "argv", ["ipinfo_context.py", ip])
    code = script.main()
    out = capsys.readouterr().out
    assert code == exit_code and json.loads(out)["status"] == status
    assert TOKEN not in out


# ------------------------------------------------------------------ real scripts, no network needed
def _env(tmp_path, token=""):
    env = dict(os.environ)
    env.update(
        {
            "IPINFO_TOKEN": token,  # set explicitly so a developer's .env cannot leak in
            "NETCLASS_CACHE_DIR": str(tmp_path / "cache"),
            "NETCLASS_VPN_PROVIDER": "",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    return env


def run_script(tmp_path, *argv, token=""):
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / argv[0]), *argv[1:]],
        capture_output=True, text=True, cwd=tmp_path, env=_env(tmp_path, token), timeout=60,
    )


@pytest.mark.parametrize(
    "script", ["classify_ip.py", "inspect_sources.py", "ripestat_context.py", "ipinfo_context.py"]
)
def test_every_script_still_imports_and_prints_help(tmp_path, script):
    done = run_script(tmp_path, script, "--help")
    assert done.returncode == 0 and "usage:" in done.stdout.lower(), done.stderr


def test_classify_help_lists_old_and_new_flags(tmp_path):
    text = run_script(tmp_path, "classify_ip.py", "--help").stdout
    for flag in ("--at", "--evidence", "--context", "--ipinfo"):
        assert flag in text


def test_real_cli_excluded_address_with_every_option_needs_no_network(tmp_path):
    plain = run_script(tmp_path, "classify_ip.py", "10.0.0.1", "--at", AT)
    full = run_script(
        tmp_path, "classify_ip.py", "10.0.0.1", "--at", AT, "--context", "--ipinfo", "--evidence",
        token=TOKEN,
    )
    assert plain.returncode == 0 and full.returncode == 0, full.stderr
    a, b = json.loads(plain.stdout), json.loads(full.stdout)
    assert a["result"]["label"] == "Unknown"
    assert a["result"]["reason_code"] == "UNKNOWN_EXCLUDED_ADDRESS"
    assert b["result"] == a["result"]
    assert b["ipinfo_metadata"]["status"] == "NOT_QUERIED"
    assert b["ripestat_context"]["status"] == "NOT_QUERIED"
    assert b["evidence"] == []
    assert TOKEN not in full.stdout + full.stderr


def test_real_ipinfo_script_is_disabled_without_a_token_and_skips_excluded(tmp_path):
    disabled = run_script(tmp_path, "ipinfo_context.py", "8.8.8.8")  # no token: no request is made
    assert disabled.returncode == 4 and json.loads(disabled.stdout)["status"] == "DISABLED"
    excluded = run_script(tmp_path, "ipinfo_context.py", "10.0.0.1", token=TOKEN)
    assert excluded.returncode == 3 and json.loads(excluded.stdout)["status"] == "NOT_QUERIED"
    assert TOKEN not in excluded.stdout + excluded.stderr


def test_real_classify_rejects_invalid_input_with_exit_code_2(tmp_path):
    done = run_script(tmp_path, "classify_ip.py", "not-an-ip")
    assert done.returncode == 2 and done.stdout == "" and "Invalid input" in done.stderr
