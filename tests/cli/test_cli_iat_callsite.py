"""The import-layer repair's published contract, exercised as a subprocess.

What a caller can rely on, and what this file pins:

  * without --out, nothing is written and the run is an analysis (exit 0 or 1 depending on whether a
    site was refused, never a silent file);
  * with --out, the input file is byte-identical afterwards, the output is a different file, and the
    six bytes written at each site decode to an indirect call through the slot the report names;
  * a refusal is exit 1 and the word "incomplete" -- the failure mode this repository is organised
    against is a partial repair reported as a finished one; two candidate tables get their own token,
    "ambiguous-iat", because a person has to say which one is the table.
"""
import hashlib
import json

import pytest

pytestmark = pytest.mark.cli


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def document(text):
    return json.JSONDecoder().raw_decode(text)[0]


def test_analysis_writes_nothing_and_reports_incomplete(run_script, iat_scenario, tmp_path):
    scen = iat_scenario("pe64")
    before = sha(scen.path)
    result = run_script("iat_callsite_restore.py", scen.path, "--iat", "0x3020,0x18", cwd=tmp_path)
    assert result.returncode == 1, result.stderr
    assert "RESULT=incomplete" in result.stdout
    assert sha(scen.path) == before
    assert list(tmp_path.iterdir()) == []


def test_the_rewrite_is_verified_and_leaves_the_input_alone(run_script, iat_scenario,
                                                            load_script, tmp_path):
    scen = iat_scenario("pe64")
    before = sha(scen.path)
    out = tmp_path / "fixed.exe"
    result = run_script("iat_callsite_restore.py", scen.path, "--iat", "0x3020,0x18",
                        "--out", out)
    assert result.returncode == 1, result.stderr
    assert "VERIFY FAILED" not in result.stdout
    assert "RESULT=incomplete" in result.stdout
    assert sha(scen.path) == before, "the input was modified"

    pe = load_script("peutil.py").PE(out.read_bytes())
    for window in (scen.sites["filler_after"], scen.sites["filler_before"] - 1):
        raw = pe.rva_bytes(window, 6)
        assert raw[:2] == b"\xFF\x15", raw.hex()
    # The refused site is untouched: the byte after its call is still the original instruction.
    assert pe.rva_bytes(scen.sites["no_filler"] + 5, 1) == b"\xC3"


def test_the_pe32_displacement_is_an_absolute_slot_address(run_script, iat_scenario,
                                                           load_script, tmp_path):
    scen = iat_scenario("pe32")
    out = tmp_path / "fixed32.exe"
    result = run_script("iat_callsite_restore.py", scen.path, "--iat", "0x3020,0x18", "--out", out)
    assert result.returncode == 1, result.stderr
    pe = load_script("peutil.py").PE(out.read_bytes())
    raw = pe.rva_bytes(scen.sites["filler_after"], 6)
    assert raw[:2] == b"\xFF\x15"
    assert int.from_bytes(raw[2:], "little") == scen.base + scen.slot_rva


def test_discovery_finds_the_table_from_the_calls(run_script, iat_scenario):
    """No --iat, no described range for these slots: the report must show the search, not a guess."""
    scen = iat_scenario("pe64")
    text = run_script("iat_callsite_restore.py", scen.path)
    assert text.returncode == 1, text.stderr
    assert "discover unique after no-pairs" in text.stdout
    assert "<- used" in text.stdout

    payload = document(run_script("iat_callsite_restore.py", scen.path, "--json").stdout)
    assert payload["discovery"]["chosen"] == {"start": 0x3020, "size": 0x18}
    assert payload["discovery"]["trigger"] == "no-pairs"
    assert [p["site_rva"] for p in payload["pairs"]] == [scen.sites["filler_after"],
                                                         scen.sites["filler_before"]]


def test_two_candidate_tables_are_refused_with_their_own_token(run_script, iat_scenario_twin):
    result = run_script("iat_callsite_restore.py", iat_scenario_twin)
    assert result.returncode == 1, result.stderr
    assert "RESULT=ambiguous-iat" in result.stdout
    assert "discover ambiguous" in result.stdout
    assert "more than one run of pointers" in result.stdout


def test_a_clean_image_exits_zero(run_script, fixtures):
    result = run_script("iat_callsite_restore.py", fixtures.pe64.path)
    assert result.returncode == 0, result.stderr
    assert "RESULT=no-pairs" in result.stdout


def test_out_equal_to_the_input_is_a_usage_error(run_script, iat_scenario):
    scen = iat_scenario("pe64")
    result = run_script("iat_callsite_restore.py", scen.path, "--out", scen.path)
    assert result.returncode == 2
    assert "never written" in result.stderr


def test_a_non_pe_is_exit_three(run_script, tmp_path):
    junk = tmp_path / "notape.bin"
    junk.write_bytes(b"MZ" + b"\x00" * 200)
    result = run_script("iat_callsite_restore.py", junk)
    assert result.returncode == 3
    assert "error:" in result.stderr


def test_json_carries_the_document_then_the_verdict_line(run_script, iat_scenario):
    scen = iat_scenario("pe64")
    result = run_script("iat_callsite_restore.py", scen.path, "--iat", "0x3020,0x18", "--json")
    payload = document(result.stdout)
    lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
    assert lines[-1].startswith("RESULT=")
    assert payload["result"] == lines[-1].split("=", 1)[1]
    assert payload["input"]["bitness"] == scen.bitness
    assert payload["input"]["base_used"] == scen.base
    assert sorted(payload["iat"]["classes"]) == ["above_image", "below_image", "in_image", "zero"]
    assert [p["site_rva"] for p in payload["pairs"]] == [scen.sites["filler_after"],
                                                         scen.sites["filler_before"]]
    assert {r["reason"] for r in payload["refused"]} == {"no-filler", "ambiguous-slot"}
    assert "output" not in payload, "a report-only run must not claim an output file"
    assert payload["discovery"] is None, "--iat is the reader asserting the range; no search runs"


def test_full_out_writes_the_same_document_and_says_where(run_script, iat_scenario, tmp_path):
    scen = iat_scenario("pe64")
    record = tmp_path / "report.json"
    result = run_script("iat_callsite_restore.py", scen.path, "--iat", "0x3020,0x18",
                        "--full-out", record)
    assert result.returncode == 1
    assert "full record" in result.stdout
    saved = json.loads(record.read_text(encoding="utf-8"))
    assert saved["tool"] == "iat_callsite_restore.py"
    assert saved["result"] == "incomplete"


def test_max_sites_bounds_the_printed_lists(run_script, iat_scenario):
    scen = iat_scenario("pe64")
    result = run_script("iat_callsite_restore.py", scen.path, "--iat", "0x3020,0x18",
                        "--max-sites", "0")
    assert result.returncode == 1
    assert "more" in result.stdout
