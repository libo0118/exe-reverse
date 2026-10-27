"""The import-layer repair's decisions, exercised on a generated scenario.

The script makes three decisions per call site and one per slot, and every one of them can be wrong
in a way that still produces a loadable file:

  * which six-byte window belongs to a site (the filler byte can be on either side),
  * whether a site can be rewritten at all (a site with no filler byte is a structural edit),
  * which slot a target belongs to (two slots can hold the same address).

So the tests are about those decisions rather than about the report's wording: each case asserts the
window or the refusal reason, and the ones covering the rewrite re-decode the bytes the script wrote
instead of trusting the counters it printed.
"""
import argparse

import pytest

pytestmark = pytest.mark.unit


def _args(image, **kw):
    base = {"image": str(image), "out": None, "base": None, "iat": None, "max_sites": 40}
    base.update(kw)
    return argparse.Namespace(**base)


def test_parse_range_accepts_both_separators(load_script):
    mod = load_script("iat_callsite_restore.py")
    assert mod.parse_range("0x48D000,0x1000") == (0x48D000, 0x1000)
    assert mod.parse_range("0x48D000:0x1000") == (0x48D000, 0x1000)
    with pytest.raises(ValueError):
        mod.parse_range("0x48D000")


def test_encode_site_is_rip_relative_on_pe32plus(iat_scenario, load_script):
    """PE32+ displacement is relative to the end of the instruction, not to the slot."""
    mod = load_script("iat_callsite_restore.py")
    scen = iat_scenario("pe64")
    pe = load_script("peutil.py").PE(scen.path.read_bytes())
    raw = mod.encode_site(pe, scen.base, 0x1200, "call", scen.slot_rva)
    assert raw[:2] == b"\xFF\x15"
    assert int.from_bytes(raw[2:], "little") == 0x3020 - 0x1200 - 6


def test_encode_site_is_absolute_on_pe32(iat_scenario, load_script):
    mod = load_script("iat_callsite_restore.py")
    scen = iat_scenario("pe32")
    pe = load_script("peutil.py").PE(scen.path.read_bytes())
    raw = mod.encode_site(pe, scen.base, 0x1200, "jmp", scen.slot_rva)
    assert raw[:2] == b"\xFF\x25"
    assert int.from_bytes(raw[2:], "little") == scen.base + scen.slot_rva


def test_plan_places_the_window_on_either_side_of_the_call(iat_scenario, load_script):
    mod = load_script("iat_callsite_restore.py")
    scen = iat_scenario("pe64")
    blob = scen.path.read_bytes()
    pe = load_script("peutil.py").PE(blob)
    pairs = [
        {"site_rva": scen.sites["filler_after"], "kind": "call", "target_va": 0,
         "slot_rvas": [scen.slot_rva]},
        {"site_rva": scen.sites["filler_before"], "kind": "call", "target_va": 0,
         "slot_rvas": [scen.slot_rva]},
    ]
    planned, refused = mod.plan_windows(pe, pairs)
    assert refused == []
    windows = {item["site_rva"]: item["window_rva"] for item in planned}
    assert windows[scen.sites["filler_after"]] == scen.sites["filler_after"]
    assert windows[scen.sites["filler_before"]] == scen.sites["filler_before"] - 1


def test_plan_refuses_a_site_whose_sixth_byte_is_an_instruction(iat_scenario, load_script):
    """The byte after the call here is a return, so writing would consume the next instruction."""
    mod = load_script("iat_callsite_restore.py")
    scen = iat_scenario("pe64")
    pe = load_script("peutil.py").PE(scen.path.read_bytes())
    pairs = [{"site_rva": scen.sites["no_filler"], "kind": "call", "target_va": 0,
              "slot_rvas": [scen.slot_rva]}]
    planned, refused = mod.plan_windows(pe, pairs)
    assert planned == []
    assert [r["reason"] for r in refused] == ["no-filler"]
    assert "next instruction" in refused[0]["detail"]


def test_plan_refuses_a_target_two_slots_hold(iat_scenario, load_script):
    mod = load_script("iat_callsite_restore.py")
    scen = iat_scenario("pe64")
    pe = load_script("peutil.py").PE(scen.path.read_bytes())
    pairs = [{"site_rva": scen.sites["ambiguous"], "kind": "call",
              "target_va": scen.base + 0x9100, "slot_rvas": list(scen.dup_slot_rvas)}]
    planned, refused = mod.plan_windows(pe, pairs)
    assert planned == []
    assert [r["reason"] for r in refused] == ["ambiguous-slot"]
    for rva in scen.dup_slot_rvas:
        assert "%#x" % rva in refused[0]["detail"]


def test_the_report_pairs_the_restorable_sites_and_names_the_others(iat_scenario, load_script):
    mod = load_script("iat_callsite_restore.py")
    scen = iat_scenario("pe64")
    blob = scen.path.read_bytes()
    pe = load_script("peutil.py").PE(blob)
    args = _args(scen.path, iat=(0x3020, 0x18))
    report = mod.build_report(args, blob, pe)

    assert [p["site_rva"] for p in report["pairs"]] == [scen.sites["filler_after"],
                                                        scen.sites["filler_before"]]
    assert {r["reason"] for r in report["refused"]} == {"no-filler", "ambiguous-slot"}
    assert "explicit-range" in report["iat"]["sources"]
    assert report["input"]["base_used"] == scen.base


def test_without_the_slot_range_the_report_says_needs_trace(iat_scenario, load_script):
    """No slot describes these targets, and the calls leave the image: that is the handle case.

    It is also the reason the verdict is not "clean". Nothing was found by pairing, and the correct
    reading is that pairing cannot work on this image, not that the image is untouched.
    """
    mod = load_script("iat_callsite_restore.py")
    scen = iat_scenario("pe64")
    blob = scen.path.read_bytes()
    pe = load_script("peutil.py").PE(blob)
    report = mod.build_report(_args(scen.path), blob, pe)
    assert report["pairs"] == []
    assert len(report["unpaired"]) == 4
    assert mod.decide_result(report, wrote=False) == "needs-trace"


def test_a_wrong_base_produces_the_same_verdict_as_a_missing_table(iat_scenario, load_script):
    """Two different causes, one report -- which is why the printed hint names the base first.

    A site's target is computed in the address space the image ran at, so a base off by the
    relocation delta turns every real pair into an unpaired call. The verdict cannot tell the two
    apart, and a reader who assumes "the table holds handles" from this report alone would go and
    write a trace they do not need.
    """
    mod = load_script("iat_callsite_restore.py")
    scen = iat_scenario("pe64")
    blob = scen.path.read_bytes()
    pe = load_script("peutil.py").PE(blob)
    report = mod.build_report(_args(scen.path, base=0x400000, iat=(0x3020, 0x18)), blob, pe)
    assert report["pairs"] == []
    assert len(report["unpaired"]) == 4
    assert mod.decide_result(report, wrote=False) == "needs-trace"
    assert report["input"]["base_source"] == "explicit --base"


def test_a_clean_image_reports_no_pairs(load_script, fixtures):
    mod = load_script("iat_callsite_restore.py")
    blob = fixtures.pe64.data
    pe = load_script("peutil.py").PE(blob)
    report = mod.build_report(_args(fixtures.pe64.path), blob, pe)
    assert report["pairs"] == []
    assert report["unpaired"] == []
    assert mod.decide_result(report, wrote=False) == "no-pairs"


def test_no_slot_values_is_its_own_verdict(load_script):
    """A run with nothing to pair against must not send the reader to write a trace.

    Both causes -- a table that holds handles, and a table this run never found -- produce the same
    empty pair list. The first needs a trace; the second needs --iat. Collapsing them into one token
    was the first version of this rule.
    """
    mod = load_script("iat_callsite_restore.py")
    with_no_slots = {"pairs": [], "refused": [], "unpaired": [1], "iat": {"slots": 0, "classes": {}}}
    assert mod.decide_result(with_no_slots, wrote=False) == "no-slots"
    with_slots = {"pairs": [], "refused": [], "unpaired": [1],
                  "iat": {"slots": 4, "classes": {}}}
    assert mod.decide_result(with_slots, wrote=False) == "needs-trace"


def test_result_tokens_follow_the_evidence(load_script):
    mod = load_script("iat_callsite_restore.py")
    base = {"pairs": [], "refused": [], "unpaired": [], "iat": {"slots": 4, "classes": {}}}
    assert mod.decide_result(dict(base), wrote=False) == "no-pairs"
    assert mod.decide_result(dict(base, pairs=[1]), wrote=False) == "report-only"
    assert mod.decide_result(dict(base, pairs=[1]), wrote=True) == "repaired"
    assert mod.decide_result(dict(base, unpaired=[1]), wrote=False) == "needs-trace"
    assert mod.decide_result(dict(base, refused=[1]), wrote=True) == "incomplete"
    assert mod.decide_result(dict(base, verification_failures=[1]), wrote=True) == "incomplete"
