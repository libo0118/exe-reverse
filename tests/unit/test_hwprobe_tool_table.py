"""The tool table's names are a claim about what is on the machine.

A name in this table is probed with shutil.which, so a name that also belongs to a common Unix
utility produces a false capability claim: the probe says the MSVC toolchain is present because
/usr/bin/link exists, and /usr/bin/link is coreutils' hard-link utility. That is the exact failure
shape this repository is built against -- a well-formed row that is confidently wrong -- and it was
found by reading the probe's own output on a Linux host, where link was reported present alongside a
note about the MSVC linker.
"""
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.unit

# Names that exist as ordinary Unix utilities, so probing them says nothing about the Windows tool
# they are paired with. Each entry is (name, the utility it collides with).
# binutils strings is deliberately not in this list: it reads PE images, so probing it on a Unix
# host is a true statement about a tool that does the job. link is different -- coreutils' link
# creates a hard link and has nothing to do with the MSVC linker it was paired with.
AMBIGUOUS = [
    ("link", "GNU coreutils hard-link utility"),
    ("install", "GNU coreutils file installer"),
]


def test_the_table_does_not_probe_an_ambiguous_name(load_script):
    names = dict(load_script("hwprobe.py").TOOL_NAMES)
    for name, collision in AMBIGUOUS:
        assert name not in names, (
            "%r is probed, but it is also the %s on every Unix host, so a hit is not evidence of "
            "the Windows tool being available" % (name, collision))


def test_editbin_replaces_link_for_header_edits(load_script):
    names = dict(load_script("hwprobe.py").TOOL_NAMES)
    assert "editbin" in names
    assert "header" in names["editbin"]


def test_no_probed_name_resolves_to_a_coreutils_binary(load_script):
    """The general form of the same defect, checked against this host rather than a list."""
    names = [name for name, _ in load_script("hwprobe.py").TOOL_NAMES]
    checked = 0
    for name in names:
        found = shutil.which(name)
        if not found:
            continue
        try:
            proc = subprocess.run([found, "--version"], capture_output=True, text=True,
                                  timeout=10, encoding="utf-8", errors="replace")
        except (OSError, subprocess.SubprocessError):
            continue
        checked += 1
        assert "GNU coreutils" not in (proc.stdout or ""), (
            "%r resolves to %s, which is a coreutils binary -- the row would claim a Windows tool"
            % (name, found))
    if not checked:
        pytest.skip("no probed tool on this host answers --version, so there is nothing to check")
