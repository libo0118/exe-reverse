#!/usr/bin/env python3
"""Restore call sites a protector rewrote, by pairing them with their import slots.

Why this exists: on one family of protectors the import layer is changed twice at once. Each slot
stops holding the address of an imported function and starts holding a handle, and each call that
used to read that slot is rewritten from a six-byte indirect call into a five-byte relative call to
the handle. Repairing the slots alone restores a table the code no longer reads; repairing the call
sites alone sends every call back into a protector that is no longer running. Both edits are the same
repair, and the second one has a layout problem that this script refuses to guess at.

What it does, in order:

  1. Inventories the slots: from the import descriptors when they survived, from the import address
     table's directory range, and from an explicit --iat range. Records which source each slot came
     from, because the three do not always agree.
  2. Scans the executable sections for E8/E9 and computes each site's target address in the address
     space the image was captured at (--base, not the header's preferred base).
  3. Pairs a site to a slot when the target address *equals* the slot's value. That is the whole
     pairing rule.
  4. If the described table explained none of the calls, looks for the table the calls do explain:
     the non-executable sections are scanned for pointer-sized values equal to a call target, the
     matches are clustered, and a single cluster is used. Two clusters are reported and not used,
     because choosing between two runs of matching pointers is how a call ends up going through the
     wrong slot. Suppress the whole step with --no-discover, or name the range with --iat.
  5. Decides the sixth byte. The rewrite is five bytes into six, so it fits only where a sixth byte
     is available: a NOP after the call (rewrite in place), a NOP before it (the window starts one
     byte earlier), or no filler at all -- in which case the sixth byte belongs to the next
     instruction and the repair is *structural*. That last case is refused, not forced.
  6. Rewrites, then re-reads the written file and re-decodes every site to confirm it addresses the
     intended slot.

What it refuses, and why a refusal is the useful output:

  * a site whose target matches two slots (two slots holding the same address). A map keyed by value
    keeps the last one silently, so one call ends up going through the wrong slot and still works
    often enough to be mistaken for a success;
  * a site with no filler byte, because writing there overwrites the first byte of the next
    instruction -- a length change, which is a structural edit and not a byte swap;
  * two candidate windows that overlap, because neither can be written without destroying the other;
  * two runs of slot values matching different call targets, because a single pick from two is a
    coin toss that the file will not reveal.

What it does not do: unpack. It assumes you already have an image whose code is decrypted. It does
not devirtualise, does not resolve handles by arithmetic, and does not carry a table of known
protector versions. When the slots hold handles rather than addresses it reports needs-trace and
stops, because the handle-to-API mapping cannot be derived from the file.

Usage:
    python iat_callsite_restore.py dumped.exe                    # report only, writes nothing
    python iat_callsite_restore.py dumped.exe --out fixed.exe    # rewrite and verify
    python iat_callsite_restore.py dumped.exe --base 0x2B0000 --iat 0x48D000,0x1000
    python iat_callsite_restore.py dumped.exe --no-discover      # control: described slots only
    python iat_callsite_restore.py dumped.exe --json --full-out report.json

Exit codes: 0 = the analysis completed and no site was refused (result no-pairs, needs-trace,
report-only or repaired), 1 = at least one site was refused, a rewrite failed verification, the run
had no slot values to pair against, or discovery found two candidate tables, 2 = usage error,
3 = the input is not a parseable PE.
"""
import argparse
import hashlib
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from peutil import PE, ParseError, DIR_IAT, s32       # noqa: E402

DEFAULT_MAX_SITES = 40
DEFAULT_DISCOVER_GAP = 0x1000   # one page: the unit the loader protects, so a natural table edge
SECTION_EXECUTE = 0x20000000
SECTION_CODE = 0x00000020

CALL = 0xE8
JMP = 0xE9
OP_CALL_IND = 0x15          # FF /2, [mem]
OP_JMP_IND = 0x25           # FF /4, [mem]
NOP = 0x90
SITE_REL_LEN = 5            # E8/E9 + rel32
SITE_ABS_LEN = 6            # FF 15/25 + disp32


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def is_executable(section):
    c = section.characteristics or 0
    return bool(c & SECTION_EXECUTE) or bool(c & SECTION_CODE)


def read_ptr(pe, rva):
    """Pointer-sized value at an RVA, or None when the bytes are not in the file."""
    n = 8 if pe.is_pe32plus else 4
    raw = pe.rva_bytes(rva, n)
    if len(raw) < n:
        return None
    return struct.unpack('<Q' if n == 8 else '<I', raw)[0]


def parse_range(text):
    """'0x48D000,0x1000' or '0x48D000:0x1000' -> (rva, size)."""
    if not text:
        return None
    body = text.replace(':', ',').split(',')
    if len(body) != 2:
        raise ValueError('expected RVA,SIZE')
    return int(body[0], 0), int(body[1], 0)


def slots_from_range(pe, start, length, source, slots):
    """Add every pointer-sized entry in [start, start+length) to the inventory.

    Slot tables are pointer-aligned in every build seen here, so an unaligned walk is not offered:
    a half-aligned table would mix the low half of one entry with the high half of the next, and
    the resulting values would pair nothing while looking like a real inventory.
    """
    step = 8 if pe.is_pe32plus else 4
    added = False
    for slot_rva in range(start, start + length - step + 1, step):
        if slot_rva in slots:
            continue
        value = read_ptr(pe, slot_rva)
        if value is None:
            continue
        slots[slot_rva] = {'value': value, 'source': source}
        added = True
    return added


def slot_inventory(pe, iat_override):
    """{rva: {'value': int, 'source': str}} plus the list of sources actually used."""
    slots = {}
    sources = []

    for desc in pe.imports():
        used = False
        for fn in desc['functions']:
            rva = fn.get('iat_rva')
            if rva is None or rva in slots:
                continue
            value = read_ptr(pe, rva)
            if value is None:
                continue
            slots[rva] = {'value': value, 'source': 'import-descriptor'}
            used = True
        if used:
            sources.append('import-descriptor')

    rva, size = pe.directories.get(DIR_IAT, (0, 0))
    if rva and size and slots_from_range(pe, rva, size, 'iat-directory', slots):
        sources.append('iat-directory')

    if iat_override:
        start, length = iat_override
        if slots_from_range(pe, start, length, 'explicit-range', slots):
            sources.append('explicit-range')

    return slots, sources


def classify_slots(pe, base, slots):
    """Where each slot's value sits relative to the image.

    The classes describe magnitude, not meaning: a value below the image is an unbound table entry
    (an RVA) as easily as it is a handle, and the two are told apart by whether a call targets it,
    not by arithmetic. Naming them as if they were interpreted was the first version of this
    function and it reported every ordinary unbound import table as protected.
    """
    out = {'zero': 0, 'below_image': 0, 'in_image': 0, 'above_image': 0}
    end = base + (pe.size_of_image or 0)
    for info in slots.values():
        value = info['value']
        if value == 0:
            info['class'] = 'zero'
        elif value < base:
            info['class'] = 'below_image'
        elif value < end:
            info['class'] = 'in_image'
        else:
            info['class'] = 'above_image'
        out[info['class']] += 1
    return out


def walk_sites(pe, base):
    """Every E8/E9 in an executable section, with the absolute target it computes to.

    Split from the pairing because discovery needs the targets *before* any slot exists, which is
    the whole point of discovery. Keeping one function that both walked and paired made that
    ordering impossible to express.
    """
    sites = []
    counts = {'bytes': 0, 'e8': 0, 'e9': 0, 'examined': 0, 'interior': 0}
    sections = []

    for sec in pe.sections:
        if not is_executable(sec):
            continue
        start = sec.raw_pointer or 0
        size = sec.raw_size or 0
        if not start or size < SITE_REL_LEN:
            continue
        data = pe.d[start:start + size]
        sections.append({'name': sec.name, 'rva': sec.virtual_address, 'raw_size': size})
        counts['bytes'] += len(data)

        for off in range(0, len(data) - SITE_REL_LEN + 1):
            op = data[off]
            if op != CALL and op != JMP:
                continue
            counts['e8' if op == CALL else 'e9'] += 1
            rva = sec.virtual_address + off
            target_va = base + rva + SITE_REL_LEN + s32(data, off + 1)
            counts['examined'] += 1
            sites.append({'site_rva': rva,
                          'kind': 'call' if op == CALL else 'jmp',
                          'target_va': target_va})

    return sites, sections, counts


def pair_sites(pe, base, sites, value_index):
    """A pair is a site whose target equals a slot's value; the rest is reported, never repaired."""
    pairs = []
    unpaired = []
    interior = 0
    for site in sites:
        slot_rvas = value_index.get(site['target_va'])
        if slot_rvas:
            pairs.append({
                'site_rva': site['site_rva'],
                'kind': site['kind'],
                'target_va': site['target_va'],
                'slot_rvas': sorted(slot_rvas),
            })
        elif pe.section_of_rva(site['target_va'] - base) is None:
            unpaired.append({'site_rva': site['site_rva'], 'target_va': site['target_va']})
        else:
            interior += 1
    return pairs, unpaired, interior


def invert(slots):
    """value -> [slot rva, ...]. A list, because two slots holding one address is a real case."""
    index = {}
    for rva, info in slots.items():
        index.setdefault(info['value'], []).append(rva)
    return index


def discover_iat(pe, base, target_vas, max_gap):
    """Find the slot table from the calls: the table holds the values those calls target.

    Why this works at all: the rewrite replaced "call through the slot" with "call the stub", so the
    slot still holds the stub's address in the builds where the table survived with stubs in it. No
    import data is needed -- the targets are the search key.

    Why it refuses: one cluster of matches is used; two or more are reported and not used, because
    choosing one of two runs of matching pointers is the kind of guess that yields a file which
    loads and calls the wrong API. A single match is called weak for the same reason: one pointer
    that happens to equal a target is a coincidence until something else agrees with it.

    The gap tolerance is one page by default, because a page is the unit the loader protects: a
    table split across pages is unusual, and a run of matches that spans pages without a
    protection boundary between them is one table.
    """
    step = 8 if pe.is_pe32plus else 4
    fmt = '<Q' if pe.is_pe32plus else '<I'
    want = set(target_vas)
    hits = []
    scanned = []

    for sec in pe.sections:
        if is_executable(sec):
            continue
        start = sec.raw_pointer or 0
        size = sec.raw_size or 0
        if not start or size < step:
            continue
        data = pe.d[start:start + size]
        scanned.append({'name': sec.name, 'rva': sec.virtual_address, 'raw_size': size})
        for off in range(0, len(data) - step + 1, step):
            if struct.unpack_from(fmt, data, off)[0] in want:
                hits.append(sec.virtual_address + off)

    hits.sort()
    clusters = []
    for rva in hits:
        if clusters and rva - clusters[-1][-1] <= max_gap:
            clusters[-1].append(rva)
        else:
            clusters.append([rva])

    detail = [{'start': c[0], 'end': c[-1] + step, 'hits': len(c)} for c in clusters]
    chosen = None
    if len(clusters) == 1 and len(clusters[0]) >= 2:
        status = 'unique'
        chosen = {'start': clusters[0][0], 'size': clusters[0][-1] - clusters[0][0] + step}
    elif len(clusters) > 1:
        status = 'ambiguous'
    elif len(clusters) == 1:
        status = 'weak'
    else:
        status = 'none'

    return {'status': status, 'targets': len(want), 'hits': len(hits), 'scanned': scanned,
            'clusters': detail, 'chosen': chosen, 'max_gap': max_gap}


def plan_windows(pe, pairs):
    """Decide the six-byte window for each pair, or refuse it.

    The filler byte is the whole difficulty: 'NOP after' means the window is the site, 'NOP before'
    means it starts one byte earlier, and no filler at all means the rewrite would consume the first
    byte of the following instruction.
    """
    planned = []
    refused = []
    claimed = []

    for pair in pairs:
        if len(pair['slot_rvas']) > 1:
            refused.append({
                'site_rva': pair['site_rva'],
                'reason': 'ambiguous-slot',
                'detail': 'target %#x is held by %d slots: %s' % (
                    pair['target_va'], len(pair['slot_rvas']),
                    ', '.join('%#x' % r for r in pair['slot_rvas'])),
            })
            continue

        site_rva = pair['site_rva']
        after = pe.rva_bytes(site_rva + SITE_REL_LEN, 1)
        before = pe.rva_bytes(site_rva - 1, 1) if site_rva >= 1 else b''
        if after == bytes([NOP]):
            window = site_rva
        elif before == bytes([NOP]):
            window = site_rva - 1
        else:
            refused.append({
                'site_rva': site_rva,
                'reason': 'no-filler',
                'detail': 'byte at %#x is %s, byte before is %s; the rewrite needs six bytes '
                          'and the sixth belongs to the next instruction'
                          % (site_rva + SITE_REL_LEN, _hex(after), _hex(before)),
            })
            continue

        if pe.section_of_rva(window) is None or pe.section_of_rva(window + SITE_ABS_LEN - 1) is None:
            refused.append({'site_rva': site_rva, 'reason': 'window-outside-section',
                            'detail': 'six-byte window at %#x crosses a section boundary' % window})
            continue

        if any(not (window + SITE_ABS_LEN <= a or b <= window) for a, b in claimed):
            refused.append({'site_rva': site_rva, 'reason': 'window-overlap',
                            'detail': 'window at %#x overlaps another window' % window})
            continue

        claimed.append((window, window + SITE_ABS_LEN))
        planned.append({'site_rva': site_rva, 'window_rva': window, 'kind': pair['kind'],
                        'target_va': pair['target_va'], 'slot_rva': pair['slot_rvas'][0]})

    return planned, refused


def _hex(raw):
    return ' '.join('%02x' % b for b in raw) if raw else 'absent'


def encode_site(pe, base, window_rva, kind, slot_rva):
    """FF 15/25 + displacement. PE32 addresses the slot absolutely; PE32+ is RIP-relative."""
    slot_va = base + slot_rva
    op = OP_CALL_IND if kind == 'call' else OP_JMP_IND
    if pe.is_pe32plus:
        disp = slot_va - (base + window_rva + SITE_ABS_LEN)
    else:
        disp = slot_va
    raw = struct.pack('<I', disp & 0xFFFFFFFF)
    return bytes([0xFF, op]) + raw


def verify_written(blob, pe_out, base, planned):
    """Re-decode every written site from the output bytes. Returns a list of failures."""
    failures = []
    for item in planned:
        raw = pe_out.rva_bytes(item['window_rva'], SITE_ABS_LEN)
        if len(raw) < SITE_ABS_LEN:
            failures.append({'window_rva': item['window_rva'], 'reason': 'unreadable'})
            continue
        want_op = OP_CALL_IND if item['kind'] == 'call' else OP_JMP_IND
        if raw[0] != 0xFF or raw[1] != want_op:
            failures.append({'window_rva': item['window_rva'], 'reason': 'opcode',
                             'detail': _hex(raw)})
            continue
        if pe_out.is_pe32plus:
            effective = (base + item['window_rva'] + SITE_ABS_LEN + s32(raw, 2)) & 0xFFFFFFFFFFFFFFFF
        else:
            # PE32 addresses the slot absolutely, so the field is the address and not an offset.
            effective = struct.unpack('<I', raw[2:])[0]
        want = base + item['slot_rva']
        if effective != want:
            failures.append({'window_rva': item['window_rva'], 'reason': 'target',
                             'detail': 'decoded %#x, expected slot %#x' % (effective, want)})
    return failures


def build_report(args, blob, pe, data_out_note=None):
    base = args.base if args.base is not None else pe.image_base
    slots, sources = slot_inventory(pe, args.iat)
    described = len(slots)
    sites, sections, counts = walk_sites(pe, base)

    pairs, unpaired, interior = pair_sites(pe, base, sites, invert(slots))
    counts['interior'] = interior

    discovery = None
    # Discovery runs when the described table did not explain the calls: either there was no
    # inventory at all, or it produced no pair while calls still leave the image. An explicit --iat
    # suppresses it, because that is the reader asserting the range.
    if not args.no_discover and not args.iat and not pairs:
        outside = {s['target_va'] for s in sites if pe.section_of_rva(s['target_va'] - base) is None}
        if outside:
            discovery = discover_iat(pe, base, outside, args.discover_gap)
            discovery['trigger'] = 'no-slots' if described == 0 else 'no-pairs'
            if discovery['chosen']:
                added = slots_from_range(pe, discovery['chosen']['start'],
                                         discovery['chosen']['size'], 'discovered-range', slots)
                discovery['used'] = bool(added)
                if added:
                    sources.append('discovered-range')
                    pairs, unpaired, interior = pair_sites(pe, base, sites, invert(slots))
                    counts['interior'] = interior
            else:
                discovery['used'] = False

    classes = classify_slots(pe, base, slots)
    planned, refused = plan_windows(pe, pairs)

    used = {item['slot_rva'] for item in planned}
    report = {
        'tool': 'iat_callsite_restore.py',
        'input': {
            'path': args.image,
            'sha256': sha256(blob),
            'size': len(blob),
            'bitness': 64 if pe.is_pe32plus else 32,
            'image_base_header': pe.image_base,
            'base_used': base,
            'base_source': 'explicit --base' if args.base is not None else 'header ImageBase',
        },
        'iat': {'sources': sources, 'slots': len(slots), 'classes': classes},
        'discovery': discovery,
        'sections_scanned': sections,
        'scan': counts,
        'pairs': planned,
        'refused': refused,
        'unpaired': unpaired,
        'slots_used': sorted(used),
        'slots_unused': len(slots) - len(used),
        'result': None,
    }
    if data_out_note:
        report['output'] = data_out_note
    return report


def decide_result(report, wrote):
    if report['refused'] or report.get('verification_failures'):
        return 'incomplete'
    discovery = report.get('discovery') or {}
    if discovery.get('status') == 'ambiguous':
        return 'ambiguous-iat'
    if report['pairs']:
        return 'repaired' if wrote else 'report-only'
    if not report['iat']['slots']:
        # No slot values at all is not evidence that the table is untouched: it is evidence that
        # this run has nothing to pair against. Reporting that as needs-trace sends the reader to
        # write a trace they do not need, which is the same misdiagnosis in a different direction.
        return 'no-slots'
    if report['unpaired']:
        return 'needs-trace'
    return 'no-pairs'


def print_report(report, max_sites):
    out = sys.stdout
    ident = report['input']
    out.write('input    %s\n' % ident['path'])
    out.write('         %d-bit, %d bytes, sha256 %s\n'
              % (ident['bitness'], ident['size'], ident['sha256'][:32] + '...'))
    out.write('         base %#x (%s)\n' % (ident['base_used'], ident['base_source']))
    if ident['base_used'] != ident['image_base_header']:
        out.write('         note: the header declares %#x; site targets are computed in the '
                  'address space you named\n' % ident['image_base_header'])
    out.write('slots    %d from %s\n'
              % (report['iat']['slots'],
                 ', '.join(report['iat']['sources']) or 'no source (no import data)'))
    classes = report['iat']['classes']
    out.write('         zero %d, below image %d, in image %d, above image %d\n'
              % (classes['zero'], classes['below_image'], classes['in_image'],
                 classes['above_image']))
    discovery = report.get('discovery')
    if discovery:
        out.write('discover %s after %s: %d call target(s), %d slot value(s) matched, %d cluster(s)\n'
                  % (discovery['status'], discovery['trigger'], discovery['targets'],
                     discovery['hits'], len(discovery['clusters'])))
        out.write('         scanned %s\n'
                  % (', '.join('%s@%#x' % (s['name'], s['rva'])
                               for s in discovery['scanned']) or 'no data section'))
        for cluster in discovery['clusters'][:max_sites]:
            out.write('         cluster %#010x..%#010x  %d hit(s)%s\n'
                      % (cluster['start'], cluster['end'], cluster['hits'],
                         '  <- used' if discovery['chosen']
                         and cluster['start'] == discovery['chosen']['start'] else ''))
    out.write('sections %s\n' % (', '.join('%s@%#x' % (s['name'], s['rva'])
                                           for s in report['sections_scanned']) or 'none'))
    scan = report['scan']
    out.write('scan     %d bytes, %d E8, %d E9, %d sites examined, %d interior calls ignored\n'
              % (scan['bytes'], scan['e8'], scan['e9'], scan['examined'], scan['interior']))

    shown = report['pairs'][:max_sites]
    out.write('pairs    %d\n' % len(report['pairs']))
    for item in shown:
        out.write('         site %#010x  window %#010x  %-4s -> slot %#010x\n'
                  % (item['site_rva'], item['window_rva'], item['kind'], item['slot_rva']))
    if len(report['pairs']) > max_sites:
        out.write('         ... %d more (raise --max-sites or use --json)\n'
                  % (len(report['pairs']) - max_sites))

    out.write('refused  %d\n' % len(report['refused']))
    for item in report['refused'][:max_sites]:
        out.write('         site %#010x  %s: %s\n'
                  % (item['site_rva'], item['reason'], item['detail']))

    out.write('unpaired %d\n' % len(report['unpaired']))
    for item in report['unpaired'][:max_sites]:
        out.write('         site %#010x  relative call leaves the image -> %#x, no slot holds it\n'
                  % (item['site_rva'], item['target_va']))
    if len(report['unpaired']) > max_sites:
        out.write('         ... %d more\n' % (len(report['unpaired']) - max_sites))

    if report['result'] == 'ambiguous-iat':
        out.write('next     more than one run of pointers matches the call targets, so no table was '
                  'chosen: name the range with --iat, or dump the table from the process and pass '
                  'it there. Picking one of these clusters is how a call ends up going through the '
                  'wrong slot\n')
    elif report['result'] == 'incomplete':
        out.write('next     each refusal is a decision for a person: a site with no filler byte is a '
                  'structural edit, and an ambiguous slot needs the trace that says which slot the '
                  'call actually used\n')
    elif report['result'] == 'no-slots':
        out.write('next     this run has no slot values to pair against: pass --iat RVA,SIZE with '
                  'the table range, or reconstruct the table first. Without it the sites below are '
                  'calls whose target nothing in this image holds\n')
    elif report['result'] == 'needs-trace':
        out.write('next     either the table does not hold these targets, or the base is not the '
                  'one the image ran at -- check --base first, because a wrong base produces the '
                  'same report and a different cause. If the base is right, the handle-to-API '
                  'mapping has to come from a trace of the resolver\n')
    elif report['result'] == 'report-only':
        out.write('next     re-run with --out to write the rewrite; the list above is the site list '
                  'the trace would otherwise have to be repeated for\n')

    for failure in report.get('verification_failures', []):
        out.write('VERIFY FAILED window %#010x: %s %s\n'
                  % (failure['window_rva'], failure['reason'], failure.get('detail', '')))
    if report.get('output'):
        o = report['output']
        out.write('output   %s\n         sha256 %s\n         checksum declared %#x computed %#x\n'
                  % (o['path'], o['sha256'], o['checksum_declared'], o['checksum_computed']))
    out.write('RESULT=%s\n' % report['result'])


def main():
    ap = argparse.ArgumentParser(
        description='Pair relative calls a protector left behind with their import slots, and '
                    'restore the indirect calls they replaced.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Report first, write second. A refusal is a finding, not a failure of the run:\n'
               '  python iat_callsite_restore.py dumped.exe\n'
               '  python iat_callsite_restore.py dumped.exe --base 0x2B0000 --out fixed.exe')
    ap.add_argument('image', help='the captured or rebuilt PE image to analyse')
    ap.add_argument('--out', help='write the repaired image here; without it nothing is written')
    ap.add_argument('--base', type=lambda v: int(v, 0),
                    help='address the image was captured at (default: the header ImageBase)')
    ap.add_argument('--iat', type=parse_range, metavar='RVA,SIZE',
                    help='explicit import-table range; suppresses discovery')
    ap.add_argument('--no-discover', action='store_true',
                    help='do not look for the table when the described slots pair nothing')
    ap.add_argument('--discover-gap', type=int, default=DEFAULT_DISCOVER_GAP, metavar='BYTES',
                    help='matches closer than this many bytes are one table (default %d, one page)'
                    % DEFAULT_DISCOVER_GAP)
    ap.add_argument('--max-sites', type=int, default=DEFAULT_MAX_SITES,
                    help='site rows printed per list (default %d)' % DEFAULT_MAX_SITES)
    ap.add_argument('--json', action='store_true', help='emit the report as JSON')
    ap.add_argument('--full-out', metavar='PATH',
                    help='write the complete report as JSON to PATH and report the path')
    args = ap.parse_args()

    if not os.path.isfile(args.image):
        sys.stderr.write('error: %s is not a file\n' % args.image)
        return 2
    if args.out and os.path.abspath(args.out) == os.path.abspath(args.image):
        sys.stderr.write('error: --out must differ from the input; the input is never written\n')
        return 2
    if args.max_sites < 0:
        sys.stderr.write('error: --max-sites must not be negative\n')
        return 2

    try:
        with open(args.image, 'rb') as fh:
            blob = fh.read()
        pe = PE(blob, args.image)
    except (ParseError, OSError) as exc:
        sys.stderr.write('error: %s: %s\n' % (args.image, exc))
        return 3

    report = build_report(args, blob, pe)
    wrote = False

    if args.out:
        out_blob = bytearray(blob)
        base = report['input']['base_used']
        for item in report['pairs']:
            raw = encode_site(pe, base, item['window_rva'], item['kind'], item['slot_rva'])
            off = pe.rva_to_offset(item['window_rva'])
            out_blob[off:off + SITE_ABS_LEN] = raw
        with open(args.out, 'wb') as fh:
            fh.write(out_blob)
        pe_out = PE(bytes(out_blob), args.out)
        failures = verify_written(bytes(out_blob), pe_out, base, report['pairs'])
        if failures:
            report['verification_failures'] = failures
        report['output'] = {
            'path': args.out,
            'sha256': sha256(bytes(out_blob)),
            'checksum_declared': pe_out.checksum or 0,
            'checksum_computed': pe_out.computed_checksum(),
            'verification': 'ok' if not failures else 'failed',
        }
        wrote = True

    report['result'] = decide_result(report, wrote)

    if args.full_out:
        with open(args.full_out, 'w', encoding='utf-8') as fh:
            json.dump(report, fh, indent=2, sort_keys=True)
            fh.write('\n')

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        print('RESULT=%s' % report['result'])
    else:
        print_report(report, args.max_sites)
        if args.full_out:
            sys.stdout.write('full record %s\n' % args.full_out)

    return 1 if report['result'] in ('incomplete', 'no-slots', 'ambiguous-iat') else 0


if __name__ == '__main__':
    sys.exit(main())
