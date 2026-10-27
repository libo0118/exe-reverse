# Extension: absorbing an import-virtualisation pass

What this pass covered, what it verified externally, and what it deliberately did not assert. The
material was three public write-ups of one protector family plus the source tree of an open-source
unpacker for it, read locally. No URL and no author is recorded here: neither was opened in this
session, and a citation that was not verified is a claim dressed as a reference.

The organising question is the one that decides what can be written down at all: **what is
mechanically true of an import layer once a protector rewrites it, and what belongs only to the
build the writer happened to have?**

## What was verified externally

| Fact | How it was established | Grade |
|---|---|---|
| The import layer is changed in two places, not one: the slot stops holding an address, and the call that read it becomes a relative call | Two write-ups describe the same pair of edits on the same product family, on different builds | `unverified` as target behaviour; `observed` that the sources say it |
| A repair can pair a site to a slot by comparing the site's computed target address with the table's values, then write an indirect call back | Read in the unpacker's fixup routine: it builds an address-to-slot map from the table, reads the relative target, and writes `FF 15`/`FF 25` | `observed` (of the source) |
| A newer generation computes each slot's value from a per-slot constant by arithmetic that is itself virtualised, so the handle-to-API mapping cannot be patched out | The same source states it in a comment at the point where it chooses to trace instead of patch | `observed` (of the source) |
| That unpacker repairs one anti-dump type only, and states that a target virtualising other regions will very likely still crash | Comment at the top of its anti-dump fixer | `observed` (of the source) |
| A dump of a target whose entry is virtualised does not run, and the tool says so rather than shipping it | Its own documentation | `observed` (of the documentation) |
| A working dump of such a target can be bound to the machine and session it was taken on, because some anti-dump checks compare module base addresses | The same documentation | `observed` (of the documentation) |
| A DLL dump loses relocation information | The same documentation | `observed` (of the documentation) |
| Targets from the late 2000s may only unpack on the OS generation they were built for | The same documentation | `observed` (of the documentation) |
| The operating system applies compatibility fixes keyed to an executable's path, so a program that crashed once can behave differently later with identical bytes | The same documentation names the mechanism and the store | `observed` (of the documentation); the store itself was not read here |
| One later build leaves the first code section untouched and only redirects the table | A write-up, on one build | `unverified` |
| A small, fixed set of runtime-owned imports is redirected twice | A write-up, on one build and one compiler | `unverified` |
| The filler byte of the 6-to-5 byte rewrite appears after the call, before it, and not at all, in different builds | Two write-ups plus the unpacker's handling of a site whose call is not at offset 0 | `unverified` |
| One write-up's version and date are internally inconsistent — it dates the build to a year, then calls the same build more than a decade old | Read here, in the source text | `observed` |

The last row is the reason the material was absorbed as mechanism only. A source that is wrong about
its own subject in one place can be wrong in another, and the wrong part does not announce itself.

## What this changed in the skill

- **New reference**, `references/iat-virtualization-and-call-site-rewriting.md`: the two-edit model,
  the pairing rule, the six-byte window and its three cases, the version-divergence table, the
  double-redirected set, the deliverable decision (repair / extract / observe / report), the limits
  an automatic unpacker inherits, and the verification rules.
- **Entry point**: five symptom rows and one route row, because "the import table parses but holds
  handles" and "a dump dies at its first imported call" are not findable from the existing rows.
- **`references/protectors-and-packers.md`**: one recognition row and a short section. The file states
  that it makes no product-level claims, so the mechanism stayed there and the detail did not.
- **`references/memory-and-dumps.md`**: call sites are part of a dump, not a detail of the import
  table, so the rebuild step now says that repairing the slots can restore a table nothing reads.
- **`references/dynamic-debugging.md`**: the instrument rule the second write-up actually
  demonstrates — a target that runs at full speed and dies when stopped has a perturbation detector,
  and the response is a different breakpoint family, not more hiding options.
- **`references/environment.md`**: the compatibility-shim fact, because it changes what "it ran
  once" means and it lives in neither file.
- **`scripts/iat_callsite_restore.py`** with a unit and a CLI layer, registered in the capability
  registry as `call_site_restore`.

## What was deliberately not asserted

- **No address, register name, opcode listing or script from any single build.** Those are the parts
  of the source material that stop being true first, and the skill already carries a rule that a
  build-level claim travels in the same sentence as the hash it was observed on.
- **No claim that the script works on a real protected sample.** It was exercised against a
  generated image whose three layout cases were written on purpose, so its rows are fixture-observed
  and say so. The route it implements is `unverified` against a protector until someone runs it.
- **No claim that repairing the call sites produces a working binary.** Virtualisation, anti-dump and
  self-integrity checks are separate problems and the reference says so in its own last section.
- **No claim that the filler byte is always a NOP.** One of the three placements has no filler, which
  is exactly why the script refuses that case instead of writing five bytes and a guess.
- **No product-strength opinion**, and none of the numeric claims from the write-ups (counts of
  redirected imports, section growth, timings) survived into the reference.

## Why this route is probed rather than declared

The repair is arithmetic over a file, so it can be tested without a target: a generated image, three
sites with deliberately different neighbours, and a slot range the import directory does not
describe. That is what the tests do, and it is why the script ships with refusals rather than
fallbacks — every fallback in this area (pick the first matching slot, overwrite the sixth byte, skip
a site silently) produces a file that loads and misbehaves later, which is the failure shape this
repository exists to make visible.
