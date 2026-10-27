# IAT Virtualization and Call-Site Rewriting

Goal: decide whether the import layer you are looking at is a table of addresses or a table of
handles, and either restore the two things a protector changed together — or establish that the
deliverable does not need them restored.

## When to load this

Load it when the import table exists but does not behave like one:

- the import directory parses, and every slot holds a small value that is not an address, or a
  value that lies inside the protector's own section
- a call in the first code section is `E8 rel32` where the compiler's own output for that source
  would be `call dword ptr [iat]`
- `FF 15` occurs a handful of times in a code section of a hundred kilobytes, while `E8` occurs
  thousands of times
- a dump loads, then faults or exits the first time the program calls an imported API
- someone has asked you to "repair the IAT" and there is no name in the image to repair it to
- you are about to describe a dump as "almost working"

The last row is the one this file exists for. "Only the IAT is broken" is a diagnosis, and on a
protector that rewrites call sites it is usually half a diagnosis.

## Two edits, not one

An import-based call is two objects that a protector can treat separately, and this family of
protectors treats both:

| Object | What the compiler emitted | What the protector makes it | Restoring it alone leaves |
|---|---|---|---|
| The IAT slot | the address of the imported function, resolved by the loader | a handle: a small tag, or the address of a stub inside the protector's section | a correct table nothing reads — every call still targets the stub directly |
| The call site | `FF 15 disp32` — call through the slot, six bytes | `E8 rel32` — a direct relative call to the stub, five bytes plus one filler byte | every call now reads a slot that still holds a handle, so it lands in the stub that no longer runs |

A repair that touches one without the other produces a file that loads and then dies in a way that
looks like a bad dump. Both edits are needed, and the second is the one with a layout problem.

**Why the filler byte matters.** The rewrite is 6 bytes to 5, so the protector has one byte left
over per site. Public write-ups of 32-bit builds describe three placements: a `NOP` after the
relative call, a `NOP` before it, and no filler at all where the byte that follows is the next
instruction (`unverified` for any given build; observed as three distinct forms across two
write-ups). Restoring the site reverses a 5-byte form into a 6-byte form, so it fits only where a
sixth byte is actually available. Where it is not, the repair is a **structural** edit — the
following instruction has to move — and no automatic writer can decide that from bytes alone.

**One more difference that must be respected.** In a 32-bit image `FF 15 disp32` addresses the slot
absolutely; in a 64-bit image it is RIP-relative, so the displacement is relative to the *end* of
the instruction. The same source-level call compiles to the same two bytes and a different
displacement. Write the wrong one and the site calls whatever lives at that address.

## Recognising the layer without running anything

| Evidence | What it indicates | Strength |
|---|---|---|
| Import directory present, and its slots hold values that resolve to nothing in the image | Slot replacement with a tag or an index rather than an address | `inferred` |
| Import directory present, slots hold addresses inside a section that is executable and writable | Slot replacement with a stub address in the protector's own code | `inferred` |
| `E8`/rel32 everywhere, `FF 15`/`FF 25` almost absent, in a native image | Call sites rewritten from indirect to direct | `inferred` |
| A relative call whose computed target lies outside every section of the image | The target is a stub the protector allocated, not code in this image, and the image cannot run as it stands | `inferred` |
| Sections named for the protector, with one large executable and writable region | The stub table lives there | `inferred` |
| A run of short functions in that region, each ending in a jump through a pointer | One stub per imported API, dispatching into the protector's resolver | `inferred` |

**A value below the image base is not by itself evidence of anything.** An ordinary unbound import
table holds RVAs, and an RVA is also a number below the base. The first version of the repair script
classified every such slot as a handle and reported ordinary unbound images as protected, which is
the failure mode this repository calls a confident wrong answer. The discriminator is whether the
value resolves to something in the image, and whether any call targets it — not its magnitude. A
tool that reports slot classes should report them as positions (below the image, inside it, above
it) and let the pairing decide what they mean.

Counting the two call forms is the cheapest confirmation and it needs no new tool:
`scripts/aob_scan.py` takes a pattern and returns how many sites matched, so `FF 15` and `E8` over
the same section turn an impression into two numbers. Record both, and record the section they
were counted over.

## The repair, in order

1. **Establish the address the code runs at.** Sites are relative, so every target you compute is
   the address in the session the image was captured from, not the file's preferred base. A dump
   taken at a relocated base is the normal case. Take the base from the capture, not from the header
   — and record which one you used.
2. **Inventory the slots.** Three sources, in descending order of trust: the import descriptors if
   they survived, the import address table directory's range if it did, and the addresses that a
   write watch reported. Say which source the inventory came from; they do not always agree. An
   inventory that came back empty is a finding about this run, not a table that holds no addresses:
   it means the range has to be supplied or rebuilt before any pairing is possible — or found, which
   is the search described below.
3. **Pair a site to a slot by value.** The site's target address equals the slot's value. This is
   the whole pairing rule, and it is also the mechanism an open-source unpacker's fixup routine
   implements (`observed` in that source: it reads the target from the relative call, looks it up in
   an address-to-slot map built from the table, and writes an indirect call back).
4. **Refuse the ambiguous pairs.** Two slots can hold the same address — a second redirect pass, a
   bound slot, a duplicated descriptor. A map keyed by value silently keeps the last one, which
   produces a file where one call goes through the wrong slot and still works often enough to be
   mistaken for a success. Report the duplicate and leave both alone unless a person resolves it.
5. **Decide the sixth byte.** Filler after: rewrite in place. Filler before: the six-byte window
   starts one byte earlier. No filler: stop, and report it as a structural repair.
6. **Write, then re-read.** Re-decode every rewritten site from the written file and confirm it now
   addresses the intended slot. A patch that assembles and is never reached is the failure this
   step exists for.
7. **Report the leftovers.** Sites with no slot and slots with no site are the content of the
   report, not noise around it: the first is a call the protector resolved by some other route, the
   second is an import nothing in this code section uses.

## When there is no table to inventory

A captured image frequently has none of the three sources: the protector destroyed the directory and
no write watch was taken. The table is still findable, because the rewrite left one relation behind —
**the slot holds the address the call targets**. So the call sites can be used as the search key:

1. Collect the targets of the relative calls that leave the image. Those are the stubs.
2. Scan the **non-executable** sections for pointer-aligned entries equal to one of those targets.
3. Cluster the matches by proximity. One cluster is the table; the range it spans is the inventory.

Two rules keep this from becoming a guess. **Two clusters are refused**, and both are printed: a
duplicated table, a copied table and a table split by a section boundary all look like this from the
outside, and choosing one of two runs of matching pointers produces a file that loads and calls the
wrong API for one import. **A single match is reported as weak**, because one pointer that happens to
equal a call target is a coincidence until a second entry agrees with it.

Two properties of the search are worth knowing before reading its result. It finds nothing when the
slots hold tags rather than stub addresses — that build has no value relation to search — and it finds
nothing when the base is wrong, because every candidate target is then computed in the wrong address
space. Those two failures look identical and need opposite responses, so check the base before
concluding that the table holds handles.

## Version divergence, and why this is a map rather than a fact

One product family, three observable behaviours, from two public write-ups and one unpacker's
source:

| Behaviour | Where it was observed | What it changes about the plan |
|---|---|---|
| The first code section is modified: call sites become relative calls | 32-bit write-up, older build | Both edits are required, and the dump contains the rewritten sites |
| The first code section is **not** modified; only the slots are redirected | another write-up, a later build | Site rewriting is unnecessary; the work is the slot-to-name mapping and nothing else |
| Every site is still written, but with the bytes already there | an unpacker's source comment | A write-watch fires thousands of times and changes nothing; a plan built on "count the writes" spends hours on no-ops |
| Slot values are computed from a per-slot constant by arithmetic that is itself virtualised | the same source, for its newest supported generation | The handle-to-API mapping **cannot** be derived offline. It is traced or not obtained |

All four are claims about particular builds, and none is `observed` on a target here: the first two
come from write-ups and the last two from a tool's source, which records what its author found rather
than what this repository ran. The transferable part is the **shape** — one product can present as any
of these, so the first task on a sample is to decide which row it is in, with evidence, before writing
any repair.

## The set of APIs that is redirected twice

One write-up reports that a small set of runtime-owned imports is redirected by a second, different
mechanism, so a naive pairing resolves them to the wrong function or to a duplicate of a previous
entry (`unverified`). The members it named are heap and error-state routines plus process exit and
unwind. Two observations about that list are worth more than the list:

- The set is small and it is **language- and version-specific**. It reflects which imports the
  runtime calls before it can call anything else.
- The useful artifact is not the list but the **test**: for each slot the pairing left unresolved,
  call it once and see which module and export the call lands in. That answers the question on the
  sample in front of you, and it answers it for a build nobody has written about.

## Deciding the deliverable: repair, extract, observe, or report

Repairing the import layer assumes there is a native image worth repairing. When the entry point or
the region that matters is virtualised, there is no original entry point in machine code, so there
is nothing to point the header at and no site list to restore.

| Situation | Deliverable | What "verified" then means |
|---|---|---|
| Code is restored, only the import layer is wrong | a repaired image | it loads, and each restored site's call returns from the intended export |
| Entry or hot region is virtualised, the payload is what is wanted | the payload, as data | it disassembles coherently at a stated base, and its configuration cross-references |
| The question is what the code does, not what the file is | a report | every claim names the site it came from |
| A local change is enough | a live patch | the patch is reached at run time, not merely present |

A scanner hit on an extracted payload is a **lead in both directions**: a detection is evidence the
bytes are the real thing, and a clean scan is not evidence they are not. Neither substitutes for
reading the entry and the configuration.

## What an automatic unpacker settles, and what it does not

An unpacker automates the three steps a person performs by hand: stop at the right moment, capture
what the protector wrote, and apply the fixups offline. Its output is a **dump with the call-site
layer repaired**, and it inherits every limit of the dump it came from. Documented limits, from the
tools' own material (`observed` in their documentation and source):

| Limit | Consequence |
|---|---|
| Anti-dump measures on the entry or on virtualised code are not repaired | A dump whose entry is virtualised does not run, and the tool says so |
| Some anti-dump checks compare module base addresses captured at run time | The dump may run on the machine and session that produced it and fail after a reboot or elsewhere |
| A DLL dump loses relocation information | The image cannot be loaded anywhere but the base it was captured at |
| Targets built for an OS generation two decades old may only unpack on that generation | The result depends on the unpacking host, which is a property of the experiment |
| Compatibility shims applied by the operating system to a program that crashed before change its behaviour | The unpacker and the target can see different behaviour, and the shim is invisible in the binary |
| Newer builds of the protector detect hardware breakpoints | The instrument question comes before the unpacking question |

Two of these are verification rules rather than unpacking rules, and they are the ones most often
skipped: **a dump that runs is not yet a portable artifact** — re-run it after a reboot and on a
second host, and record both results; and **the host is part of the experiment** — the same file can
behave differently because the operating system shimmed it, so check before attributing a rare
failure to the protector.

## Verification

1. The loader accepting the file is a statement about layout. Exercise the calls before saying more.
2. For each distinct slot that was restored, at least one call through it must return. A run that
   never reaches the restored region proves nothing about the repair.
3. A base-address-bound dump is a limitation to state, not a defect to hide: name the base and the
   session.
4. Record which slots were paired by value and which by tracing. They carry different confidence.
5. A refusal is a result. "Nine sites restored, one refused because its sixth byte is the next
   instruction" is a finished finding; "the IAT is fixed" is not.

## What this file does not contain

- No addresses, register names, opcode sequences or script listings from a single build. Those are
  properties of one sample and are the first thing that stops being true.
- No claim about any protector's strength.
- No promise that repairing the import layer produces a working binary. Virtualised regions,
  anti-dump checks and self-integrity checks are separate problems with separate files.

## Related material in this skill

- `references/protectors-and-packers.md` — is this a compressor or a protector, and is unpacking
  the right route at all
- `references/memory-and-dumps.md` — turning a captured image into a file the loader accepts
- `references/virtualization-and-flattening.md` — what a virtualised region is, when there is no
  entry point to restore
- `references/dynamic-debugging.md` — choosing the instrument, and what a session must record
- `references/verification.md` — what a passing run proves
- `scripts/iat_callsite_restore.py` — the pairing and rewrite above, offline, with refusals
