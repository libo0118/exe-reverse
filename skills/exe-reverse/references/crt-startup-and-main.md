# C runtime startup: the code that runs before `main`, and how to find `main`

Goal: know why the routine at `AddressOfEntryPoint` is not the program's own code, what it has and
has not done by the time it calls `main`, and how to reach `main` when the image has no symbols —
before a patch is placed at the entry point on the assumption that the C runtime is already usable
there.

## When to load this

Load this when a debugger stops at the entry point and the code there belongs to the C runtime; when
the image is stripped and the routine the programmer wrote still has to be found; when a prologue
installs an exception frame by hand, ends in `__chkesp`, or XORs a stack slot with a global; when a
patch at the entry point crashes before it does anything; and when deciding whether a target has a
`main` at all.

Grades: the entry symbols, the chain and the `/GS` construction are `inferred` from Microsoft's
documented linker defaults and from the C runtime's own source. The 32-bit VC++ 6.0 shapes under
"Recognising a 6.0-era startup" come from a public Chinese tutorial series on C-to-assembly,
collected outside this repository, and are `unverified` here: no build was reproduced against them.
No target was started under a debugger to write this file, so every row is a shape to look for, and
the call into `main` is confirmed only by running the image.

## The entry point is the runtime's code

`AddressOfEntryPoint` is a linker decision, and the default is the C runtime's own startup routine,
not the function the programmer wrote.

| Subsystem, character set | Symbol the linker places | Eventually calls |
|---|---|---|
| console, ANSI | `mainCRTStartup` | `main` |
| console, Unicode | `wmainCRTStartup` | `wmain` |
| GUI, ANSI | `WinMainCRTStartup` | `WinMain` |
| GUI, Unicode | `wWinMainCRTStartup` | `wWinMain` |
| DLL | `_DllMainCRTStartup` | `DllMain` |

Two things override the table, and both are worth checking before believing anything below: the
`/ENTRY` linker option names another routine outright, and a protector or packer rewrites the field
to its own stub, whose job is to rebuild the original image before the real startup ever runs
(`references/protectors-and-packers.md`). A copy of a non-standard entry point is not evidence of a
protector by itself — a build script can set `/ENTRY` too — but it does mean the chain below is not
the one to read.

## The chain, in the order it runs

The names after `mainCRTStartup` are the Visual Studio 2015 and later restructure. Visual Studio
2005 to 2013 named the intermediate `_tmainCRTStartup`, and earlier runtimes did the work in the
startup routine itself. The shape is what matters, not the spelling.

```
mainCRTStartup              the entry point
  __scrt_common_main        one implementation for exe and dll startup
    __scrt_common_main_seh  initialises, inside a structured exception handler
      _initterm             C++ static constructors and C initialisers
      ...                   per-thread data, atexit registration
      invoke_main           the only stage that knows the program's signature
        main                the routine the programmer wrote
    exit(main result)       the process ends here, not at main's ret
```

What that order changes:

- **The arguments do not exist yet at the entry point.** `argc`, `argv` and the environment are
  parsed by the startup routine; before it has run, the three arguments `main` will receive have not
  been computed from the command line.
- **Static constructors run before `main`, in `_initterm`.** A global object whose constructor is
  the real initialisation has already run by the first instruction of `main`; looking for it there
  is looking in the wrong function.
- **`main`'s `ret` is not the end of the process.** It returns to the runtime, which calls `exit`
  with that value: `atexit` handlers, stream flushing and static destructors all run after it. A
  breakpoint on "process exit" is on `exit`, and a patch that intercepts `main`'s return value is
  intercepting one intermediate result.
- **TLS callbacks run before the entry point itself** (`references/pe-structure.md`), so "the first
  code in the program" is a claim about a layer, not about the file.
- **A stub placed at the entry point runs before any of the above.** It cannot rely on the C runtime
  being initialised — heap, stdio, locale and constructors are all still pending. This is why an
  entry-point patch that calls a CRT function is a crash rather than a patch, and why the same patch
  moved into `main` behaves.

## Recognising a 6.0-era startup

The far end of the supported range is a 32-bit, unoptimised VC++ 6.0 build, and its startup has
tells that are not documented as such — they are what that runtime emitted (`unverified`, from the
tutorial corpus named above).

| Shape in the listing | Reads as |
|---|---|
| `push ebp; mov ebp, esp; push -1; push handler; mov eax, fs:[0]; push eax; mov fs:[0], esp` | an exception registration record installed by hand: the function owns a `__try`. At the entry point it is the runtime wrapping `main` |
| `mov eax, fs:[0]` / `mov fs:[0], eax` anywhere | walking or restoring the SEH chain. Common in startup code; on its own it is not anti-debug |
| `cmp ebp, esp; call __chkesp` after the epilogue's `mov esp, ebp` | `/GZ` stack-frame checking, a debug build of that era |
| `mov eax, 0CCCCCCCCh; mov ecx, N/4; lea edi, [ebp-N]; rep stosd` | uninitialised stack filled with `int 3` bytes — the frame table in `references/assembly-idioms.md` |
| imports of `GetVersion`, `GetCommandLineA/W`, `GetStartupInfoA/W`, `SetUnhandledExceptionFilter`, `HeapSetInformation` | the runtime initialising itself, not program logic |
| names or strings `__set_app_type`, `_controlfp`, `__setusermatherr`, `_setargv`, `_setenvp`, `_initterm` | the stages of the table above, in a static-CRT build |

Two boundaries on this table. It is 32-bit only: x64 has no `fs:[0]` chain at all, because
exception handling is table-based and dispatched through `__C_specific_handler`; on x64 the startup
is recognised from the import set and from the `__scrt_common_main_seh` name where a PDB or a
string survives. And the debug marks are exactly that — a release build of the same era has neither
`__chkesp` nor the `0xCC` fill, so their absence says nothing about which compiler produced the
file.

## `/GS`: the cookie explains a crash at the epilogue

`/GS` stores a value derived from the stack pointer in the frame and re-derives it before returning.
The derivation is the point: the saved value is tied to *this* frame, so it cannot be moved or
replayed.

```
x86                                     x64
mov eax, dword ptr [__security_cookie]  mov rax, qword ptr [__security_cookie]
xor eax, ebp                            xor rax, rsp
mov dword ptr [ebp-4], eax              mov qword ptr [rsp+28h], rax
...                                     ...
mov ecx, dword ptr [ebp-4]              mov rcx, qword ptr [rsp+28h]
xor ecx, ebp                            xor rcx, rsp
call __security_check_cookie            call __security_check_cookie
```

On x86 the XOR operand is whichever register holds the frame base — EBP when the frame pointer is
kept, ESP in an optimised build — and the epilogue must use the same one as the prologue.

What it changes:

- **It is a frame tell, not a local.** A slot written once at entry and read once before the
  epilogue, with a module global on both sides of an XOR, is the cookie. Reading it as an ordinary
  local and patching its value breaks the derivation, and the failure appears in
  `__security_check_cookie`, which reads as "my patch crashed the function".
- **A detour must not skip or repeat the prologue's half of it.** A hook that jumps over the cookie
  store but returns through the epilogue, or that runs the prologue twice, leaves a value the check
  did not write. This is the same constraint as the frame itself
  (`references/assembly-idioms.md` §Frames: what the prologue says about the producer).
- **An uninitialised cookie has a default.** The runtime fills `__security_cookie` once during
  startup; before that, a static-CRT image shows the built-in default (`0xBB40E64E` on 32-bit,
  `0x00002B992DDFA232` on 64-bit, from the runtime's source; `unverified` here). A slot equal to a
  default means "startup has not run yet", not "this routine has no `/GS`".
- **`__security_check_cookie` is also a symbol.** In a stripped image the call target is an address
  inside the image, and its body is a compare against the cookie global followed by the failure
  path; the compare is what identifies it.

## Finding `main` when there are no symbols

The startup chain is the map; the call into `main` is the one edge that leaves the runtime.

1. **Confirm the entry point is the runtime.** Import set and the tells above. If it is a packer
   stub, rebuild first; the chain is not visible until then.
2. **Find the argument globals.** `invoke_main` is the only stage that reads the parsed arguments,
   so the routine that loads `__argc` and `__argv` and then tail-calls a routine that is not an
   import is the one holding the call to `main`. In an optimised build this may be the entire
   visible remnant of the chain.
3. **Or run it.** Break at the entry point, break on `GetCommandLineW`/`GetCommandLineA`, return,
   and step until the first `call` whose target is not an import. The other direction works too:
   break on a user-visible API the program touches early and walk up until the frame is no longer
   runtime code.
4. **Confirm the signature rather than the address.** The C runtime always passes three arguments —
   `int main(int argc, char **argv, char **envp)` — even when the source declares two, so the callee
   reads `[ebp+8]`, `[ebp+0Ch]` and `[ebp+10h]` (x86), or RCX, RDX and R8 (x64), and returns an
   `int` in EAX/RAX that the caller hands to `exit`. A GUI target's `WinMain(HINSTANCE, HINSTANCE,
   LPSTR, int)` takes four arguments, and its first comes from `GetModuleHandle` rather than from
   the caller's computation.
5. **Check the claim against the process, not the listing.** Set a breakpoint on the candidate and
   confirm it is reached once, after the runtime's initialisation, with the command line's
   arguments.
   A candidate reached before `_initterm` is a constructor or a TLS callback, not `main`.

**Not every PE has a `main`.** A DLL's program code is `DllMain` and its exports; an `/ENTRY`
override, a packer stub, a managed assembly with a native host, an IL2CPP player and a Go or Rust
image each have their own entry convention (`references/handoff-boundaries.md`,
`references/managed-dotnet.md`, `references/unity-il2cpp.md`,
`references/compiler-fingerprints.md`). Finding "the first program function" in those is a different
question with a different answer, and reporting the runtime's entry point as the program's is the
error this file exists to prevent.

## What this file does not do

- **No address and no version.** The chain is a shape; the offsets, the number of stages and the
  spelling of each symbol belong to one runtime version, and a build that inlines or folds them can
  leave only the call to `main` visible.
- **It does not make the startup readable as business logic.** Initialisation code is where a
  protector's own checks often sit, and that is `references/protectors-and-packers.md` and
  `references/anti-analysis.md`.
- **A recovered `main` is a candidate until it is run.** The confirmation step above is the only
  thing that moves the claim off `unverified`, and it is recorded like any other run
  (`references/verification.md`).
- **The 32-bit rows are third-party.** They are a hypothesis about one toolchain's output, useful
  for recognition and not a measurement; where they disagree with what the target actually does,
  the target wins.
