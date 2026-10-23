# Virtualization and Flattening

Goal: recognise the obfuscation that changes the **shape** of code rather than hiding it, apply the
reduction that actually applies, and know the point at which manual reading stops being the right
instrument.

## When to load this

Load it when the code is readable but refuses to make sense:

- one function is a many-thousand-line `switch` over a value that is loaded from memory
- every decompiler gives the same answer for a function: a loop, a switch, and a tangle of variables that
  are live across every case
- long straight-line arithmetic runs with no memory access and no call
- a branch whose condition cannot matter, but which the compiler could not have removed
- a dispatch loop with a table of code addresses, plus a data region the headers say is not code
- the same routine executes a different number of instructions on two runs with the same input

This is a different problem from `protectors-and-packers.md`. There, code is hidden and the question is how
to see it. Here, code is visible and the question is what it means.

## Two families, and what each costs

| Family | What it is | The route | Strength of the distinction |
|---|---|---|---|
| Shape-changing transformation | The original instructions survive, rearranged. Flattening, substitution, bogus control flow, dead code | Reduce locally: evaluate, propagate, simplify. Hand-readable for small functions, scriptable for large ones | `inferred` from the mechanism |
| Virtualisation | The original instructions are translated to an internal bytecode, and an interpreter executes it | Recover the opcode table and the virtual program first. Nothing about the original code is readable until that is done | `inferred` from the mechanism |

The families look similar in a listing and could not be more different in cost. A flattened function is a
puzzle with a fixed answer. A virtualised function is a new instruction set, and the interpreter is
usually the smaller half of the work.

## Control-flow flattening

**Mechanism.** A variable holds a state value. A loop reads it, switches on it, and each case performs one
of the original basic blocks and assigns the next state. The original control-flow graph is replaced by a
state machine whose states are the original blocks. Read at source level in a compiler-level pass during
this project's recon, the shape is exact: the pass creates a switch variable, moves every original basic
block into a switch, and computes the case constants through a scrambling function with a key (`observed`
in this project's source pass).

**What it does to a decompiler, and why that is not a bug.** The output is a loop containing a switch. Each
case begins and ends with reads and writes of the state variable and of the original function's locals, so
every variable is live across every case, and no case has a fallthrough that a structural analysis can
recover. The decompiler is reporting faithfully: the compiled function really is a state machine, and the
control flow really is gone (`inferred`: this follows from the mechanism, and the listing is the evidence).
Blaming the tool and switching tools produces the same listing from a different program.

**Evidence that identifies it.**

- one variable is written in every block and read exactly once, at the loop head
- the number of distinct values compared at the switch equals the number of plausible blocks
- case bodies contain the original operations, including memory accesses that make sense as a group
- the case constants are not in source order, and are frequently dense but permuted
- asking where a case's code "continues" gives an answer that depends on a value, never on a fallthrough

**The reduction, in order.**

1. Find the initial state value: a constant assigned before the loop, or computed by the prologue. Record
   it, because it is the entry block.
2. For each case, extract what it does to the state variable and what the state value is at its end.
3. Build a graph of case to successor. This graph is the original control-flow graph, and building it is
   the entire reduction.
4. Relabel the blocks by reachability rather than by state value; the scramble is now irrelevant and can be
   discarded.
5. Where a case ends with a conditional assignment to the state (a comparison that picks one of two
   values), that is the original conditional branch. Recover the condition as it appears, not as the state
   value it produces.
6. Recover loops from cycles in the graph, and re-render the function with its real structure.
7. Re-read it. The reduction does not need to produce source; it needs to produce a listing whose control
   flow is the original one.

**Where the hand reduction stops working.** Two cases break it. When the next state is a *function* of the
previous state rather than a constant, step 2 becomes a data-dependency problem rather than a table read.
When the case bodies are virtualised rather than native, the reduction has no original blocks to recover.
Both are handoff conditions, not harder puzzles.

## Instruction substitution and arithmetic identity chains

**Mechanism.** A constant, or a simple operation, is replaced by an equivalent expression. The replacement
is usually recursive: the substituted expression contains further substitutions. The result is a
straight-line region that computes something you already know, in the longest way available.

Typical shapes, described by their structure rather than by any one compiler's output: a constant spread
across two temporaries and combined; an addition rewritten as a subtraction of a negative; a value
reconstructed from bit fields and shifts; a chain of XOR, rotate and add with a constant folded into each
step. The common property is that the whole region is a function of a small number of real inputs
(`inferred`).

**Evidence.**

- a long run of arithmetic with no memory access, no call, and no comparison that decides anything
- intermediate values that are computed and used exactly once
- the same input variable feeding several parallel chains that are combined at the end
- a suspicious relationship between two chains, such as one being the bitwise complement of the other

**The reduction.** These chains are deterministic and small, so evaluation is the reduction:

1. Evaluate the chain for a concrete input and check the result against the expected value. This confirms
   the chain computes what you think, and is faster than reading it.
2. Evaluate twice more with inputs that differ in one bit, to confirm which input bits reach the output and
   therefore what the chain's real arity is.
3. Re-express the region as the operation it implements, and record the width used at each step.

**The two errors that produce a wrong answer that looks right.** Width: a chain that is an identity in
64-bit arithmetic is a different function after a 32-bit truncation, and the truncation is usually a single
instruction at the end of the chain. Signedness: a shift or a division whose unsigned and signed forms
differ is where the substitution hides its real semantics. Evaluate in the exact width and signedness the
instruction stream uses, not in the width of a host language.

**When to stop reading.** If evaluating the chain requires the value of an input you cannot supply, the
chain is not substitution, it is the algorithm. At that point the useful move is to mark the region as a
function with a signature and defer it, not to keep simplifying.

## Bogus control flow and opaque predicates

**Mechanism.** A branch whose condition is constant, but not obviously so. The classic shapes are
arithmetic facts dressed as data-dependent tests: a predicate over a squared value, a comparison between
two quantities that are equal only because of a preceding substitution, a bit test on a value constructed
so that the bit is always the same (`inferred`: these are constructions, and each one is provable by hand).
The branch has two arms; one of them is the continuation, and the other is a decoy.

**Evidence.**

- a condition whose inputs are all produced by the substitution layer rather than by memory or a parameter
- one arm that is longer, denser, or contains a copy of the other arm with a changed constant
- both arms writing the same variables, which is what makes the decoy plausible to a reader
- duplicated sequences in the listing, offset from each other, which is also what makes a linear-sweep
  disassembler produce garbage while a recursive-descent one refuses to disassemble (`inferred`: both
  behaviours follow from how each strategy chooses instruction boundaries)

**Why the decoy matters.** The dead arm is a cheap place to put protection. A breakpoint set in the dead
arm never fires, the process runs, and the session concludes that the breakpoint mechanism is being
detected. Before treating a never-firing breakpoint as an anti-debug finding, confirm the breakpoint is in
reachable code, using a trace rather than another breakpoint placement.

**The reduction.**

1. Determine the arm that actually executes: run it and record which arm is taken. This is authoritative
   and takes one run.
2. Determine whether the other arm is even satisfiable: a solver asked whether the condition can take the
   other value answers the question exactly, and its answer also tells you whether the predicate is
   genuinely opaque or merely hard to read.
3. Delete the dead arm from your model, and note what was in it. If the dead arm contained a check, the
   check never runs, and any work spent on it was wasted.

Step 2 is the first place where a solver is cheaper than a reader, and `symbolic-execution.md` covers where
that boundary is.

## Dead code and redundant state

**Mechanism.** Instructions that do nothing, and variables that store something nobody reads. This is the
cheapest obfuscation to apply and the most valuable to remove, because flattening produces a large amount
of redundant state on its own: the state variable survives the reduction as a variable that is written
everywhere and read nowhere.

**Evidence.** Assignments to a variable with no reader on any path forward; calls whose return value is
discarded; branches whose two arms produce identical state; a variable whose every use is an assignment.

**The reduction.** Build a use-definition chain per variable and remove definitions with no uses, iterating
because removing one definition can make another redundant. Then re-run the flattening reduction: a
function that was 300 cases often collapses to 30 once the redundant state is gone.

**One check before deleting anything.** Dead code that performs a side effect is not dead. A store to
memory, a call, an output, a lock acquisition or a page touch is observable even when its value is not
used, and targets hide work in exactly those instructions. Look at what each apparently dead instruction
touches before removing it from the model.

## Virtual machine protectors

**Mechanism.** The protected region is translated to an internal bytecode. The image contains an
interpreter: a dispatcher loop that fetches an opcode, a table of handlers that implement the operations,
and internal state that stands in for the machine the original code ran on. Vendor documentation for
virtualising protectors describes exactly this, and states the analyst's counter-move in the same
document: reverse engineering a virtualised fragment comes down to building a disassembler for the
architecture the virtual machine imitates (`observed` in this project's vendor-documentation pass).

**Recognition. The observable shape.**

| Evidence | What it means | Strength |
|---|---|---|
| A loop that reads a small unit from a buffer and transfers control through a table indexed by it | The fetch-and-dispatch cycle | `inferred` |
| A variable that is only ever incremented, XORed with a constant, or assigned a constant, and is used solely to index or fetch | The virtual program counter | `inferred` |
| A pointer that walks a data region which the section headers classify as data, not code | The bytecode stream | `inferred` |
| A table of code addresses whose entries are not the target of any call in the image | The handler table | `inferred` |
| A private stack or register array, in a global or a heap allocation, accessed by many small routines | The virtual machine's state | `inferred` |
| Many small routines performing nearly the same operation with different encodings | Handler variants, emitted per operation shape | `inferred` |
| A large, self-contained region with no native call structure and no native constants | The virtualised function, or a group of them | `inferred` |

**The handler extraction problem.** Reading virtualised code requires a mapping from opcode values to
semantics. Disassembling one handler is nearly useless on its own, because a handler implements one
operation and the meaning of the program lives in the *sequence* of operations. The unit of work is the
opcode table, not the handler.

**How the table is recovered.** By observing the dispatch. Record which handler address is reached for each
value read from the bytecode stream, over many inputs, until every opcode value that this program uses has
been seen with the handler it selects. Then characterise each handler by its effect on the virtual state:
which state slots it reads, which it writes, whether it touches process memory, whether it performs a
native call. The characterisation is emulation and trace work; the reading is a confirmatory step.

**Why one handler is rarely the answer.** Even with the table in hand, the deliverable is the virtual
program, and the virtual program has to be transcribed before anything can be said about the original
code. That transcription is a mechanical job over a long instruction stream, and it is the job a tool
should be doing. A session that identifies one handler and then attempts to read the rest by hand has
chosen the most expensive possible route through the same work.

**Cost, stated honestly.** Handler sets and encodings are properties of a build (`inferred`). A
devirtualisation script written against one build of a protected binary does not transfer to the next build
without evidence that the dispatcher and the handler set are unchanged. Any claim about the number of
opcodes, the shape of the handler table or the state layout is a build-level claim, and belongs in the same
sentence as the hash of the file it was observed on.

## Handing off from reading to a trace or a solver

| Evidence | Reduction step | Hand off when |
|---|---|---|
| A dispatcher switch with a constant next-state per case | Build case-to-successor graph, relabel by reachability | The graph has more blocks than you can hold, or next-state is computed rather than constant |
| A long straight-line arithmetic chain | Evaluate at several inputs in the exact width | The chain's output depends on an input you cannot supply |
| A conditional with a constant condition | Record the executed arm; ask a solver whether the other is satisfiable | The predicate's inputs come from memory or a call |
| Dead state | Use-def chains, iterate | Never; this is mechanical and belongs in a script |
| A dispatch loop over bytecode | Recover the opcode table from the dispatch trace | Immediately after recognition: the trace is what makes every later step possible |
| A virtualised function whose result you need but whose structure you do not | Emulate the interpreter with the protected region's real inputs | The result is needed and the structure is not |

**The rule behind the last row.** A virtual machine interpreter is a program, and a program with known
inputs and a bounded execution can be run rather than understood. When the deliverable is a value, running
the interpreter with instrumented state is legitimate work; when the deliverable is the algorithm, the
interpreter has to be lifted.

## What a proof of the reduction is worth, measured

The kit's reducer ends a reduction with sampling and says so: sampling refutes, it does not prove. With
an external solver named on the command line, the same run now asks the solver for an input that
distinguishes the two forms, and the statement changes with the answer. Measured on this host
(`observed`):

| Question put to the solver | Answer | What the run may then claim |
|---|---|---|
| the classic substitution chain against its reduction, at 32 bits | no distinguishing input exists | **equivalent for every input at that width** -- a proof, and the output's token changes to say so |
| a genuinely different pair, as a control | a witness, with values | the witness is re-substituted by hand before being believed; a model parsed slightly wrong is a counterexample that isn't |
| a solver that cannot run, times out, or answers unknown | nothing | the sampled statement stands alone, and the run says the proof was attempted |

Two details carry the honesty of the whole exercise. **The proof is about the semantics the tool
actually evaluates**: its evaluator masks a shift count to six bits, an x86 habit, and the question put
to the solver applies the same mask on both sides -- without that, the solver would prove a cleaner
function than the one the samples ran on, and the proof would not cover its own sampling. And **a
proven reduction is not a lifted algorithm**: what is proven is that the smaller form is the same
function as the obfuscated one, which verifies a step of the lifting. The structure still has to be
recovered, and nothing here recovers it.

## What this file does not contain

- No claims about any particular protector's virtual machine. What is stated here is the shape such an
  interpreter has, which follows from what an interpreter is.
- No opcode counts, handler counts, or instruction-set sizes. Every one of those is build-specific.
- No thresholds in instructions or blocks for "too big to read by hand". The threshold is your working
  memory against the size of the function in front of you; what this file supplies is the handoff
  conditions, not a number.
