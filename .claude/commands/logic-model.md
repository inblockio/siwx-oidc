# Logic Model

Structured reasoning protocol for approaching any task as a causal chain of falsifiable hypotheses.
Based on: W.K. Kellogg Foundation Logic Model (2004), Pearl's Structural Causal Models (2000), OECD-DAC results chain.

> **INVARIANT:** Never skip CONTEXT or GOAL. Every action must trace back to an explicit goal through a defensible if-then chain. If the chain breaks, stop and re-scope with the user.

---

## Formal Definition

A logic model is a **directed acyclic graph (DAG)** of if-then causal hypotheses:

```
Inputs → Activities → Outputs → Outcomes → Impact
```

Each arrow is a **testable claim**, not a guarantee. Assumptions annotate each edge — they are conditions that must hold but are outside your control. An unexamined assumption is the primary failure mode.

**Key distinction:** Output != Outcome. An output is a deliverable (code written, file created). An outcome is a state change (bug resolved, user can do X). Never confuse the two.

---

## The Five Phases

Execute these in order. Each phase produces an explicit artifact (even if just a sentence).

### Phase 1 — CONTEXT (Where am I?)

Discover the operating environment before acting.

| Check | How |
|---|---|
| Existing structures | Read CLAUDE.md, skills/, docs/, memory/ |
| Codebase state | `git status`, `git log`, file exploration |
| Available tools | MCP tools, CLI tools, skills, existing tests |
| Current limitations | Sandbox walls, missing access, known gaps |
| Prior work | Memory records, recent commits, open PRs |

**Output:** A mental model of what exists, what works, and what doesn't.

### Phase 2 — GOAL (What am I trying to achieve?)

State the goal in one sentence. If you cannot, the task is too complex — decompose.

| Rule | Detail |
|---|---|
| Simple and clear | One sentence, no conjunctions hiding sub-goals |
| Measurable | How will we know it's done? Define the acceptance criterion. |
| Scoped | What is explicitly out of scope? |
| Confirmed | Clarify with the user before execution. Do not assume. |

**If-then test:** "IF this goal is achieved, THEN the user's need is met." If that doesn't hold, the goal is wrong.

**Complex tasks:** Break into sub-goals with measurable milestones. Each sub-goal gets its own logic model pass.

### Phase 3 — INPUTS (What do I need?)

Identify resources required for the task:

- **Code assets** — files, functions, modules to read or modify
- **Knowledge assets** — skills, docs, API references, prior decisions
- **External dependencies** — APIs, services, permissions, access tokens
- **Constraints** — time, sandbox limitations, architectural rules

Link each input to a specific activity (Phase 4). An input without a consumer is noise. An activity without an input is blocked.

### Phase 4 — ACTIVITIES + OUTPUTS (What do I do? What do I produce?)

The concrete implementation. This is a **continuously evolving data workflow** — not a static plan.

| Principle | Detail |
|---|---|
| Relate assets via hyperlinks | Cross-reference files, functions, docs, skills by path |
| Chain activities causally | Each activity's output feeds the next activity's input |
| Validate each link | For each `IF activity THEN output`: is it sufficient? Is it necessary? |
| Iterate | Update the workflow as you learn. The first plan is always wrong. |

**If-then chain for each step:**
```
IF I have [input],
  THEN I can perform [activity].
IF I perform [activity],
  THEN I will produce [output].
IF I produce [output],
  THEN [outcome] follows.
```

Each link that cannot be defended with evidence or reasoning is an **assumption** — surface it.

### Phase 5 — BOUNDARY CONDITIONS (What must NOT happen?)

The "what not to do" is as important as the plan. Identify and clarify with the user.

| Category | Examples |
|---|---|
| **Assumptions** | Conditions you depend on but don't control (API availability, sandbox behavior, user permissions) |
| **Exclusions** | What is explicitly out of scope — prevents scope creep |
| **Invariants** | Rules that must never be violated (e.g., MCP pipeline mandatory, no direct Gusto calls) |
| **Risks** | Each assumption inverted is a risk. Name the top 3. |
| **External factors** | Environment changes that could invalidate the plan |

> If a boundary condition is unclear, **stop and ask**. Do not guess at constraints.

---

## Applying the Model

### Before starting any non-trivial task

```
1. CONTEXT  — What exists? (discovery: 2-5 min)
2. GOAL     — What do I achieve? (confirm with user)
3. INPUTS   — What do I need? (identify, verify accessible)
4. WORK     — Activities → Outputs → Outcomes (execute, iterate)
5. BOUNDS   — What must not happen? (clarify with user)
```

### During execution

- **Validate each if-then link** as you go. If an assumption breaks, surface it immediately.
- **Update the workflow** — the model is living, not frozen. New information changes the DAG.
- **Track outputs vs. outcomes** — "I wrote the code" (output) != "the bug is fixed" (outcome). Verify the outcome.

### Red flags (stop and re-scope)

- You cannot state the goal in one sentence
- An activity has no clear input or produces no clear output
- You discover an assumption you cannot verify
- The if-then chain has more than 5 links without intermediate validation
- The user hasn't confirmed the goal or boundary conditions

---

## Formal Grounding

| Concept | Source | Key insight |
|---|---|---|
| DAG structure | Pearl, *Causality* (2000) | Each edge is a causal claim; missing edges are independence claims |
| If-then chain | Kellogg Foundation (2004) | Every link is a falsifiable hypothesis |
| Assumptions track | USAID Logframe (1969) | Unexamined assumptions are the #1 failure mode |
| Output != Outcome | OECD-DAC (2019) | Deliverables are not results |
| Theory of Change | Weiss (1995) | Every arrow needs a defensible "why" |
| Sufficiency test | Bradford Hill criteria (1965) | Is the cause sufficient? Necessary? Attributable? |

---

## Key Takeaway

A logic model is not a plan — it is a **set of testable hypotheses about causation**. The value is not in following the plan, but in making every assumption explicit so failures are diagnosed, not mysterious.
