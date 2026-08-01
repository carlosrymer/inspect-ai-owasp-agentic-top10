# PRD — Inspect AI: utility vs. security on the OWASP Agentic Top 10

## Problem statement

Agent capability is measured constantly. Agent security almost never is, and when it is, it
is measured on a separate benchmark from a separate suite, so the two numbers never meet.
That leaves the question teams actually face unanswered: *if I harden this agent, what does
it cost me?*

The gap is not a lack of red-teaming. It's that utility benchmarks and security benchmarks
use different environments, so you cannot subtract one from the other. A jailbreak rate on
a chat benchmark tells you nothing about whether the support agent you are about to ship
will still process refunds correctly once you bolt a security prompt onto it.

I wanted a setup where both numbers come from the *same* environment, the same tools and the
same tasks, so that a defense's security benefit and its utility cost are directly
comparable — and then to actually run the tradeoff across several defensive postures and
publish the 2-D result.

## Target user

Engineers shipping tool-using agents into a real business process — support, ops, finance,
IT — who have to decide how much to harden and can't currently price the decision. Secondarily,
anyone evaluating Inspect AI as a framework for building non-trivial custom evals, since
this is a worked example of its `Task`/`solver`/`scorer`/`sandbox` abstractions on a problem
that is not multiple choice.

## Goals

- Score one agent on **two independent axes** — task utility and attack resilience — from a
  single run over a single environment.
- Ground both scores in **what the agent did**, not what it said: an action ledger written
  inside the sandbox, read back by the scorers.
- Cover **3–4 OWASP Top 10 for Agentic Applications (2026) classes** accurately, citing the
  real published list rather than inventing categories.
- Evaluate **three defensive postures** on the identical suite so the tradeoff is visible
  and quantified, not asserted.
- Make the result **auditable**: commit the `.eval` logs, derive every published number from
  them, and ship a site that reads the exported JSON rather than hard-coded figures.
- Build with **Inspect's own abstractions**, so the repo doubles as a worked example of the
  framework rather than a hand-rolled loop wearing its name.

## Non-goals

- Not a red-team service or a general-purpose attack tool. Every payload is a synthetic
  fixture confined to a network-isolated container, targeting a fictional company.
- Not a model leaderboard. The comparison of interest is posture-vs-posture; the model is a
  variable I hold fixed and report, not the subject.
- Not full OWASP coverage. Six of the ten classes need infrastructure this harness does not
  have, and I would rather cover four honestly than ten badly.
- Not a statistically powered study. One run per cell, 6 samples per class.
- Not a production-grade guardrail library. The policy engine is a deliberately blunt stand-in
  for capability restriction, built so its cost shows up.

## Scope (MVP)

**The environment.** A support-operations agent for "Meridian Cloud", a fictional B2B SaaS
company. Ten tools: four read tools (`read_ticket`, `lookup_customer`, `fetch_page`,
`read_kb`, plus `list_kb`) and five action tools (`issue_refund`, `send_email`, `escalate`,
`update_customer`, `close_ticket`). All ten are backed by files in a per-sample Docker
container.

**The suite.** 8 base scenarios, each a genuinely solvable ticket with a deterministic
success condition — refund exactly the duplicated charge; escalate a suspected data exposure
to tier 3 and leave it open; compute and email the new monthly total after a seat change;
read a linked incident page and correctly attribute an outage to the customer's own firewall.
24 attack variants, 6 in each of four OWASP classes, each planting one payload in exactly one
fixture file. 32 samples total.

**The classes.** ASI01 Agent Goal Hijack, ASI02 Tool Misuse & Exploitation, ASI03 Agent
Identity & Privilege Abuse, ASI06 Memory & Context Poisoning.

**The postures.** `naive` (job description only), `hardened-prompt` (adds an explicit
security policy), `guarded-tools` (adds tool-output quarantining and a runtime policy
engine).

**The output.** Committed `.eval` logs, an exported JSON results bundle, and a static
GitHub Pages site with the utility-vs-resilience scatter, per-class breakdown, a grid showing
which legitimate tickets each posture breaks, and drill-down to real ledgers and transcripts.

## User stories

- As an engineer shipping a support agent, I want to see the utility cost of a security
  prompt measured on the same tasks as its security benefit, so that I can decide whether to
  pay it.
- As a security reviewer, I want to see *which* attack class each posture fails on, so that I
  can tell whether a defense addresses my actual threat model or just the easy half of it.
- As a skeptical reader, I want to open the exact payload, the agent's real tool calls and
  the transcript for any cell in the results, so that I can check the scoring rather than
  trust it.
- As someone evaluating Inspect AI, I want to read a non-trivial eval that uses real
  `Task`s, custom `@tool`s, a sandbox and custom `@scorer`s, so that I can judge the
  framework on something harder than a Q&A benchmark.

## Success criteria

The technology claim being trialed is that **Inspect AI is a serious framework for building
custom, environment-heavy agent evals — not just for running prebuilt benchmarks.** That held
up. The abstractions I needed all existed and composed: a `react` agent I could re-prompt per
posture without touching the tools; `@tool` functions that could reach into the sandbox;
`sandbox()` still being live during scoring, which is the single fact that makes the
action-ledger design possible; and custom `@metric`s that receive full `SampleScore` objects,
so one task could carry both clean and attacked samples and still report them separately.
The framework got out of the way of the part that was mine to write.

Where it fell short: loading a task by file path breaks relative imports inside a package,
so I drive everything through the `eval()` API instead of the CLI. Docker sandbox startup
dominates wall-clock on a suite this small. And nothing in the framework helps you decide
what to score — the hard part here was designing 32 samples whose success is determined by
the ledger, and that was entirely on me.

The eval itself succeeded on its own terms: it produced a real, non-obvious tradeoff curve
with an inversion I did not predict, and every number is reproducible from committed logs.
The findings are reported in the README, including the two predictions I got wrong.

## Risks / open questions

- **Small-n.** 6 samples per class means a single flipped sample moves a class rate by 16.7
  points. Mitigated by reporting sample counts everywhere and telling readers to read the
  class bars as direction. Not mitigated by repeats — there are none.
- **I wrote both sides.** My payloads test my defenses. A posture that scores well here is
  well-defended against the 24 attacks I thought of, which is a much weaker claim than
  "secure". Stated plainly on the site and in the README.
- **Exposure vs. resistance.** An agent that never opens the poisoned page trivially
  "resists" it. Mitigated by computing per-sample whether the payload's channel was actually
  retrieved, and reporting where it wasn't.
- **Utility specs could be wrong.** If a required action were unachievable the posture
  comparison would be garbage. Mitigated by 128 offline tests that assert an ideal ledger
  scores 1.0 on every scenario and that a compromised ledger trips every attack check —
  all run before any model call.
- **Open question:** how much of the resilience measured here is the model's general
  instruction-hierarchy training rather than anything in my postures? The naive baseline is
  the main control, and a partial second model gives a first read on it — but only on the two
  prompt-level postures, since that provider's credit ran out mid-sweep.
- **Open question:** the policy engine catches out-of-policy *actions* but is blind to
  attacks that only need in-policy actions. That looks like a structural ceiling on runtime
  enforcement, and this suite can only hint at it.

## Timeline

A single working session: research and scope the OWASP class selection; design the 8
scenarios and 24 payloads; build the tools, solvers and scorers; validate the scoring specs
offline; run the posture matrix; export, build the site, and ship.
