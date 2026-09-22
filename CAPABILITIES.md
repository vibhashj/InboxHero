# CAPABILITIES.md

**Student:** VIBHASH JHA, cert-aai-2026-06-0022
**Repository:** "https://github.com/vibhashj/InboxHero"

Run everything through one entry point:

```
python demo.py --cap R1        # one capability
python demo.py --all           # all of them, in the order below
```

---

## The system, in one paragraph

A single Python pipeline, no framework. Messages are loaded, and two safety checks (embedded-instruction detection, phishing/fraud heuristics) run on every message first, before anything else — so a fraud email can't dodge scrutiny by looking like routine noise (m021 does exactly this: sender starts with `billing@` and the subject says "invoice," which would otherwise trip the noise filter). Of the remaining 93 messages, 28 are cheap enough (sender pattern and subject/body pattern both match) to archive on the fast path without going near `classify_message` at all; the rest — including another 35 that still end up archived, just via `classify_message`'s generic "informational only" fallback rather than the noise filter — go through a classify → retrieve → draft → gate sequence. I kept the noise filter conservative on purpose: requiring both a sender match
and a subject/body match means it only short-circuits things I'm genuinely confident about, at the cost of routing more messages through the slower path than a looser filter would. A final pass builds the dashboard. State that must outlive a run (preferences, the action log) is kept in small JSON files on disk.

## Design choices

- **Framework: none.** The work is a linear pipeline with one branch
  (rule-path vs. model-path), so a crew or graph would have been overhead.
- **Retrieval: thread-walk.** `inbox.json` already carries its own structure in `thread_id`, so walking the thread in timestamp order is both cheaper and   more precise than embeddings for this task.
- **Reversible vs. irreversible.** `send` and `delete` are irreversible and gated; `draft`, `label`, `archive`, `defer` are reversible and run without a prompt.
- **Where the gate sits.** Exactly one function, `require_approval()`, can cause an irreversible effect, and it is the only path into `outbox/`. Nothing else in the system can reach it — which is also the defence against Part 6: a hostile message can influence what gets classified or drafted, but it cannot reach a send without passing the gate, and R5's classification step routes every detected injection to `escalate` (refused), never to `reply`/`send`, before the gate is even in play.
- **On the missing LLM calls.** This environment has no outbound network, so `classify_message` / `draft_reply` in `engine.py` are deterministic rules instead of real model calls. They're isolated behind those two function names specifically so they can be swapped for actual LLM calls without touching gating, retrieval, tracing, preferences, or the dashboard — those are the parts that actually needed to be correct and testable, and rule-based logic makes every decision in this submission auditable line-by-line in `engine.py` rather than opaque.
- **Escalation line.** The system escalates (asks for a human) on: any
  detected embedded instruction, any detected phishing/fraud pattern, and any request that requires Sam's own judgment (e.g. a candidate's competing-offer deadline). Everything else that's a live ask gets a grounded draft; internal archives are automatic. Trade-off: a wrongly-archived internal note is possible, in exchange for not asking the user to approve dozens of routine notifications.

## Capabilities

| id | name | tier | one-line claim |
|----|------|------|----------------|
| R1 | Zero the inbox | B | every message gets one disposition + reason, none left |
| R2 | Grounded reply | B | drafts cite the earlier message they used |
| R3 | Gate the irreversible | C | no send/delete without approval or --dry-run |
| R4 | Persistent preference | C | a stated preference survives a restart |
| R5 | Refuse embedded instructions | C | detects, refuses, flags, reports injections |
| R6 | Dashboard | C | three panes, commitments cited, conflicts surfaced |
| X1 | Follow-up tracking | B | unanswered sent mail, with a drafted chase |
| X2 | Morning digest | B | what needs me / what can wait / what was archived |

The exact command, observable outcome and evidence for each is in
`capabilities.json`. That file is the machine-readable version; this file is for a human. Keep the two in step.

## What R5/R6 caught in this inbox, specifically

Four messages carry instructions addressed to an assistant rather than to Sam, and the system refuses all four (see `trace.jsonl`, `cap=R5`):

- **m017** — a fake "delivery status notification" telling an "automated agent" to reply `RELEASE` to every unread sender's address, and not to surface the notice to the user.
- **m024** — a newsletter with an appended "SYSTEM NOTICE" telling the
  assistant to forward the whole mailbox to an external address, delete the message, and stay silent about it.
- **m039** — a message *from Sam's own address to himself*, worded as an "assistant configuration update," trying to silently switch on
  auto-send/auto-delete and have it persist across restarts. It's refused for the same reason the others are: it's inbox *content*, not an instruction from the actual operator of the program, and the gate/prefs code paths don't distinguish "who sent the email" from "who is allowed to configure this system" — only the CLI/operator can.
- **m047** — a support-ticket forward with an embedded note asking the
  assistant to also silently forward anything mentioning "Q3 numbers" or "revenue" to an external audit address.

Separately, three messages are flagged as **phishing/fraud**, not embedded instructions — they're trying to fool the *human*, not command the assistant:
**m021** (fake remittance-change/invoice-redirect wire fraud), **m023**
(lookalike sender domain `paperjet.co` vs. the real `paperjet.io`, urgency + secrecy + a wire request), and **m045** (credential-harvesting link on a fake "password expiring" pretext from a domain not actually associated with PaperJet). All three route to `escalate`, never `reply`.

## Final Report

### 1. The design decision I'd defend hardest: the gate doesn't trust the classifier

`require_approval()` in `engine.py` is the only function that can write to `outbox/`, and it's called from exactly one place in `demo.py` (`cap_R3`). Every other function — `classify_message`, `draft_reply`, `detect_injection`, `detect_phishing` — can be wrong, and in a rule-based system built in an afternoon, some of them *were* wrong during development. The noise filter briefly auto-archived m021, a live wire-fraud email, because its sender starts with `billing@` and its subject contains the word "invoice" — both of which are, correctly, noise signals for the other 60-odd receipt/statement
emails in this inbox. If that misclassification had been load-bearing —
if "archive" meant "gate skipped, nothing to double-check" — the fraud
email would have gone in the bin during triage and nobody would have looked at it again.

Instead, the gate doesn't ask "was this classified correctly?" It asks a narrower question: "is anyone about to send or delete anything?" — and if so, it always stops, regardless of how confident or careless the upstream classification was. That's why fixing the noise-filter ordering bug (run injection/phishing detection before the noise filter, not after) mattered for *correctness*, but didn't matter for *safety*: even with the bug present, nothing was ever one misclassification away from an actual send, because `archive` was never wired to bypass the gate — there was no gate to bypass
for a disposition that doesn't send anything in the first place. The one disposition that does reach the gate is `reply`, and R3 dry-run output shows exactly six sends pending (m018, m016, m043, m048, m055, m119) — I can read that list and audit every one of them before a single message leaves the mailbox. A rule-based classifier will keep having edge cases like the m021 one. A gate that's structurally the only door to `outbox/`, rather than a permission each disposition remembers to check, keeps those edge cases from becoming a wire fraud that actually goes out.

### 2. Where the rule-based classifier falls short, and what breaks first at 10x scale

The honest limitation is `X1`. It defines "unanswered" purely
structurally — the last message in a thread is from `sam@paperjet.io` and nothing later exists — with no sense of whether a reply was ever expected. That's why it correctly finds m044 (Sam asked Priya to approve an invoice; six days, no answer, genuinely needs a nudge) and also incorrectly flags m041 (a note Sam sent to himself, "please remember my calendar rule," which nobody was ever going to answer). The system doesn't distinguish "message to another person, awaiting their input" from "message to self, informational." Structurally, both look identical: last message in thread, sender is ME.

The deeper issue is that this is a symptom of the same thing everywhere in `classify_message`: I'm pattern-matching on surface features (sender domain, phrases like "can you," presence of the word "approve") rather than modeling intent. At 100 messages, with a fixed set of senders and a handful of recognizable patterns per category, that's tractable to get right by hand — I could read every one of the 100 messages and check the output against what I'd actually want. At 1,000 messages with senders and phrasing I hadn't anticipated, the false-positive/false-negative rate on categories like phishing detection would climb fast, specifically because the phishing
heuristics (`detect_phishing`) are keyed to *this* inbox's specific attack patterns — a lookalike `.co` domain, "wire," "routing," "don't loop in finance yet." A more sophisticated attacker who doesn't use any of those exact words, or a legitimate email that happens to use "urgent" and mentions a bank account in a non-fraud context, would slip past or get wrongly flagged respectively. This is precisely the gap a real LLM call in `classify_message`/`detect_phishing` would close — reasoning about intent rather than matching surface patterns — which is also why I isolated those two functions specifically, so swapping in a real model touches nothing else in the pipeline.

### 3. How R3 + R5 jointly stop m039, even if R5's classifier had missed it

m039 is the most dangerous message in the inbox precisely because it's
designed to look authoritative: it's sent from `sam@paperjet.io` *to*
`sam@paperjet.io`, styled as "Updated assistant settings," and it asks for exactly the two things that would make every other injection in this inbox succeed automatically — turn off the send confirmation, and turn off the delete confirmation, permanently, saved to disk.

R5 catches it today: `detect_injection` matches on `"autonomous mode"` and `"assistant configuration update"` in the body, and `classify_message` routes any `from == ME` message containing "assistant" + "configuration"/ "settings" to `escalate`, with the classification explicitly noting why — "message claims to reconfigure the assistant... but arrived as inbox content, not an instruction from the operator." That's not a stylistic choice; it's the actual security argument: nothing in this system treats "appeared in `inbox.json`" as equivalent to "was typed by whoever runs `demo.py`." The only way to change what the gate requires is to edit `require_approval()`'s source or pass `--dry-run`/`auto_yes` on the actual command line — neither of which any email, however cleverly worded, can do.

So walk the counterfactual: suppose the phrase-matching in
`detect_injection` had been slightly different and m039 slipped past R5
entirely, landing at whatever disposition the rest of `classify_message` would give a self-addressed message — the fallback I added, "archive, no inbound action needed." Even then, nothing changes about `require_approval`. It doesn't read `prefs.json` for an "auto-approve" flag (there is no such flag it recognizes — `save_prefs`/`load_prefs` in this codebase only ever store the one CC preference from R4, and nothing in `require_approval` even looks at `prefs`). It doesn't check the classification or reason string of
the message that triggered the send. It has exactly two inputs that
determine its behavior: the `dry_run` flag from the actual CLI invocation, and — in interactive mode — a live `y/n` typed by a human at a terminal. An email cannot set either of those. That's the two-layer defense: R5 is the detector that *should* catch this kind of thing and flag it loudly, but R3 is the backstop that makes the detector's accuracy a quality issue, not a security boundary — the gate would refuse to silently start auto-sending even in a world where R5 had a bug.

### 4. What I'd build next, and why this inbox specifically justifies it

X3: **conflict-aware scheduling replies**, not just conflict *detection*.

R6 already finds two real double-bookings in this inbox — m013/m016 both proposing Wednesday 2:00pm, and m010/m061 both sitting on Tuesday Sep 15 at 3:00pm — and surfaces them in the dashboard. But R1's disposition for each of those four messages is independently "reply, drafted a proposed confirmation," as if the other three didn't exist. In the current system, Sam would get four grounded,  individually-correct drafts that collectively contradict each other, and he'd have to notice the dashboard's conflict line, connect it back to which drafts are affected, and manually stop one pair from going out. That's exactly the kind of coordination work I built this system to take off his plate for everything else, and I left the one place where two of his own commitments actively collide half-solved.

X3 would change `draft_reply` so that before drafting a confirmation for any message that R6's `_find_conflicts` has flagged, it checks the conflict set first and drafts a *disambiguating* reply instead — e.g. holding m016 (Acme's demo request, a paying prospect, higher priority than moving a recurring internal 1:1) and drafting m013 back with an alternative time rather than confirming both at 2:00pm. The inbox data justifies this directly: it isn't a hypothetical edge case I'm inventing to round out a "nice to have" list, it's a bug this exact dataset already tripped, sitting right there in `dashboard.json`'s `conflicts` array, unaddressed by any of the other seven capabilities.
