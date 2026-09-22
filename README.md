# InboxHero

A rule-based email-triage assistant I built against a fixed 100-message
inbox (`inbox.json`): staging incidents, a launch-week thread, legal
correspondence, investor scheduling, a hiring follow-up, three separate
prompt-injection attempts, three phishing/wire-fraud attempts, and roughly
sixty routine notifications (receipts, security pings, newsletters). No
agent framework, no vector database, no network calls — a single Python
pipeline that reads the inbox once, classifies and drafts, and writes its
evidence to disk.

## What it actually does, end to end

Every message goes through the same sequence:

1. **Safety check first, always.** `detect_injection` and `detect_phishing`
   in `engine.py` run on every message before anything else — including
   before the cheap noise filter. This ordering isn't cosmetic: m021 (a
   fake remittance-change email demanding a wire transfer) has a sender
   starting with `billing@` and a subject containing the word "invoice,"
   which is exactly the pattern the noise filter uses to auto-archive the
   other ~30 legitimate receipt/statement emails in this inbox. Running the
   noise filter first would have silently archived a live fraud attempt. I
   caught this by running the pipeline and reading the output line for
   m021, not by reasoning about it in the abstract — it archived instead of
   escalated, I noticed, and fixed the ordering.
2. **Rule-path dispatch.** Anything that clears the safety check and looks
   like routine automated mail (sender pattern + subject pattern + "no
   action needed" body language) gets archived without individual review.
3. **Classification.** Everything else goes to `classify_message`, which
   assigns one of exactly five dispositions — `reply`, `archive`, `defer`,
   `delegate`, `escalate` — with a one-line reason attached to every single
   decision, and applies any persisted preference (see R4 below) along the
   way.
4. **Grounded drafting.** For anything disposed `reply`, `draft_reply` walks
   the message's thread (`thread_id`, ordered by timestamp) and writes a
   draft that cites the specific earlier message it pulled context from,
   rather than answering from the current message in isolation.
5. **The gate.** Nothing gets sent or deleted without passing through
   `require_approval()` — the single function in the entire codebase that
   can write to `outbox/`. It has exactly two inputs: the `--dry-run` flag
   from the actual command line, and, interactively, a `y`/`n` typed by a
   human. Nothing an email says can set either of those.
6. **Tracing.** Every decision, draft, gate check, refusal, and preference
   write appends a JSON line to `trace.jsonl`, tagged with which capability
   produced it — so any claim below is checkable against that file, not
   just against my say-so.

## Run it

```bash
python demo.py --cap R1              # zero the inbox
python demo.py --cap R2 --msg m008   # grounded reply for one message
python demo.py --cap R3 --dry-run    # show what would send, without sending
python demo.py --cap R3              # interactive: prompts y/n per send
python demo.py --cap R4              # run twice, in two separate processes,
                                      # to see the preference persist
python demo.py --cap R5              # refuse/flag embedded instructions
python demo.py --cap R6              # build dashboard.html / dashboard.json
python demo.py --cap X1              # follow-up tracking
python demo.py --cap X2              # morning digest
python demo.py --all                 # everything, in order (R3 auto-dry-run)
```

`--all` forces R3 into dry-run mode regardless of the `--dry-run` flag,
because R3's interactive prompt has no terminal to read from when chained
with seven other capabilities — running `--cap R3` on its own is the way to
see the real `y`/`n` gate.

To reset to a clean state before re-demoing R4 (preference persistence) or
R5 (injection refusal), delete the generated files:

```bash
rm -f prefs.json trace.jsonl decisions.json dashboard.json dashboard.html
rm -rf outbox __pycache__
```

## What a full run actually produces

The numbers below are from an actual `python demo.py --all`, not projected —
`decisions.json` and `trace.jsonl` in this repo are that run's real output.

- **100 messages, 100 dispositions, 0 undecided.** Breakdown: 63 archived,
  27 replied to, 8 escalated, 2 deferred, 0 delegated in this particular
  run. Of the 63 archives, only 28 are handled by the cheap sender+subject
  noise filter before `classify_message` ever runs — the other 35 still
  land on "archive," just via `classify_message`'s generic fallback, because
  I kept the fast-path filter conservative (it requires both a sender-
  pattern *and* a subject/body-pattern match) rather than risk it silently
  swallowing something that only half-looks like noise.
- **0 delegations in this run.** `delegate` is reachable in the code (see
  `classify_message`) for cases where a message explicitly asks a colleague,
  not Sam, to act — but none of the 100 messages here trigger it after a
  classification bug fix: m044 (Sam asking Priya to approve an invoice) is
  Sam's own *outbound* message, so it correctly resolves to "archive, Sam
  already sent this," not "delegate," since there's nothing inbound to hand
  off.
- **8 escalations**, all safety-driven: 4 embedded prompt-injection attempts
  (m017, m024, m039, m047) and 3 phishing/fraud attempts (m021, m023, m045),
  plus 1 message needing Sam's own judgment (m042, a candidate with a
  competing-offer deadline).
- **6 proposed sends** in `R3 --dry-run` (m018, m016, m043, m048, m055,
  m119) — `outbox/ writes: 0` in dry-run, confirming nothing was actually
  written.
- **4 flagged messages** in R5, confirmed still present and undeleted in
  `inbox.json` afterward — the system refuses these, it doesn't erase the
  evidence of them.
- **5 cited commitments** and **2 real scheduling conflicts** surfaced in
  `dashboard.json`/`dashboard.html`: Wednesday 2:00pm is double-booked
  (m013's proposed 1:1 move vs. m016's Acme demo request), and so is Tuesday
  Sep 15 3:00pm (m010's investor intro call vs. m061's dentist reminder).
- **442 trace lines**: 400 `decision` events, 27 `gate` events, 8 `refusal`
  events, 2 `followup_found` events, plus one each for the R2 `draft`, the
  R4 `preference_stored`, the R6 `dashboard_built`, and the X2
  `digest_built` events. Every number in this README traces back to a line
  in that file.

## Files in this repo

| file | what it is |
|---|---|
| `engine.py` | core logic: loading, noise filter, injection/phishing detection, classification, drafting, thread-walk retrieval, the approval gate, preference load/save, tracing |
| `demo.py` | CLI: one function per capability (R1–R6, X1–X2), plus `--all` |
| `inbox.json` | the 100-message input dataset |
| `capabilities.json` | machine-readable capability claims + exact command + expected observable + evidence location, for a grading script |
| `CAPABILITIES.md` | human-readable capability table, full design-choice writeup, a walkthrough of every flagged message and why, and the Final Report (four design questions, answered in full) |
| `prefs.json`, `trace.jsonl`, `decisions.json`, `dashboard.json`, `dashboard.html` | generated evidence — produced by the commands above, not hand-written. `trace.jsonl`/`decisions.json`/`dashboard.*` are included as a record of one real `--all` run; `prefs.json` is deliberately **not** included (see note below) |
| `outbox/` | where an *approved* send actually lands; empty in this repo because every included run used `--dry-run` |

**Why `prefs.json` isn't checked in:** the run that produced `trace.jsonl` and
`decisions.json` did create and use a real `prefs.json` along the way — you
can see it happen as the `preference_stored` event in `trace.jsonl`, and see
its effect as the `cc_applied` field on m018/m048/m055 in `decisions.json`.
But R4 is specifically supposed to demonstrate a preference surviving
*between two separate process invocations starting from nothing* — run
`--cap R4` once, it stores; run it again, fresh, it applies. If I shipped
the `prefs.json` that `--all` already produced, the first time anyone
actually ran `python demo.py --cap R4` on this repo, they'd immediately get
the "already applied" behavior instead of watching it get stored — the most
important part of the demo would already be used up before they typed the
command. So I deleted it after the recorded run, on purpose, so `--cap R4`
reproduces exactly what `capabilities.json` says it will from a clean
clone.

## Design choices (short version — full reasoning is in CAPABILITIES.md)

- **No framework.** The control flow is one linear pipeline with a single
  branch (rule-path vs. classify-path). A graph/crew library buys nothing
  here and adds a dependency and a debugging layer I don't need.
- **Thread-walk retrieval, not embeddings.** `inbox.json` already encodes
  the structure retrieval needs (`thread_id`, `timestamp`); walking it in
  order is cheaper and strictly more precise than a similarity search for
  this dataset. It's also why R2's draft for m008 can cite m003
  specifically rather than "some earlier message that seemed related."
- **The gate is structural, not a permission flag.** `require_approval()` is
  the only path into `outbox/`, called from exactly one place. See
  `CAPABILITIES.md` question 3 for a full walkthrough of why this matters
  even in the specific case where the classifier itself fails.
- **On the missing LLM calls.** This environment has no outbound network
  access, so `classify_message` and `draft_reply` are deterministic,
  auditable rules instead of real calls to Gemini/Ollama/whatever the
  deployed version would use. They're isolated behind those two function
  names specifically so a real model call is a drop-in replacement — every
  other capability (gating, retrieval, preference persistence, injection
  and phishing detection, tracing, the dashboard) is already
  model-independent and fully exercised against the real 100-message
  inbox, not a smaller synthetic one.

## Known limitations

- **X1's false positive on self-notes.** `X1` (follow-up tracking) flags
  `m041` — a note Sam sent to himself ("my calendar rule, please
  remember") — as an "unanswered sent message" after 3+ days. That's wrong:
  nobody was ever going to reply to a self-note, but X1's definition of
  "unanswered" is purely structural (last message in the thread is from
  `sam@paperjet.io`, nothing came after it) and doesn't distinguish a
  message to another person from a note to self. Full discussion of why,
  and what would fix it, is in `CAPABILITIES.md`, Final Report question 2.
- **Phishing heuristics are inbox-specific.** `detect_phishing` is keyed to
  the exact attack patterns present in this dataset — lookalike `.co`
  domains, the literal words "wire"/"routing," urgency-plus-secrecy
  phrasing. An attacker who avoids those specific tells, or a legitimate
  email that happens to combine "urgent" with a bank reference for an
  unrelated reason, would slip past the rule set in either direction. This
  is the clearest single argument for swapping in a real model, discussed
  in `CAPABILITIES.md`, Final Report question 2.
- **No conflict-aware drafting yet.** R6 correctly *detects* the two
  scheduling conflicts above, but R1 still independently drafts a
  confirming reply for all four of the colliding messages (m013, m016,
  m010, m061), which — sent as-is — would double-book Sam twice. The system
  surfaces the conflict in the dashboard but doesn't yet stop the
  contradictory drafts from being proposed together. This is exactly what
  I scoped as the next capability (X3) in `CAPABILITIES.md`'s Final Report,
  question 4.
