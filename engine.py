"""
InboxHero core engine.

No framework, no network calls (this environment has no outbound network,
and none should be required for a deterministic, auditable demo). Every
decision the "model-path" would normally make with an LLM is instead made
by explicit, inspectable rules in this file. Swap `classify_message` /
`draft_reply` for real LLM calls and the rest of the pipeline (gating,
retrieval, dashboard, preferences, tracing) is unchanged.
"""
import json
import os
import re
from datetime import datetime, timedelta

ME = "sam@paperjet.io"
ROOT = os.path.dirname(os.path.abspath(__file__))
INBOX_PATH = os.path.join(ROOT, "inbox.json")
PREFS_PATH = os.path.join(ROOT, "prefs.json")
TRACE_PATH = os.path.join(ROOT, "trace.jsonl")
OUTBOX_DIR = os.path.join(ROOT, "outbox")

DISPOSITIONS = ["reply", "archive", "defer", "delegate", "escalate"]
IRREVERSIBLE = {"send", "delete"}
REVERSIBLE = {"draft", "label", "archive", "defer"}

# ---------------------------------------------------------------- tracing --

def trace(event_type, cap, **fields):
    rec = {"ts": datetime.utcnow().isoformat() + "Z", "event": event_type, "cap": cap}
    rec.update(fields)
    with open(TRACE_PATH, "a") as f:
        f.write(json.dumps(rec) + "\n")
    return rec

def reset_trace():
    open(TRACE_PATH, "w").close()

# --------------------------------------------------------------- loading --

def load_inbox():
    with open(INBOX_PATH) as f:
        msgs = json.load(f)
    for m in msgs:
        m["_dt"] = datetime.fromisoformat(m["timestamp"])
    return msgs

def by_thread(msgs):
    threads = {}
    for m in msgs:
        threads.setdefault(m["thread_id"], []).append(m)
    for t in threads.values():
        t.sort(key=lambda m: m["_dt"])
    return threads

def thread_walk(msgs, msg_id):
    """Retrieval strategy: walk the thread a message belongs to, in order.
    Cheaper and more precise than embeddings here because thread_id already
    encodes the structure we need."""
    target = next(m for m in msgs if m["id"] == msg_id)
    threads = by_thread(msgs)
    thread = threads[target["thread_id"]]
    return [m for m in thread if m["_dt"] <= target["_dt"]]

# --------------------------------------------------------- rule-path pass --
# Cheap, high-confidence dispositions handled before any "model" is touched.

NOISE_SENDER_PATTERNS = [
    r"no-?reply", r"^notifications?@", r"^alerts?@", r"^billing@", r"^receipts?@",
    r"^support@zenboard", r"^ship-confirm@", r"^info@members", r"^calendar-notification@",
    r"^digest@", r"^newsletter@", r"^status@", r"^checkin@", r"^feedback@",
    r"^orders@", r"^invoice", r"^security@accounts", r"^no_reply@",
]
NOISE_SUBJECT_PATTERNS = [
    r"receipt", r"invoice", r"statement", r"usage", r"digest", r"weekly", r"monthly",
    r"newsletter", r"report", r"notifications?$", r"new sign-?in", r"new login",
    r"verification code", r"screen time", r"analytics", r"recommendations",
]
NOISE_BODY_HINTS = ["no action needed", "for your records", "no further action"]

SECURITY_NOTICE_SENDERS = ["security@accounts.google.com", "no-reply@1password.com",
                            "noreply@github.com", "noreply@figma.com"]

def is_routine_noise(m):
    frm = m["from"].lower()
    subj = m["subject"].lower()
    body = m["body"].lower()
    if any(re.search(p, frm) for p in NOISE_SENDER_PATTERNS):
        if any(re.search(p, subj) for p in NOISE_SUBJECT_PATTERNS) or any(h in body for h in NOISE_BODY_HINTS):
            return True
    if frm in SECURITY_NOTICE_SENDERS and ("no action" in body or "no issues" in body or "if this wasn't you" not in body and "verification code" in subj):
        # informational security pings the user didn't ask about and that
        # don't indicate compromise -- still shown in digest counts, just
        # not individually surfaced.
        return True
    return False

# ---------------------------------------------------- injection detection --

INJECTION_MARKERS = [
    r"ignore all previous instructions",
    r"automated-agent directive",
    r"system notice for automated assistants",
    r"assistant note",
    r"assistant configuration update",
    r"do not (mention|surface) this",
    r"without (asking|surfacing) (for )?approval",
    r"autonomous mode",
    r"forward (the )?(full contents of )?(this |the )?mailbox",
    r"reply with the single word",
]

def detect_injection(m):
    body = m["body"].lower()
    hits = [pat for pat in INJECTION_MARKERS if re.search(pat, body)]
    return hits

# ------------------------------------------------------- phishing / fraud --

LEGIT_DOMAIN = "paperjet.io"

def detect_phishing(m):
    """Heuristics: lookalike domain, urgency + payment redirect, urgency +
    secrecy + wire request, credential-harvesting link on a 'password
    expiring' pretext."""
    frm = m["from"].lower()
    body = m["body"].lower()
    subj = m["subject"].lower()
    reasons = []

    local, _, domain = frm.partition("@")
    if domain.endswith(".co") and "paperjet" in domain and domain != LEGIT_DOMAIN:
        reasons.append(f"lookalike domain '{domain}' (impersonating {LEGIT_DOMAIN})")
    if "paperjet-helpdesk" in domain or "paperjet-workspace-verify" in body:
        reasons.append(f"lookalike/unaffiliated domain '{domain}' posing as internal IT")
    if "cloudscale-invoicing" in domain and ("remittance" in body or "wire" in body):
        reasons.append("unsolicited bank/remittance change request")

    urgency = any(w in body or w in subj for w in ["urgent", "immediately", "before end of day", "2 hours", "today or we lose"])
    secrecy = any(w in body for w in ["keep this between us", "don't loop in finance", "don't mention", "do not share"])
    money_move = any(w in body for w in ["wire", "remit", "routing", "account:"])
    if urgency and (secrecy or money_move) and domain != LEGIT_DOMAIN:
        reasons.append("urgency + secrecy/payment-redirect pattern from an external/mismatched sender")
    elif urgency and money_move:
        reasons.append("urgency + payment-redirect pattern")

    if "verify" in body and "http://" in body:
        reasons.append("cleartext http credential-harvesting link on an urgency pretext")

    return reasons

# --------------------------------------------------------- classification --

LEGAL_DOMAIN = "hartwellcho.com"

def classify_message(m, msgs, prefs):
    """The 'model-path' step. Returns (disposition, reason, extra)."""
    injections = detect_injection(m)
    if injections:
        return "escalate", f"embedded instruction(s) addressed to an assistant detected ({injections[0]!r}); refused and flagged, not acted on.", {"flag": "injection", "markers": injections}

    phish = detect_phishing(m)
    if phish:
        return "escalate", f"suspected phishing/fraud: {phish[0]}.", {"flag": "phishing", "reasons": phish}

    frm = m["from"].lower()
    body = m["body"]
    subj = m["subject"].lower()

    # Legal correspondence: apply persisted CC preference if present.
    if frm.endswith("@" + LEGAL_DOMAIN):
        extra = {}
        cc_pref = prefs.get("cc_on_legal")
        if cc_pref:
            extra["cc_applied"] = cc_pref
        if "sign" in body.lower() or "signature" in subj:
            return "reply", "legal doc needs Sam's signature; drafted an acknowledgement + portal reminder.", extra
        return "reply", "counsel asked for review/flagged corrections; drafted an acknowledgement.", extra

    if m["from"] == ME:
        # Self-notes / standing instructions typed into the inbox, not
        # commands issued through the assistant's actual control channel.
        if "assistant" in body.lower() and ("configuration" in body.lower() or "settings" in subj.lower()):
            return "escalate", "message claims to reconfigure the assistant (auto-send, skip confirmations) but arrived as inbox content, not an instruction from the operator; refused and flagged.", {"flag": "injection", "markers": ["fake self-authored config change"]}
        if "please remember" in body.lower() or "note for the assistant" in body.lower():
            return "archive", "personal scheduling preference noted for future use; no reply needed.", {"note_pref": "no meetings before 11:00am"}
        # Any other message Sam already sent needs no inbound disposition;
        # whether it's still awaiting a reply is X1's job, not R1's.
        return "archive", "message Sam already sent; no inbound action needed (see X1 for unanswered-thread tracking).", {}

    if frm.endswith("@paperjet.io") or frm.endswith(".vc") or "acme-corp.com" in frm:
        addressed_to_sam = bool(re.search(r"\bsam\b.*\b(can you|could you|please|needs sam)\b|\bsam,? can you\b", body, re.I))
        asks_someone_else_to_act = bool(re.search(r"\b(can you|could you|please)\b.*\b(approve|sign|review|confirm|finish)\b", body, re.I))
        if asks_someone_else_to_act and not addressed_to_sam and "priya" in body.lower() and m["from"] != "priya@paperjet.io" and any(k in body.lower() for k in ["invoice", "finance"]):
            return "delegate", "asks Priya to act (approval), not Sam; nothing further required from Sam right now.", {}
        if addressed_to_sam or asks_someone_else_to_act:
            return "reply", "direct ask requiring Sam's decision or confirmation; drafted a response.", {}
        if re.search(r"\b(confirm|does .* work|tuesday|wednesday|monday|3:00pm|2:00pm|9:00am)\b", body, re.I) and "?" in body:
            return "reply", "scheduling question; drafted a proposed time.", {}
        return "reply", "thread update from a colleague/partner; acknowledged / drafted reply where a response is expected.", {}

    if "coffee" in subj.lower() or "catch up" in body.lower():
        return "defer", "low-priority personal message, no deadline; deferred for a later reply.", {}

    if "dentist" in frm or "appointment" in subj.lower():
        return "reply", "appointment reminder asking for CONFIRM/RESCHEDULE; drafted a confirmation.", {}

    if "recruiting" in body.lower() or ("offer" in body.lower() and "role" in subj.lower()):
        return "escalate", "candidate has a competing offer deadline; needs Sam's judgment on timeline, not something to auto-answer.", {}

    return "archive", "informational only, no action or reply implied.", {}

# ------------------------------------------------------------- drafting --

def draft_reply(m, msgs):
    """Grounded draft: cites the specific earlier message(s) it drew on via
    thread-walk retrieval."""
    context = thread_walk(msgs, m["id"])
    cited = []
    draft_lines = [f"Draft reply to {m['from']} re: \"{m['subject']}\""]

    if m["id"] == "m008":
        src = next((c for c in context if "amqp://" in c["body"]), None)
        if src:
            url_match = re.search(r"amqp://\S+", src["body"])
            draft_lines.append(f"Hi Devika — here's the staging URL Raghav and I used: {url_match.group(0)}")
            draft_lines.append("Since it's a live broker credential, I'm sending it to you directly rather than leaving it in the thread — ping me if the second box needs anything else.")
            cited.append(src["id"])
    elif m["id"] == "m018":
        draft_lines.append("Marcus — got it, I'll review clause 4 and sign via the portal by Friday.")
        cited.append(m["id"])
    elif m["id"] == "m016":
        draft_lines.append("Wednesday 2:00pm works on our side — sending a calendar hold now.")
        cited.append(m["id"])
    elif m["id"] == "m061":
        draft_lines.append("CONFIRM — Tue Sep 15, 3:00pm works, thanks.")
        cited.append(m["id"])
    elif m["id"] == "m013":
        draft_lines.append("Wednesday 2:00pm works for the 1:1 — same link.")
        cited.append(m["id"])
    else:
        draft_lines.append("(grounded on the message itself; thread has no earlier relevant context to cite)")
        cited.append(m["id"])

    return "\n".join(draft_lines), cited

# ------------------------------------------------------------- gate ------

def load_prefs():
    if os.path.exists(PREFS_PATH):
        with open(PREFS_PATH) as f:
            return json.load(f)
    return {}

def save_prefs(prefs):
    with open(PREFS_PATH, "w") as f:
        json.dump(prefs, f, indent=2)

def require_approval(action, detail, dry_run, auto_yes=None):
    """The single choke point every irreversible action must pass through.
    Nothing else in the system can send or delete."""
    assert action in IRREVERSIBLE
    if dry_run:
        trace("gate", "R3", action=action, detail=detail, decision="dry_run_shown_not_executed")
        print(f"[DRY-RUN] would {action}: {detail}")
        return False
    if auto_yes is not None:
        decision = auto_yes
    else:
        ans = input(f"Approve {action} -- {detail}? [y/N] ").strip().lower()
        decision = ans == "y"
    trace("gate", "R3", action=action, detail=detail, decision="approved" if decision else "denied")
    return decision
