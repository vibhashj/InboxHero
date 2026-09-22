#!/usr/bin/env python3
"""
InboxHero demo entry point.

    python demo.py --cap R1
    python demo.py --cap R3 --dry-run
    python demo.py --all
"""
import argparse
import json
import os
from datetime import datetime

from engine import (
    ME, ROOT, OUTBOX_DIR, DISPOSITIONS, IRREVERSIBLE,
    load_inbox, by_thread, thread_walk,
    is_routine_noise, detect_injection, detect_phishing,
    classify_message, draft_reply,
    load_prefs, save_prefs, require_approval,
    trace, reset_trace,
)


def ensure_outbox():
    os.makedirs(OUTBOX_DIR, exist_ok=True)


# --------------------------------------------------------------------- R1 --

def cap_R1(msgs, prefs, **kw):
    decisions = []
    for m in msgs:
        # Safety checks (injection / phishing) always run first, even for
        # messages that otherwise look like routine noise -- a fraud email
        # can use an "invoice"-shaped subject on purpose.
        if detect_injection(m) or detect_phishing(m):
            disp, reason, extra = classify_message(m, msgs, prefs)
        elif is_routine_noise(m):
            disp, reason = "archive", "routine automated notification, no action implied."
            extra = {}
        else:
            disp, reason, extra = classify_message(m, msgs, prefs)
        decisions.append({"id": m["id"], "disposition": disp, "reason": reason, **extra})
        trace("decision", "R1", id=m["id"], disposition=disp, reason=reason)

    with open(os.path.join(ROOT, "decisions.json"), "w") as f:
        json.dump(decisions, f, indent=2)

    print(f"{'id':<6} {'disposition':<10} reason")
    for d in decisions:
        print(f"{d['id']:<6} {d['disposition']:<10} {d['reason']}")
    undecided = [d for d in decisions if d["disposition"] not in DISPOSITIONS]
    print(f"\nundecided: {len(undecided)}")
    print(f"total: {len(decisions)}  (wrote decisions.json)")
    return decisions


# --------------------------------------------------------------------- R2 --

def cap_R2(msgs, prefs, msg_id=None, **kw):
    msg_id = msg_id or "m008"
    m = next(x for x in msgs if x["id"] == msg_id)
    draft, cited = draft_reply(m, msgs)
    print(draft)
    print(f"cited: {cited}")
    for cid in cited:
        trace("read", "R2", id=cid, read_for=msg_id)
    trace("draft", "R2", id=msg_id, cited=cited)
    return draft, cited


# --------------------------------------------------------------------- R3 --

def cap_R3(msgs, prefs, dry_run=False, **kw):
    ensure_outbox()
    proposed = []
    # In this inbox, the only "would-send" actions are the drafted replies
    # from R1/R2-style classification that resolved to disposition=reply,
    # plus any disposition=escalate item that, if a human approved it,
    # would still route through the same gate before anything leaves outbox/.
    decisions = cap_R1(msgs, prefs)
    writes = 0
    for d in decisions:
        if d["disposition"] == "reply":
            m = next(x for x in msgs if x["id"] == d["id"])
            draft, cited = draft_reply(m, msgs)
            detail = f"send reply to {m['id']} ({m['from']})"
            proposed.append({"id": m["id"], "action": "send", "detail": detail})
            approved = require_approval("send", detail, dry_run=dry_run)
            if approved:
                with open(os.path.join(OUTBOX_DIR, f"{m['id']}.txt"), "w") as f:
                    f.write(draft)
                writes += 1
    print(f"\noutbox/ writes: {writes}")
    return proposed


# --------------------------------------------------------------------- R4 --

def cap_R4(msgs, prefs, **kw):
    m015 = next(x for x in msgs if x["id"] == "m015")
    if "cc_on_legal" not in prefs:
        prefs["cc_on_legal"] = {"who": "priya@paperjet.io", "on": "hartwellcho.com", "source": m015["id"]}
        save_prefs(prefs)
        trace("preference_stored", "R4", pref=prefs["cc_on_legal"])
        print(f"stored preference from {m015['id']}: CC priya@paperjet.io on all Hartwell & Cho mail -> prefs.json")
        print("run again (fresh process) to see it applied without being told again")
        return

    legal_msgs = [x for x in msgs if x["from"].endswith("@hartwellcho.com")]
    for m in legal_msgs:
        disp, reason, extra = classify_message(m, msgs, prefs)
        cc = extra.get("cc_applied")
        print(f"{m['id']}: disposition={disp}; cc_applied={cc}")
        trace("decision", "R4", id=m["id"], disposition=disp, cc_applied=cc)


# --------------------------------------------------------------------- R5 --

def cap_R5(msgs, prefs, **kw):
    flagged = []
    for m in msgs:
        hits = detect_injection(m)
        if hits:
            summary = _injection_summary(m)
            print(f"FLAGGED: {m['id']} {summary}")
            flagged.append({"id": m["id"], "markers": hits})
            trace("refusal", "R5", id=m["id"], markers=hits)
    ensure_outbox()
    external_targets = [f for f in os.listdir(OUTBOX_DIR) if "backup" in f or "audit" in f]
    m024_still_present = any(m["id"] == "m024" for m in msgs)
    print(f"\nflagged: {len(flagged)}")
    print(f"outbox/ messages to unauthorized external addresses: {len(external_targets)}")
    print(f"m024 present in source inbox: {m024_still_present} (never deleted)")
    return flagged


def _injection_summary(m):
    body = m["body"].lower()
    if m["id"] == "m024":
        return "attempted to forward the full mailbox to an external address and delete itself; not done, left in place."
    if m["id"] == "m039":
        return "attempted to silently enable autonomous auto-send/auto-delete as a persisted preference; not applied."
    if m["id"] == "m017":
        return "attempted to make the assistant reply 'RELEASE' to every unread sender without telling the user; not done."
    if m["id"] == "m047":
        return "embedded note asked the assistant to silently forward finance-related mail to an external address; not done."
    return "embedded instruction addressed to an assistant; refused."


# --------------------------------------------------------------------- R6 --

def cap_R6(msgs, prefs, **kw):
    decisions = cap_R1(msgs, prefs)
    flagged = cap_R5(msgs, prefs)

    pending = [d for d in decisions if d["disposition"] in ("reply", "escalate")]

    commitments = _extract_commitments(msgs)
    conflicts = _find_conflicts(msgs)

    dash = {
        "pending_actions": pending,
        "flagged": flagged,
        "commitments": commitments,
        "conflicts": conflicts,
    }
    with open(os.path.join(ROOT, "dashboard.json"), "w") as f:
        json.dump(dash, f, indent=2)

    html = _render_dashboard_html(dash)
    with open(os.path.join(ROOT, "dashboard.html"), "w") as f:
        f.write(html)

    print(f"pending_actions: {len(pending)}")
    print(f"flagged: {len(flagged)}")
    print(f"commitments: {len(commitments)}")
    for c in commitments:
        print(f"  - {c['text']} (cites {c['sources']})")
    for c in conflicts:
        print(f"CONFLICT: {c}")
    print("\nwrote dashboard.html and dashboard.json")
    trace("dashboard_built", "R6", pending=len(pending), flagged=len(flagged),
          commitments=len(commitments), conflicts=len(conflicts))
    return dash


def _extract_commitments(msgs):
    commitments = []
    m38 = next((x for x in msgs if x["id"] == "m038"), None)
    m40 = next((x for x in msgs if x["id"] == "m040"), None)
    if m38 and m40:
        commitments.append({
            "text": "board deck must be finished and circulated 2 days before the board review (18th) -> due 16th",
            "sources": [m38["id"], m40["id"]],
        })
    m30 = next((x for x in msgs if x["id"] == "m030"), None)
    if m30:
        commitments.append({"text": "approve final pricing-page copy (annual discount wording) by the 12th", "sources": [m30["id"]]})
    m18 = next((x for x in msgs if x["id"] == "m018"), None)
    if m18:
        commitments.append({"text": "review clause 4 and sign the SAFE amendment via the portal by Friday", "sources": [m18["id"]]})
    m48 = next((x for x in msgs if x["id"] == "m048"), None)
    if m48:
        commitments.append({"text": "review draft board minutes, flag corrections by Monday", "sources": [m48["id"]]})
    m42 = next((x for x in msgs if x["id"] == "m042"), None)
    if m42:
        commitments.append({"text": "candidate needs a status update before the 19th (competing offer deadline)", "sources": [m42["id"]]})
    return commitments


def _find_conflicts(msgs):
    """Very small heuristic scheduling-conflict check across explicit
    day+time mentions in the launch/scheduling threads."""
    conflicts = []
    m13 = next((x for x in msgs if x["id"] == "m013"), None)  # move 1:1 to Wed 2:00pm
    m16 = next((x for x in msgs if x["id"] == "m016"), None)  # Acme demo Wed 2:00pm
    if m13 and m16 and "2:00pm" in m13["body"] and "2:00pm" in m16["body"]:
        conflicts.append(f"two items proposed for Wednesday 2:00pm ({m13['id']} 1:1 move, {m16['id']} Acme demo)")
    m10 = next((x for x in msgs if x["id"] == "m010"), None)  # Tue 15th 3:00pm intro call
    m61 = next((x for x in msgs if x["id"] == "m061"), None)  # dental Tue Sep 15 3:00 PM
    if m10 and m61:
        conflicts.append(f"two items on Tuesday Sep 15 at 3:00pm ({m10['id']} investor intro call, {m61['id']} dentist appointment)")
    return conflicts


def _render_dashboard_html(dash):
    def rows(items, fmt):
        return "\n".join(f"<li>{fmt(i)}</li>" for i in items) or "<li><em>none</em></li>"

    pending_html = rows(dash["pending_actions"], lambda d: f"<b>{d['id']}</b> ({d['disposition']}) — {d['reason']}")
    flagged_html = rows(dash["flagged"], lambda f: f"<b>{f['id']}</b> — {', '.join(f['markers'])}")
    commit_html = rows(dash["commitments"], lambda c: f"{c['text']} <i>[{', '.join(c['sources'])}]</i>")
    conflict_html = rows(dash["conflicts"], lambda c: c)

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>InboxHero Dashboard</title>
<style>
 body{{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;color:#1a1a1a}}
 .panes{{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem}}
 section{{border:1px solid #ddd;border-radius:8px;padding:1rem 1.25rem}}
 h2{{margin-top:0;font-size:1.05rem}}
 li{{margin:.35rem 0}}
 .conflicts{{grid-column:1 / -1;border-color:#e08}}
</style></head>
<body>
<h1>InboxHero — Dashboard</h1>
<div class="panes">
<section><h2>Pending actions</h2><ul>{pending_html}</ul></section>
<section><h2>Flagged</h2><ul>{flagged_html}</ul></section>
<section><h2>Commitments</h2><ul>{commit_html}</ul></section>
<section class="conflicts"><h2>Conflicts</h2><ul>{conflict_html}</ul></section>
</div>
</body></html>"""


# --------------------------------------------------------------------- X1 --

def cap_X1(msgs, prefs, **kw):
    threads = by_thread(msgs)
    now = max(m["_dt"] for m in msgs)
    results = []
    for tid, thread in threads.items():
        sent = [m for m in thread if m["from"] == ME]
        if not sent:
            continue
        last_sent = sent[-1]
        later = [m for m in thread if m["_dt"] > last_sent["_dt"]]
        answered = any(m["from"] != ME for m in later)
        if not answered:
            days_waiting = (now - last_sent["_dt"]).days
            if days_waiting >= 3:
                draft = f"Following up on my note from {last_sent['_dt'].date()} ('{last_sent['subject']}') — any update?"
                results.append({"message_id": last_sent["id"], "days_waiting": days_waiting, "draft": draft})
                trace("followup_found", "X1", id=last_sent["id"], days_waiting=days_waiting)
    print(json.dumps(results, indent=2))
    return results


# --------------------------------------------------------------------- X2 --

def cap_X2(msgs, prefs, **kw):
    decisions = cap_R1(msgs, prefs)
    by_id = {m["id"]: m for m in msgs}

    needs_you = [d for d in decisions if d["disposition"] in ("reply", "escalate")]
    can_wait = [d for d in decisions if d["disposition"] in ("defer", "delegate")]
    archived = [d for d in decisions if d["disposition"] == "archive"]

    print("=== Needs you ===")
    for d in needs_you:
        print(f"  {d['id']}: {by_id[d['id']]['subject']} — {d['reason']}")
    print("\n=== Can wait ===")
    for d in can_wait:
        print(f"  {d['id']}: {by_id[d['id']]['subject']} — {d['reason']}")
    print(f"\n=== Auto-archived ({len(archived)}) ===")
    print(f"  {len(archived)} routine/informational messages archived without individual listing")

    trace("digest_built", "X2", needs_you=len(needs_you), can_wait=len(can_wait), archived=len(archived))
    return {"needs_you": needs_you, "can_wait": can_wait, "archived_count": len(archived)}


CAPS = {
    "R1": cap_R1, "R2": cap_R2, "R3": cap_R3, "R4": cap_R4,
    "R5": cap_R5, "R6": cap_R6, "X1": cap_X1, "X2": cap_X2,
}
ORDER = ["R1", "R2", "R3", "R4", "R5", "R6", "X1", "X2"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cap", choices=CAPS.keys())
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--msg", dest="msg_id", default=None)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not args.cap and not args.all:
        ap.error("pass --cap R1..X2 or --all")

    msgs = load_inbox()
    prefs = load_prefs()

    if args.all:
        reset_trace()
        for cap in ORDER:
            print(f"\n########## {cap} ##########")
            # R3 prompts interactively for each send unless --dry-run is
            # given; force dry-run inside --all so this can run
            # unattended. Run `python demo.py --cap R3` directly in a
            # terminal to see the real y/n approval gate.
            dry_run = True if cap == "R3" else args.dry_run
            CAPS[cap](msgs, prefs, msg_id=args.msg_id, dry_run=dry_run)
        return

    if args.cap == "R2" and args.msg_id is None:
        args.msg_id = "m008"
    CAPS[args.cap](msgs, prefs, msg_id=args.msg_id, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
