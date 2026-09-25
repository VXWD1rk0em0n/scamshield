"""Stage 6 - user feedback and analyst review.

Recovery path when the system is wrong:
* "This is legitimate" records an appeal and lets the user proceed immediately
  (links re-enabled). The case goes to the analyst queue.
* Adding the sender to the trusted list needs a second, explicit confirmation,
  and the entry can be removed at any time.
* "Report scam" puts the case in the analyst queue.
* Analysts confirm or overturn; every decision is an appended audit event.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from scamshield.audit import AuditStore
from scamshield.pii import mask_sender


class UserAction(str, Enum):
    APPEAL_LEGITIMATE = "appeal_legitimate"
    REPORT_SCAM = "report_scam"
    LINKS_REVEALED = "links_revealed"
    TRUST_REQUESTED = "trust_sender_requested"
    TRUST_CONFIRMED = "trust_sender_confirmed"
    TRUST_CANCELLED = "trust_sender_cancelled"
    TRUST_REMOVED = "trust_sender_removed"


class AnalystOutcome(str, Enum):
    CONFIRMED_SCAM = "confirmed_scam"
    OVERTURNED_LEGITIMATE = "overturned_legitimate"


@dataclass(frozen=True)
class FeedbackOutcome:
    ok: bool
    message: str
    links_enabled: bool = False
    needs_confirmation: bool = False


@dataclass(frozen=True)
class TrustRequest:
    case_id: str
    user_id: str
    sender_id: str
    sender_masked: str | None


def appeal_legitimate(store: AuditStore, case_id: str, user_id: str) -> FeedbackOutcome:
    store.add_event(case_id, "user", UserAction.APPEAL_LEGITIMATE.value)
    return FeedbackOutcome(
        True,
        "Thanks - you can proceed; links are enabled for this message. An analyst will review the case to improve detection.",
        links_enabled=True,
    )


def reveal_links(store: AuditStore, case_id: str, user_id: str) -> FeedbackOutcome:
    store.add_event(case_id, "user", UserAction.LINKS_REVEALED.value)
    return FeedbackOutcome(True, "Links shown as plain text. Open them only if you verified the sender.", links_enabled=True)


def report_scam(store: AuditStore, case_id: str, user_id: str) -> FeedbackOutcome:
    store.add_event(case_id, "user", UserAction.REPORT_SCAM.value)
    return FeedbackOutcome(True, "Reported. The case is in the analyst queue. Nothing was deleted.")


def request_trust(store: AuditStore, case_id: str, user_id: str, sender_id: str | None) -> TrustRequest | FeedbackOutcome:
    """Step 1 of 2 - nothing is trusted until ``confirm_trust`` is called."""
    if not sender_id:
        return FeedbackOutcome(False, "This message has no sender ID, so it can't be added to your trusted list.")
    store.add_event(case_id, "user", UserAction.TRUST_REQUESTED.value)
    return TrustRequest(case_id, user_id, sender_id, mask_sender(sender_id))


def confirm_trust(store: AuditStore, request: TrustRequest, confirmed: bool) -> FeedbackOutcome:
    """Step 2 of 2 - explicit second confirmation adds the sender to the trusted list."""
    if not confirmed:
        store.add_event(request.case_id, "user", UserAction.TRUST_CANCELLED.value)
        return FeedbackOutcome(True, "Not added. You can still proceed with this message.")
    store.set_trusted(
        request.user_id, request.sender_id, active=True, case_id=request.case_id, sender_masked=request.sender_masked
    )
    store.add_event(request.case_id, "user", UserAction.TRUST_CONFIRMED.value, {"sender": request.sender_masked})
    return FeedbackOutcome(
        True,
        f"{request.sender_masked} added to your trusted list. Future messages from it get a lower risk score "
        "(it can still be flagged if it asks for codes or payment while impersonating someone). Remove it any time.",
        links_enabled=True,
    )


def remove_trusted(store: AuditStore, user_id: str, sender_hash: str, case_id: str | None = None) -> FeedbackOutcome:
    store.deactivate_trusted_by_hash(user_id, sender_hash)
    if case_id:
        store.add_event(case_id, "user", UserAction.TRUST_REMOVED.value)
    return FeedbackOutcome(True, "Removed from your trusted list.")


def analyst_decide(store: AuditStore, case_id: str, analyst: str, outcome: AnalystOutcome, note: str = "") -> None:
    store.add_event(case_id, "analyst", outcome.value, {"analyst": analyst, "note": note[:500]})


QUEUE_SQL = """
SELECT * FROM case_view
WHERE analyst_outcome = 'pending'
  AND status = 'OK'
  AND (tier IN ('HIGH', 'CRITICAL') OR needs_review = 1
       OR case_id IN (SELECT case_id FROM case_events
                      WHERE event_type IN ('appeal_legitimate', 'report_scam')))
ORDER BY
  CASE WHEN case_id IN (SELECT case_id FROM case_events WHERE event_type = 'appeal_legitimate') THEN 0
       WHEN needs_review = 1 THEN 1
       WHEN case_id IN (SELECT case_id FROM case_events WHERE event_type = 'report_scam') THEN 2
       ELSE 3 END,
  ts DESC
"""


def analyst_queue(store: AuditStore) -> list[dict]:
    rows = store.query(QUEUE_SQL)
    for r in rows:
        types = {e["event_type"] for e in store.events(r["case_id"])}
        r["reasons"] = ", ".join(
            x
            for x, present in (
                ("user appeal", "appeal_legitimate" in types),
                ("needs review", bool(r["needs_review"])),
                ("user report", "report_scam" in types),
                (f"tier {r['tier']}", r["tier"] in ("HIGH", "CRITICAL")),
            )
            if present
        )
    return rows


def decision_stats(store: AuditStore) -> dict:
    q = store.query
    total = q("SELECT COUNT(*) AS n FROM audit_log")[0]["n"]
    flagged = q("SELECT COUNT(*) AS n FROM audit_log WHERE tier IN ('MEDIUM','HIGH','CRITICAL')")[0]["n"]
    appeals = q("SELECT COUNT(DISTINCT case_id) AS n FROM case_events WHERE event_type='appeal_legitimate'")[0]["n"]
    reports = q("SELECT COUNT(DISTINCT case_id) AS n FROM case_events WHERE event_type='report_scam'")[0]["n"]
    decided = q("SELECT analyst_outcome AS o, COUNT(*) AS n FROM case_view WHERE analyst_outcome != 'pending' GROUP BY analyst_outcome")
    by_outcome = {r["o"]: r["n"] for r in decided}
    appeal_outcomes = q(
        """SELECT analyst_outcome AS o, COUNT(*) AS n FROM case_view
           WHERE case_id IN (SELECT case_id FROM case_events WHERE event_type='appeal_legitimate')
           GROUP BY analyst_outcome"""
    )
    by_tier = {r["tier"] or "INSUFFICIENT_DATA": r["n"] for r in q("SELECT tier, COUNT(*) AS n FROM audit_log GROUP BY tier")}
    overturned = by_outcome.get(AnalystOutcome.OVERTURNED_LEGITIMATE.value, 0)
    confirmed = by_outcome.get(AnalystOutcome.CONFIRMED_SCAM.value, 0)
    decided_n = overturned + confirmed
    return {
        "total_cases": total,
        "flagged_cases": flagged,
        "appeals": appeals,
        "appeal_rate": round(appeals / flagged, 3) if flagged else 0.0,
        "reports": reports,
        "analyst_decisions": decided_n,
        "confirmed_scam": confirmed,
        "overturned_legitimate": overturned,
        "overturn_rate": round(overturned / decided_n, 3) if decided_n else 0.0,
        "appeal_outcomes": {r["o"]: r["n"] for r in appeal_outcomes},
        "by_tier": by_tier,
        "queue_size": len(store.query(QUEUE_SQL)),
    }
