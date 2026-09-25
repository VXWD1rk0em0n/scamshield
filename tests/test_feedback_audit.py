from __future__ import annotations

import csv
import io
import json
import logging
import sqlite3
import time

import pytest

from conftest import msg
from scamshield import feedback as fb
from scamshield.logging_utils import JsonFormatter, redact
from scamshield.models import Tier

SCAM = "PayPal: confirm your card details now at https://paypal-verify-help.com or call (415) 555-0132. Code 551203."
SENDER = "+1 (415) 555-0132"


def test_audit_record_has_required_fields_and_only_masked_text(rules_only, store):
    res = rules_only.analyze(msg(SCAM, sender=SENDER, claimed="PayPal"))
    row = store.get_case(res.case_id)
    for col in ("case_id", "ts", "channel", "masked_message", "signals", "rule_hits", "llm_output", "score", "tier",
                "intervention", "user_action", "analyst_outcome", "model_version", "config_hash"):
        assert col in row
    assert "555-0132" not in json.dumps(row) and "551203" not in json.dumps(row)
    assert row["sender_masked"] == "[PHONE …32]"
    assert row["config_hash"] == rules_only.config.config_hash
    assert row["user_action"] == "none" and row["analyst_outcome"] == "pending"


def test_audit_log_is_append_only(rules_only, store):
    res = rules_only.analyze(msg(SCAM))
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store._conn.execute("UPDATE audit_log SET tier='LOW' WHERE case_id=?", (res.case_id,))
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store._conn.execute("DELETE FROM audit_log WHERE case_id=?", (res.case_id,))
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store._conn.execute("UPDATE case_events SET event_type='x'")


def test_retention_purge_only_removes_expired_cases(rules_only, store):
    old = rules_only.analyze(msg(SCAM))
    fb.report_scam(store, old.case_id, "u1")
    out = store.purge_expired(30, now_epoch=time.time() + 31 * 86400)  # everything is 31 days old
    assert out["cases_deleted"] == 1 and out["events_deleted"] >= 2
    fresh = rules_only.analyze(msg(SCAM))
    assert store.purge_expired(30)["cases_deleted"] == 0
    assert store.get_case(fresh.case_id) is not None
    assert store.query("SELECT COUNT(*) AS n FROM retention_purge")[0]["n"] == 0  # window closed again


def test_export_csv(rules_only, store):
    rules_only.analyze(msg(SCAM, sender=SENDER))
    rows = list(csv.DictReader(io.StringIO(store.export_csv())))
    assert len(rows) == 1 and rows[0]["tier"] == "CRITICAL"
    assert "555-0132" not in store.export_csv()


def test_appeal_lets_user_proceed_and_queues_case(rules_only, store):
    res = rules_only.analyze(msg(SCAM, sender=SENDER))
    out = fb.appeal_legitimate(store, res.case_id, "u1")
    assert out.ok and out.links_enabled
    assert store.get_case(res.case_id)["user_action"] == "appeal_legitimate"
    queue = fb.analyst_queue(store)
    assert queue[0]["case_id"] == res.case_id and "user appeal" in queue[0]["reasons"]


def test_trust_requires_second_confirmation_and_is_reversible(rules_only, store):
    res = rules_only.analyze(msg("Can you review the Q4 deck before 5pm today? Thanks!", sender="@sam.lee"))
    req = fb.request_trust(store, res.case_id, "u1", "@sam.lee")
    assert not store.is_trusted("u1", "@sam.lee")  # step 1 alone does nothing
    fb.confirm_trust(store, req, confirmed=False)
    assert not store.is_trusted("u1", "@sam.lee")
    fb.confirm_trust(store, fb.request_trust(store, res.case_id, "u1", "@sam.lee"), confirmed=True)
    assert store.is_trusted("u1", "@sam.lee") and not store.is_trusted("someone-else", "@sam.lee")
    again = rules_only.analyze(msg("Can you review the Q4 deck before 5pm today? Thanks!", sender="@sam.lee"), user_id="u1")
    assert again.rules.fired("TRUSTED_SENDER")
    entry = store.trusted_list("u1")[0]
    assert "sam" not in json.dumps(entry)  # only hashed / masked sender stored
    fb.remove_trusted(store, "u1", entry["sender_hash"])
    assert not store.is_trusted("u1", "@sam.lee")


def test_trusted_sender_cannot_mask_a_critical_attack(rules_only, store):
    first = rules_only.analyze(msg("hello there, it's me again from work", sender=SENDER), user_id="u1")
    fb.confirm_trust(store, fb.request_trust(store, first.case_id, "u1", SENDER), confirmed=True)
    res = rules_only.analyze(msg(SCAM, sender=SENDER), user_id="u1")
    assert res.rules.fired("TRUSTED_SENDER") and res.tier.rank >= Tier.HIGH.rank


def test_report_and_analyst_decisions_feed_stats(rules_only, store):
    a = rules_only.analyze(msg(SCAM))
    b = rules_only.analyze(msg("Chase: verify your account at https://chase-login-help.com and reply with your PIN."))
    fb.report_scam(store, a.case_id, "u1")
    fb.appeal_legitimate(store, b.case_id, "u1")
    fb.analyst_decide(store, a.case_id, "ana", fb.AnalystOutcome.CONFIRMED_SCAM)
    fb.analyst_decide(store, b.case_id, "ana", fb.AnalystOutcome.OVERTURNED_LEGITIMATE, "known vendor")
    stats = fb.decision_stats(store)
    assert stats["confirmed_scam"] == 1 and stats["overturned_legitimate"] == 1 and stats["overturn_rate"] == 0.5
    assert stats["appeals"] == 1 and stats["reports"] == 1 and stats["queue_size"] == 0
    assert stats["appeal_outcomes"] == {"overturned_legitimate": 1}
    # overturn is itself reversible: a later decision supersedes it, history is kept
    fb.analyst_decide(store, b.case_id, "lead", fb.AnalystOutcome.CONFIRMED_SCAM)
    assert store.get_case(b.case_id)["analyst_outcome"] == "confirmed_scam"
    assert [e["event_type"] for e in store.events(b.case_id)][-2:] == ["overturned_legitimate", "confirmed_scam"]


def test_events_for_unknown_case_are_rejected(store):
    with pytest.raises(KeyError):
        store.add_event("nope", "user", "report_scam")


def test_structured_logs_never_contain_message_content(rules_only, caplog):
    with caplog.at_level(logging.INFO, logger="scamshield"):
        rules_only.analyze(msg(SCAM, sender=SENDER))
    records = [r for r in caplog.records if r.getMessage() == "analysis_complete"]
    assert records
    line = JsonFormatter().format(records[0])
    payload = json.loads(line)
    assert payload["tier"] == "CRITICAL" and payload["rule_ids"]
    assert "paypal-verify-help" not in line and "555-0132" not in line and "confirm your card" not in line


def test_formatter_drops_unknown_extras_and_redacts_keys():
    rec = logging.LogRecord("scamshield", logging.INFO, __file__, 1, "key sk-ant-api03-abcdefghijk", None, None)
    rec.text = "raw message body"
    out = JsonFormatter().format(rec)
    assert "raw message body" not in out and "sk-ant-api03" not in out
    assert redact("x-api-key: abc123") == "[REDACTED]"
