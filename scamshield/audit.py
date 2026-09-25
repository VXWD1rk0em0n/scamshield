"""Stage 7 - append-only case / audit record in SQLite.

* ``audit_log`` and ``case_events`` reject UPDATE outright and reject DELETE
  unless the row is older than an active retention-purge cutoff (enforced by
  triggers, so even ad-hoc SQL cannot rewrite history).
* User actions and analyst outcomes are appended as events; ``case_view`` shows
  each case with its latest user action and analyst outcome.
* Only masked text is stored. Sender and user IDs are stored as keyed hashes.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from scamshield.models import AnalysisResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    case_id          TEXT PRIMARY KEY,
    ts               TEXT NOT NULL,
    ts_epoch         REAL NOT NULL,
    user_hash        TEXT,
    channel          TEXT,
    status           TEXT,
    masked_message   TEXT,
    sender_masked    TEXT,
    claimed_sender   TEXT,
    signals          TEXT,
    rule_hits        TEXT,
    llm_output       TEXT,
    llm_status       TEXT,
    score            INTEGER,
    tier             TEXT,
    confidence       REAL,
    needs_review     INTEGER,
    mode             TEXT,
    intervention     TEXT,
    user_action      TEXT NOT NULL DEFAULT 'none',
    analyst_outcome  TEXT NOT NULL DEFAULT 'pending',
    model_version    TEXT,
    config_hash      TEXT,
    latency_ms       REAL
);
CREATE TABLE IF NOT EXISTS case_events (
    event_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT NOT NULL REFERENCES audit_log(case_id),
    ts          TEXT NOT NULL,
    ts_epoch    REAL NOT NULL,
    actor       TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    detail      TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_case ON case_events(case_id);
CREATE TABLE IF NOT EXISTS retention_purge (cutoff_epoch REAL NOT NULL);
CREATE TABLE IF NOT EXISTS purge_log (
    ts TEXT NOT NULL, cutoff TEXT NOT NULL, cases_deleted INTEGER, events_deleted INTEGER
);
CREATE TABLE IF NOT EXISTS trusted_senders (
    user_hash     TEXT NOT NULL,
    sender_hash   TEXT NOT NULL,
    sender_masked TEXT,
    case_id       TEXT,
    added_ts      TEXT NOT NULL,
    active        INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (user_hash, sender_hash)
);

CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
WHEN NOT EXISTS (SELECT 1 FROM retention_purge WHERE OLD.ts_epoch < cutoff_epoch)
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only; only expired rows may be purged'); END;
CREATE TRIGGER IF NOT EXISTS case_events_no_update BEFORE UPDATE ON case_events
BEGIN SELECT RAISE(ABORT, 'case_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS case_events_no_delete BEFORE DELETE ON case_events
WHEN NOT EXISTS (SELECT 1 FROM retention_purge r JOIN audit_log a ON a.case_id = OLD.case_id
                 WHERE a.ts_epoch < r.cutoff_epoch)
BEGIN SELECT RAISE(ABORT, 'case_events is append-only; only expired rows may be purged'); END;

CREATE VIEW IF NOT EXISTS case_view AS
SELECT a.case_id, a.ts, a.channel, a.status, a.masked_message, a.sender_masked, a.claimed_sender,
       a.signals, a.rule_hits, a.llm_output, a.llm_status, a.score, a.tier, a.confidence,
       a.needs_review, a.mode, a.intervention,
       COALESCE((SELECT e.event_type FROM case_events e WHERE e.case_id = a.case_id AND e.actor = 'user'
                 ORDER BY e.event_id DESC LIMIT 1), a.user_action) AS user_action,
       COALESCE((SELECT e.event_type FROM case_events e WHERE e.case_id = a.case_id AND e.actor = 'analyst'
                 ORDER BY e.event_id DESC LIMIT 1), a.analyst_outcome) AS analyst_outcome,
       a.model_version, a.config_hash, a.latency_ms, a.user_hash
FROM audit_log a;
"""

EXPORT_COLUMNS = (
    "case_id", "ts", "channel", "status", "masked_message", "sender_masked", "claimed_sender", "signals",
    "rule_hits", "llm_output", "llm_status", "score", "tier", "confidence", "needs_review", "mode",
    "intervention", "user_action", "analyst_outcome", "model_version", "config_hash", "latency_ms",
)


def _now() -> tuple[str, float]:
    epoch = time.time()
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds"), epoch


def _load_pepper(db_path: Path) -> bytes:
    env = os.environ.get("SCAMSHIELD_PEPPER")
    if env:
        return env.encode()
    pepper_file = db_path.parent / ".pepper"
    if not pepper_file.exists():
        pepper_file.write_text(secrets.token_hex(32), encoding="utf-8")
    return pepper_file.read_text(encoding="utf-8").strip().encode()


class AuditStore:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._pepper = _load_pepper(self.path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)

    # ------------------------------------------------------------ identity hashing
    def hash_id(self, value: str | None) -> str | None:
        if not value:
            return None
        norm = "".join(value.split()).lower()
        return hmac.new(self._pepper, norm.encode(), hashlib.sha256).hexdigest()[:24]

    # ------------------------------------------------------------ writes
    def record(self, result: AnalysisResult, *, user_id: str | None, sender_masked: str | None, claimed_masked: str | None) -> None:
        s = result.signals
        signals_json = json.dumps(
            {
                **(result.source or {"source": "text"}),
                "quality_flags": list(s.quality_flags),
                "original_length": s.original_length,
                "truncated": s.truncated,
                "known_contact": s.known_contact,
                "link_hosts": sorted({u.host for u in s.urls}),
                "shorteners": sorted({u.host for u in s.urls if u.is_shortener}),
                "ip_literal_links": sum(u.is_ip_literal for u in s.urls),
                "phones": len(s.phones),
                "amounts": [a.value.strip() for a in s.amounts][:10],
                "crypto_addresses": len(s.crypto_addresses),
                "obfuscation": {
                    "in_word_zero_width": s.obfuscation.in_word_zero_width,
                    "bidi_controls": s.obfuscation.bidi_controls,
                    "mixed_script_words": len(s.obfuscation.mixed_script_words),
                    "compat_chars": s.obfuscation.compat_chars,
                },
            }
        )
        from scamshield.pii import mask_text  # local import keeps module graph acyclic

        rule_hits = [
            {
                "id": h.rule_id,
                "name": h.name,
                "weight": h.weight,
                "reason": mask_text(h.reason).text,
                "snippets": [mask_text(x).text for x in h.snippets],
            }
            for h in (result.rules.hits if result.rules else ())
        ]
        llm = result.llm
        llm_json = json.dumps(llm.verdict.model_dump()) if llm and llm.ok and llm.verdict else None
        risk = result.risk
        with self._lock:
            self._conn.execute(
                """INSERT INTO audit_log (case_id, ts, ts_epoch, user_hash, channel, status, masked_message,
                   sender_masked, claimed_sender, signals, rule_hits, llm_output, llm_status, score, tier,
                   confidence, needs_review, mode, intervention, model_version, config_hash, latency_ms)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    result.case_id,
                    result.timestamp,
                    datetime.fromisoformat(result.timestamp).timestamp(),
                    self.hash_id(user_id),
                    s.channel.value,
                    s.status.value,
                    result.masked_text,
                    sender_masked,
                    claimed_masked,
                    signals_json,
                    json.dumps(rule_hits),
                    llm_json,
                    llm.status.value if llm else None,
                    risk.score if risk else None,
                    risk.tier.value if risk else None,
                    risk.confidence if risk else None,
                    int(risk.needs_review) if risk else 0,
                    risk.mode.value if risk else None,
                    result.intervention.action.value,
                    result.model_version,
                    result.config_hash,
                    round(result.latency_ms, 1),
                ),
            )
            self._conn.execute(
                "INSERT INTO case_events (case_id, ts, ts_epoch, actor, event_type, detail) VALUES (?,?,?,?,?,?)",
                (
                    result.case_id,
                    result.timestamp,
                    datetime.fromisoformat(result.timestamp).timestamp(),
                    "system",
                    f"intervention:{result.intervention.action.value}",
                    json.dumps({"tier": risk.tier.value if risk else None}),
                ),
            )

    def add_event(self, case_id: str, actor: str, event_type: str, detail: dict | None = None) -> None:
        if actor not in {"user", "analyst", "system"}:
            raise ValueError("actor must be user, analyst or system")
        ts, epoch = _now()
        with self._lock:
            if not self._conn.execute("SELECT 1 FROM audit_log WHERE case_id=?", (case_id,)).fetchone():
                raise KeyError(f"unknown case {case_id}")
            self._conn.execute(
                "INSERT INTO case_events (case_id, ts, ts_epoch, actor, event_type, detail) VALUES (?,?,?,?,?,?)",
                (case_id, ts, epoch, actor, event_type, json.dumps(detail or {})),
            )

    # ------------------------------------------------------------ trusted senders
    def set_trusted(self, user_id: str, sender_id: str, *, active: bool, case_id: str | None, sender_masked: str | None) -> None:
        ts, _ = _now()
        with self._lock:
            self._conn.execute(
                """INSERT INTO trusted_senders (user_hash, sender_hash, sender_masked, case_id, added_ts, active)
                   VALUES (?,?,?,?,?,?)
                   ON CONFLICT(user_hash, sender_hash) DO UPDATE SET active=excluded.active, added_ts=excluded.added_ts""",
                (self.hash_id(user_id), self.hash_id(sender_id), sender_masked, case_id, ts, int(active)),
            )

    def is_trusted(self, user_id: str | None, sender_id: str | None) -> bool:
        if not user_id or not sender_id:
            return False
        row = self._conn.execute(
            "SELECT active FROM trusted_senders WHERE user_hash=? AND sender_hash=?",
            (self.hash_id(user_id), self.hash_id(sender_id)),
        ).fetchone()
        return bool(row and row["active"])

    def trusted_list(self, user_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT sender_hash, sender_masked, case_id, added_ts FROM trusted_senders WHERE user_hash=? AND active=1 ORDER BY added_ts DESC",
            (self.hash_id(user_id),),
        ).fetchall()
        return [dict(r) for r in rows]

    def deactivate_trusted_by_hash(self, user_id: str, sender_hash: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE trusted_senders SET active=0 WHERE user_hash=? AND sender_hash=?",
                (self.hash_id(user_id), sender_hash),
            )

    # ------------------------------------------------------------ reads
    def get_case(self, case_id: str) -> dict | None:
        row = self._conn.execute("SELECT * FROM case_view WHERE case_id=?", (case_id,)).fetchone()
        return dict(row) if row else None

    def events(self, case_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT ts, actor, event_type, detail FROM case_events WHERE case_id=? ORDER BY event_id", (case_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def cases(self, limit: int = 200) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM case_view ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def query(self, sql: str, params: tuple = ()) -> list[dict]:
        return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------ export / retention
    def export_csv(self) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(EXPORT_COLUMNS)
        for row in self._conn.execute(f"SELECT {', '.join(EXPORT_COLUMNS)} FROM case_view ORDER BY ts"):
            writer.writerow([row[c] for c in EXPORT_COLUMNS])
        return buf.getvalue()

    def purge_expired(self, retention_days: int, *, now_epoch: float | None = None) -> dict:
        now_epoch = time.time() if now_epoch is None else now_epoch
        cutoff = now_epoch - retention_days * 86400
        cutoff_iso = datetime.fromtimestamp(cutoff, timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute("INSERT INTO retention_purge (cutoff_epoch) VALUES (?)", (cutoff,))
                expired = "SELECT case_id FROM audit_log WHERE ts_epoch < ?"
                ev = self._conn.execute(
                    f"DELETE FROM case_events WHERE case_id IN ({expired})", (cutoff,)
                ).rowcount
                cs = self._conn.execute("DELETE FROM audit_log WHERE ts_epoch < ?", (cutoff,)).rowcount
                self._conn.execute("DELETE FROM retention_purge")
                ts, _ = _now()
                self._conn.execute(
                    "INSERT INTO purge_log (ts, cutoff, cases_deleted, events_deleted) VALUES (?,?,?,?)",
                    (ts, cutoff_iso, cs, ev),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        return {"cutoff": cutoff_iso, "cases_deleted": cs, "events_deleted": ev}

    def close(self) -> None:
        self._conn.close()
