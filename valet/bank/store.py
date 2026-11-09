"""
The bank's own store (SQLite for the PoC). Grants, codes, tokens, approvals, the spend ledger,
receipts and the customer's accounts all live here. Nothing in this file leaves the bank.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from datetime import datetime
from typing import Any

from .config import SAST

SCHEMA = """
CREATE TABLE IF NOT EXISTS customers (id TEXT PRIMARY KEY, username TEXT UNIQUE, name TEXT, password_sha256 TEXT,
    email TEXT UNIQUE);
CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, customer TEXT, name TEXT, number TEXT, balance INTEGER);
CREATE TABLE IF NOT EXISTS beneficiaries (id TEXT PRIMARY KEY, customer TEXT, name TEXT, account TEXT);
CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, account TEXT, time REAL, description TEXT,
    amount INTEGER, by_agent TEXT);
CREATE TABLE IF NOT EXISTS par (request_uri TEXT PRIMARY KEY, client_id TEXT, params TEXT, expires REAL, used INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS grants (id TEXT PRIMARY KEY, customer TEXT, client_id TEXT, level TEXT, details TEXT,
    status TEXT, created REAL, expires REAL, jkt TEXT, consent_hash TEXT, sub TEXT);
CREATE TABLE IF NOT EXISTS codes (code TEXT PRIMARY KEY, grant_id TEXT, client_id TEXT, redirect_uri TEXT,
    challenge TEXT, expires REAL, used INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS refresh (hash TEXT PRIMARY KEY, grant_id TEXT, jkt TEXT, used INTEGER DEFAULT 0, created REAL);
CREATE TABLE IF NOT EXISTS hints (grant_id TEXT, digest TEXT, detail TEXT, expires REAL, PRIMARY KEY (grant_id, digest));
CREATE TABLE IF NOT EXISTS approvals (id TEXT PRIMARY KEY, grant_id TEXT, client_id TEXT, detail TEXT, digest TEXT,
    message TEXT, reason TEXT, status TEXT, created REAL, expires REAL, token_issued INTEGER DEFAULT 0,
    consumed INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS ledger (grant_id TEXT, month TEXT, spent INTEGER, PRIMARY KEY (grant_id, month));
CREATE TABLE IF NOT EXISTS receipts (seq INTEGER PRIMARY KEY, record TEXT, hash TEXT, signature TEXT);
CREATE TABLE IF NOT EXISTS jti (jti TEXT PRIMARY KEY, expires REAL);
"""


def month_key(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts or time.time(), SAST).strftime("%Y-%m")


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


class Store:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.db.executescript(SCHEMA)

    # ------------------------------------------------------------- basics
    def q(self, sql: str, *args: Any) -> list[sqlite3.Row]:
        with self.lock:
            return self.db.execute(sql, args).fetchall()

    def one(self, sql: str, *args: Any) -> sqlite3.Row | None:
        rows = self.q(sql, *args)
        return rows[0] if rows else None

    def x(self, sql: str, *args: Any) -> int:
        with self.lock:
            return self.db.execute(sql, args).rowcount

    def tx(self):
        """`with store.tx():` runs a block atomically."""
        store = self

        class _Tx:
            def __enter__(self):
                store.lock.acquire()
                store.db.execute("BEGIN IMMEDIATE")

            def __exit__(self, et, ev, tb):
                try:
                    store.db.execute("ROLLBACK" if et else "COMMIT")
                finally:
                    store.lock.release()
        return _Tx()

    # -------------------------------------------------------- seed data
    def seed_demo(self) -> None:
        if self.one("SELECT 1 FROM customers"):
            return
        with self.tx():
            self.db.execute("INSERT INTO customers VALUES (?,?,?,?,?)",
                            ("cus_thandi", "thandi", "Thandi Mokoena", _sha("demo"), "thandi@example.com"))
            self.db.execute("INSERT INTO accounts VALUES (?,?,?,?,?)", ("acc_4821", "cus_thandi", "Cheque account", "••4821", 18_430_55))
            self.db.execute("INSERT INTO accounts VALUES (?,?,?,?,?)", ("acc_9907", "cus_thandi", "Savings account", "••9907", 42_000_00))
            for bid, name, acct in [("ben_water", "Water & Sanitation", "40021187"),
                                    ("ben_school", "Sunrise Primary School", "62114930"),
                                    ("ben_dstv", "Satellite TV", "11902241")]:
                self.db.execute("INSERT INTO beneficiaries VALUES (?,?,?,?)", (bid, "cus_thandi", name, acct))
            now = time.time()
            for days, desc, amt in [(3, "Salary", 28_500_00), (2, "Grocer", -1_240_30), (1, "Fuel", -850_00)]:
                self.db.execute("INSERT INTO transactions (account,time,description,amount,by_agent) VALUES (?,?,?,?,?)",
                                ("acc_4821", now - days * 86400, desc, amt, None))

    def check_password(self, username: str, password: str) -> sqlite3.Row | None:
        row = self.one("SELECT * FROM customers WHERE username=?", username)
        return row if row and row["password_sha256"] == _sha(password) else None

    def customer_for_idp(self, value: str) -> sqlite3.Row | None:
        """Map the claim the bank's IdP vouches for (username, email or customer number) to a customer."""
        return self.one("SELECT * FROM customers WHERE username=? OR lower(email)=lower(?) OR id=?", value, value, value)

    # --------------------------------------------------------- DPoP replay
    def seen_jti(self, jti: str, ttl: float = 120) -> bool:
        now = time.time()
        with self.lock:
            self.db.execute("DELETE FROM jti WHERE expires < ?", (now,))
            try:
                self.db.execute("INSERT INTO jti VALUES (?,?)", (jti, now + ttl))
                return False
            except sqlite3.IntegrityError:
                return True

    # ------------------------------------------------------------- grants
    def grant(self, grant_id: str) -> dict[str, Any] | None:
        row = self.one("SELECT * FROM grants WHERE id=?", grant_id)
        if not row:
            return None
        g = dict(row)
        g["details"] = json.loads(g["details"])
        if g["status"] == "active" and g["expires"] < time.time():
            self.x("UPDATE grants SET status='expired' WHERE id=?", grant_id)
            g["status"] = "expired"
        return g

    def grants_for(self, customer: str) -> list[dict[str, Any]]:
        return [self.grant(r["id"]) for r in self.q("SELECT id FROM grants WHERE customer=? ORDER BY created DESC", customer)]

    def set_status(self, grant_id: str, status: str) -> None:
        self.x("UPDATE grants SET status=? WHERE id=?", status, grant_id)
        if status in ("paused", "revoked"):
            self.x("UPDATE approvals SET status='cancelled' WHERE grant_id=? AND status='pending'", grant_id)
        if status == "revoked":
            self.x("DELETE FROM refresh WHERE grant_id=?", grant_id)

    def spent(self, grant_id: str, month: str | None = None) -> int:
        row = self.one("SELECT spent FROM ledger WHERE grant_id=? AND month=?", grant_id, month or month_key())
        return row["spent"] if row else 0
