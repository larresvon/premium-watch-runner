from __future__ import annotations

import hashlib
import hmac
import base64
import gzip
import io
import json
import math
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .models import normalize_cart_probe, utc_now
from .security import validate_public_http_url


HOSTED_PROVIDER_PLATFORMS = frozenset({"shopify", "youngcart", "kimchidvd", "cafe24"})
HOSTED_SNAPSHOT_SCHEMA_VERSION = 1
HOSTED_SNAPSHOT_MAX_COMPRESSED_BYTES = 500_000
HOSTED_SNAPSHOT_MAX_UNCOMPRESSED_BYTES = 10_000_000
HOSTED_SNAPSHOT_RECENT_OBSERVATIONS_PER_GROUP = 12
HOSTED_SNAPSHOT_RECENT_EVENTS = 2_000
HOSTED_SNAPSHOT_RECENT_SENT_OUTBOX = 2_000
HOSTED_SNAPSHOT_ROW_LIMITS = {
    "sources": 100,
    "watches": 500,
    "product_ids": 25_000,
    "products": 25_000,
    "product_variants": 25_000,
    "catalog_latest": 25_000,
    "observations": 50_000,
    "events": 50_000,
    "outbox": 10_000,
}

_HOSTED_SOURCE_FIELDS = (
    "id", "name", "platform", "url", "discovery_enabled", "discovery_interval",
    "product_interval", "include_keywords", "exclude_keywords", "market_context", "currency_hint",
)
_HOSTED_WATCH_FIELDS = (
    "id", "source_id", "product_id", "product_url", "variant_id", "label",
    "cart_probe_enabled", "created_at",
)
_HOSTED_OBSERVATION_FIELDS = frozenset({
    "product_id", "variant_id", "product_title", "variant_title", "url", "image_url",
    "available", "status", "quantity", "quantity_kind", "price", "currency",
    "compare_at_price", "detail", "observed_at", "cart_probe", "market_context",
    "observer_context", "comparison_context",
})
_HOSTED_COMPARISON_FIELDS = frozenset({
    "product_id", "variant_id", "product_title", "variant_title", "url", "image_url",
    "available", "status", "status_observed_at", "quantity", "quantity_kind",
    "availability_observed_at", "quantity_observed_at", "price", "currency",
    "compare_at_price", "price_observed_at", "detail", "observed_at", "cart_probe",
    "market_context", "observer_context", "comparison_context",
})
_HOSTED_EVENT_DETAIL_FIELDS = frozenset({
    "store_name", "variant_title", "availability", "old_available", "new_available",
    "previous_observed_at", "old_price", "new_price", "currency", "direction", "new_low",
    "historical_low", "tracking_started_at", "tracking_note", "quantity", "old_quantity",
    "new_quantity", "quantity_kind", "detail", "old_accepted_quantity",
    "new_accepted_quantity", "requested_quantity", "old_outcome", "new_outcome", "outcome",
    "topic_id", "status", "available", "image_url",
})
_SENSITIVE_QUERY_KEY = re.compile(r"(?:token|auth|session|cookie|password|secret|signature|credential|api[_-]?key|access[_-]?key|sid)", re.I)
_OUTBOX_STATUSES = frozenset({"pending", "retry", "sending", "uncertain", "sent", "failed"})


class Database:
    """Durable local state for Premium Watch."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    @staticmethod
    def json_dump(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def json_load(value: str | bytes | None, default: Any = None) -> Any:
        if value in (None, ""):
            return default
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return default

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level="DEFERRED")
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA synchronous = FULL")
        conn.execute("PRAGMA busy_timeout = 30000")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @contextmanager
    def _using_connection(self, connection: sqlite3.Connection | None) -> Iterator[sqlite3.Connection]:
        if connection is not None:
            yield connection
        else:
            with self.connect() as opened:
                yield opened

    def initialize(self) -> None:
        with self.connect() as db:
            db.execute("PRAGMA journal_mode = WAL")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS app_settings (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    webhook_protected BLOB,
                    mention_user_id TEXT NOT NULL DEFAULT '',
                    mention_role_id TEXT NOT NULL DEFAULT '',
                    notify_price_increases INTEGER NOT NULL DEFAULT 1,
                    auto_discovery_alerts INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL
                );
                INSERT OR IGNORE INTO app_settings(id, updated_at) VALUES (1, CURRENT_TIMESTAMP);

                CREATE TABLE IF NOT EXISTS app_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sources (
                    source_id TEXT PRIMARY KEY,
                    source_json TEXT NOT NULL,
                    baseline_complete INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'waiting',
                    last_success_at TEXT,
                    last_discovery_at TEXT,
                    next_discovery_at TEXT,
                    discovery_failures INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    discovery_status TEXT NOT NULL DEFAULT 'waiting',
                    discovery_last_error TEXT NOT NULL DEFAULT '',
                    discovery_last_success_at TEXT,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS browser_bridge_pairing (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    pair_code_hash TEXT NOT NULL DEFAULT '',
                    pair_code_expires_at TEXT,
                    token_hash TEXT NOT NULL DEFAULT '',
                    extension_origin TEXT NOT NULL DEFAULT '',
                    paired_at TEXT,
                    updated_at TEXT NOT NULL
                );
                INSERT OR IGNORE INTO browser_bridge_pairing(id,updated_at) VALUES(1,CURRENT_TIMESTAMP);

                CREATE TABLE IF NOT EXISTS browser_bridge_sections (
                    source_id TEXT PRIMARY KEY REFERENCES sources(source_id) ON DELETE CASCADE,
                    status TEXT NOT NULL DEFAULT 'waiting',
                    baseline_complete INTEGER NOT NULL DEFAULT 0,
                    last_attempt_at TEXT,
                    last_success_at TEXT,
                    last_capture_at TEXT,
                    last_error TEXT NOT NULL DEFAULT '',
                    last_topic_count INTEGER NOT NULL DEFAULT 0,
                    cursor_topic_id TEXT NOT NULL DEFAULT '',
                    last_report_id TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS browser_bridge_reports (
                    source_id TEXT NOT NULL REFERENCES sources(source_id) ON DELETE CASCADE,
                    report_id TEXT NOT NULL,
                    accepted_at TEXT NOT NULL,
                    PRIMARY KEY(source_id, report_id)
                );

                CREATE TABLE IF NOT EXISTS products (
                    source_id TEXT NOT NULL REFERENCES sources(source_id) ON DELETE CASCADE,
                    product_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    url TEXT NOT NULL,
                    image_url TEXT NOT NULL DEFAULT '',
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    PRIMARY KEY(source_id, product_id)
                );
                CREATE INDEX IF NOT EXISTS products_last_seen_idx ON products(last_seen_at DESC);

                CREATE TABLE IF NOT EXISTS product_variants (
                    source_id TEXT NOT NULL,
                    product_id TEXT NOT NULL,
                    variant_id TEXT NOT NULL DEFAULT '',
                    variant_title TEXT NOT NULL DEFAULT '',
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    PRIMARY KEY(source_id, product_id, variant_id)
                );

                CREATE TABLE IF NOT EXISTS observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id TEXT NOT NULL,
                    product_id TEXT NOT NULL,
                    variant_id TEXT NOT NULL DEFAULT '',
                    observed_at TEXT NOT NULL,
                    price TEXT,
                    currency TEXT,
                    status TEXT NOT NULL,
                    available INTEGER,
                    quantity INTEGER,
                    quantity_kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS observations_exact_idx
                    ON observations(source_id, product_id, variant_id, observed_at DESC, id DESC);
                CREATE INDEX IF NOT EXISTS observations_tracking_idx
                    ON observations(source_id, product_id, observed_at);

                CREATE TABLE IF NOT EXISTS catalog_latest (
                    source_id TEXT NOT NULL,
                    product_id TEXT NOT NULL,
                    variant_id TEXT NOT NULL DEFAULT '',
                    observed_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY(source_id, product_id, variant_id)
                );
                CREATE INDEX IF NOT EXISTS catalog_latest_product_idx
                    ON catalog_latest(source_id, product_id, variant_id);

                CREATE TABLE IF NOT EXISTS watches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id TEXT NOT NULL REFERENCES sources(source_id) ON DELETE CASCADE,
                    product_id TEXT NOT NULL DEFAULT '',
                    product_url TEXT NOT NULL,
                    variant_id TEXT NOT NULL DEFAULT '',
                    label TEXT NOT NULL DEFAULT '',
                    baseline_complete INTEGER NOT NULL DEFAULT 0,
                    cart_probe_enabled INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    UNIQUE(source_id, product_url, variant_id)
                );
                CREATE TABLE IF NOT EXISTS watch_states (
                    watch_id INTEGER NOT NULL REFERENCES watches(id) ON DELETE CASCADE,
                    variant_id TEXT NOT NULL DEFAULT '',
                    observation_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(watch_id, variant_id)
                );
                CREATE TABLE IF NOT EXISTS cart_probe_checks (
                    watch_id INTEGER NOT NULL REFERENCES watches(id) ON DELETE CASCADE,
                    variant_id TEXT NOT NULL DEFAULT '',
                    last_attempt_at TEXT,
                    next_due_at TEXT,
                    last_success_at TEXT,
                    failures INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY(watch_id, variant_id)
                );

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dedup_key TEXT NOT NULL UNIQUE,
                    kind TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    product_id TEXT NOT NULL DEFAULT '',
                    variant_id TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    title TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    url TEXT NOT NULL DEFAULT '',
                    details_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS events_created_idx ON events(created_at DESC, id DESC);

                CREATE TABLE IF NOT EXISTS outbox (
                    id TEXT PRIMARY KEY,
                    event_id INTEGER REFERENCES events(id) ON DELETE SET NULL,
                    kind TEXT NOT NULL DEFAULT 'alert',
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at TEXT NOT NULL,
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    delivered_at TEXT
                );
                CREATE INDEX IF NOT EXISTS outbox_due_idx ON outbox(status, next_attempt_at, created_at);

                CREATE TABLE IF NOT EXISTS checks (
                    source_id TEXT NOT NULL REFERENCES sources(source_id) ON DELETE CASCADE,
                    product_url TEXT NOT NULL,
                    variant_id TEXT NOT NULL DEFAULT '',
                    last_success_at TEXT,
                    next_due_at TEXT,
                    failures INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    PRIMARY KEY(source_id, product_url, variant_id)
                );
                """
            )
            watch_columns = {row["name"] for row in db.execute("PRAGMA table_info(watches)")}
            if "baseline_complete" not in watch_columns:
                db.execute("ALTER TABLE watches ADD COLUMN baseline_complete INTEGER NOT NULL DEFAULT 0")
            if "cart_probe_enabled" not in watch_columns:
                db.execute("ALTER TABLE watches ADD COLUMN cart_probe_enabled INTEGER NOT NULL DEFAULT 0")
            source_columns = {row["name"] for row in db.execute("PRAGMA table_info(sources)")}
            if "discovery_status" not in source_columns:
                db.execute("ALTER TABLE sources ADD COLUMN discovery_status TEXT NOT NULL DEFAULT 'waiting'")
            if "discovery_last_error" not in source_columns:
                db.execute("ALTER TABLE sources ADD COLUMN discovery_last_error TEXT NOT NULL DEFAULT ''")
            if "discovery_last_success_at" not in source_columns:
                db.execute("ALTER TABLE sources ADD COLUMN discovery_last_success_at TEXT")
            bridge_section_columns = {row["name"] for row in db.execute("PRAGMA table_info(browser_bridge_sections)")}
            if "baseline_complete" not in bridge_section_columns:
                db.execute("ALTER TABLE browser_bridge_sections ADD COLUMN baseline_complete INTEGER NOT NULL DEFAULT 0")
            # A process may have stopped after the request crossed the network.
            # Never retry an alert whose delivery result cannot be proved.
            db.execute(
                "UPDATE outbox SET status='uncertain',last_error='Delivery outcome uncertain after restart.' WHERE status='sending'"
            )
            # Migrate old display readings only once; do not rescan growing history on startup.
            if not db.execute("SELECT 1 FROM app_state WHERE key='catalog_latest_migrated'").fetchone():
                db.execute(
                    """INSERT OR IGNORE INTO catalog_latest(source_id,product_id,variant_id,observed_at,payload_json)
                       SELECT o.source_id,o.product_id,o.variant_id,o.observed_at,o.payload_json
                       FROM observations o
                       WHERE o.id IN (
                         SELECT MAX(id) FROM observations GROUP BY source_id,product_id,variant_id
                       )"""
                )
                db.execute(
                    "INSERT INTO app_state(key,value) VALUES('catalog_latest_migrated','1')"
                )

    def seed_source(self, source: dict[str, Any]) -> None:
        source_id = str(source["id"])
        configured = {k: v for k, v in source.items() if k not in {"baseline_complete", "status", "last_success_at", "last_error"}}
        with self.connect() as db:
            db.execute(
                "INSERT OR IGNORE INTO sources(source_id,source_json,updated_at) VALUES(?,?,?)",
                (source_id, self.json_dump(configured), utc_now()),
            )
            if str(configured.get("platform", "")).lower() == "invision":
                db.execute(
                    "INSERT OR IGNORE INTO browser_bridge_sections(source_id,updated_at) VALUES(?,?)",
                    (source_id, utc_now()),
                )

    def upsert_source(self, source: dict[str, Any]) -> None:
        source_id = str(source["id"])
        configured = {k: v for k, v in source.items() if k not in {"baseline_complete", "status", "last_success_at", "last_error"}}
        with self.connect() as db:
            db.execute(
                """INSERT INTO sources(source_id,source_json,updated_at) VALUES(?,?,?)
                   ON CONFLICT(source_id) DO UPDATE SET source_json=excluded.source_json,updated_at=excluded.updated_at""",
                (source_id, self.json_dump(configured), utc_now()),
            )
            if str(configured.get("platform", "")).lower() == "invision":
                db.execute(
                    "INSERT OR IGNORE INTO browser_bridge_sections(source_id,updated_at) VALUES(?,?)",
                    (source_id, utc_now()),
                )

    def sources(self, connection: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
        with self._using_connection(connection) as db:
            rows = db.execute("SELECT * FROM sources ORDER BY source_id").fetchall()
        result = []
        for row in rows:
            source = self.json_load(row["source_json"], {})
            source.setdefault("discovery_enabled", True)
            source.update(
                baseline_complete=bool(row["baseline_complete"]),
                status=row["status"],
                last_success_at=row["last_success_at"],
                last_error=row["last_error"] or "",
                last_discovery_at=row["last_discovery_at"],
                next_discovery_at=row["next_discovery_at"],
                discovery_failures=int(row["discovery_failures"] or 0),
                discovery_status=row["discovery_status"],
                discovery_last_error=row["discovery_last_error"] or "",
                discovery_last_success_at=row["discovery_last_success_at"],
            )
            result.append(source)
        return result

    def source(self, source_id: str, connection: sqlite3.Connection | None = None) -> dict[str, Any] | None:
        with self._using_connection(connection) as db:
            row = db.execute("SELECT * FROM sources WHERE source_id=?", (source_id,)).fetchone()
        if not row:
            return None
        source = self.json_load(row["source_json"], {})
        source.setdefault("discovery_enabled", True)
        source.update(
            baseline_complete=bool(row["baseline_complete"]), status=row["status"],
            last_success_at=row["last_success_at"], last_error=row["last_error"] or "",
            last_discovery_at=row["last_discovery_at"], next_discovery_at=row["next_discovery_at"],
            discovery_failures=int(row["discovery_failures"] or 0),
            discovery_status=row["discovery_status"],
            discovery_last_error=row["discovery_last_error"] or "",
            discovery_last_success_at=row["discovery_last_success_at"],
        )
        return source

    def browser_bridge_credentials(self) -> dict[str, Any]:
        """Return server-side bridge credentials for authentication only."""
        with self.connect() as db:
            row = db.execute("SELECT * FROM browser_bridge_pairing WHERE id=1").fetchone()
        return {key: row[key] for key in row.keys()} if row else {}

    def set_browser_bridge_pair_code(self, code_hash: str, expires_at: str) -> None:
        with self.connect() as db:
            db.execute(
                """UPDATE browser_bridge_pairing SET pair_code_hash=?,pair_code_expires_at=?,updated_at=?
                   WHERE id=1""",
                (code_hash, expires_at, utc_now()),
            )

    def consume_browser_bridge_pair_code(
        self, code_hash: str, *, now: str, token_hash: str, origin: str,
    ) -> bool:
        """Atomically consume a live one-use code and bind a bearer to its origin."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT pair_code_hash,pair_code_expires_at FROM browser_bridge_pairing WHERE id=1"
            ).fetchone()
            if not row or not row["pair_code_hash"] or not row["pair_code_expires_at"]:
                return False
            try:
                expires = datetime.fromisoformat(str(row["pair_code_expires_at"]).replace("Z", "+00:00"))
                current = datetime.fromisoformat(str(now).replace("Z", "+00:00"))
                live = expires.tzinfo is not None and current.tzinfo is not None and current < expires
            except (TypeError, ValueError):
                live = False
            if not live:
                db.execute(
                    "UPDATE browser_bridge_pairing SET pair_code_hash='',pair_code_expires_at=NULL,updated_at=? WHERE id=1",
                    (utc_now(),),
                )
                return False
            if not hmac.compare_digest(str(row["pair_code_hash"]), str(code_hash)):
                return False
            db.execute(
                """UPDATE browser_bridge_pairing
                   SET pair_code_hash='',pair_code_expires_at=NULL,token_hash=?,extension_origin=?,paired_at=?,updated_at=?
                   WHERE id=1""",
                (token_hash, origin, now, now),
            )
            # A new browser identity must explicitly verify both current tabs again.
            # Keep catalog products/history intact; the next complete full scan is quiet.
            db.execute(
                """UPDATE browser_bridge_sections SET status='waiting',baseline_complete=0,
                     last_attempt_at=NULL,last_success_at=NULL,last_capture_at=NULL,last_error='',
                     last_topic_count=0,cursor_topic_id='',last_report_id='',updated_at=?""",
                (now,),
            )
            return True

    def revoke_browser_bridge(self) -> None:
        with self.connect() as db:
            db.execute(
                """UPDATE browser_bridge_pairing
                   SET pair_code_hash='',pair_code_expires_at=NULL,token_hash='',extension_origin='',paired_at=NULL,updated_at=?
                   WHERE id=1""",
                (utc_now(),),
            )

    def browser_bridge_section(self, source_id: str, connection: sqlite3.Connection | None = None) -> dict[str, Any] | None:
        with self._using_connection(connection) as db:
            row = db.execute("SELECT * FROM browser_bridge_sections WHERE source_id=?", (source_id,)).fetchone()
        return {key: row[key] for key in row.keys()} if row else None

    def browser_bridge_sections(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM browser_bridge_sections ORDER BY source_id").fetchall()
        return [{key: row[key] for key in row.keys()} for row in rows]

    def browser_bridge_report_accepted(
        self, source_id: str, report_id: str, connection: sqlite3.Connection | None = None,
    ) -> bool:
        with self._using_connection(connection) as db:
            return db.execute(
                "SELECT 1 FROM browser_bridge_reports WHERE source_id=? AND report_id=?",
                (source_id, report_id),
            ).fetchone() is not None

    def record_browser_bridge_error(
        self, source_id: str, *, attempted_at: str, status: str, error: str,
        connection: sqlite3.Connection | None = None,
    ) -> None:
        with self._using_connection(connection) as db:
            db.execute(
                """INSERT INTO browser_bridge_sections(source_id,status,last_attempt_at,last_error,updated_at)
                   VALUES(?,?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET
                     status=excluded.status,last_attempt_at=excluded.last_attempt_at,
                     last_error=excluded.last_error,updated_at=excluded.updated_at""",
                (source_id, status, attempted_at, error, attempted_at),
            )

    def record_browser_bridge_success(
        self, source_id: str, *, attempted_at: str, captured_at: str, topic_count: int,
        cursor_topic_id: str, report_id: str, connection: sqlite3.Connection | None = None,
    ) -> None:
        with self._using_connection(connection) as db:
            db.execute(
                "INSERT OR IGNORE INTO browser_bridge_reports(source_id,report_id,accepted_at) VALUES(?,?,?)",
                (source_id, report_id, attempted_at),
            )
            db.execute(
                """INSERT INTO browser_bridge_sections(
                     source_id,status,baseline_complete,last_attempt_at,last_success_at,last_capture_at,last_error,
                     last_topic_count,cursor_topic_id,last_report_id,updated_at
                   ) VALUES(?,'healthy',1,?,?,?,'',?,?,?,?)
                   ON CONFLICT(source_id) DO UPDATE SET
                     status='healthy',baseline_complete=1,last_attempt_at=excluded.last_attempt_at,
                     last_success_at=excluded.last_success_at,last_capture_at=excluded.last_capture_at,
                     last_error='',last_topic_count=excluded.last_topic_count,
                     cursor_topic_id=excluded.cursor_topic_id,last_report_id=excluded.last_report_id,
                     updated_at=excluded.updated_at""",
                (source_id, attempted_at, attempted_at, captured_at, topic_count,
                 cursor_topic_id, report_id, attempted_at),
            )

    def update_source_health(
        self, source_id: str, *, baseline_complete: bool | None = None, status: str | None = None,
        last_success_at: str | None = None, last_discovery_at: str | None = None,
        next_discovery_at: str | None = None, discovery_failures: int | None = None,
        last_error: str | None = None, discovery_status: str | None = None,
        discovery_last_error: str | None = None, discovery_last_success_at: str | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> None:
        fields: dict[str, Any] = {"updated_at": utc_now()}
        for key, value in (
            ("baseline_complete", None if baseline_complete is None else int(baseline_complete)),
            ("status", status), ("last_success_at", last_success_at),
            ("last_discovery_at", last_discovery_at), ("next_discovery_at", next_discovery_at),
            ("discovery_failures", discovery_failures), ("last_error", last_error),
            ("discovery_status", discovery_status), ("discovery_last_error", discovery_last_error),
            ("discovery_last_success_at", discovery_last_success_at),
        ):
            if value is not None:
                fields[key] = value
        sql = ",".join(f"{key}=?" for key in fields)
        with self._using_connection(connection) as db:
            db.execute(f"UPDATE sources SET {sql} WHERE source_id=?", (*fields.values(), source_id))

    def upsert_product(
        self, source_id: str, product: dict[str, Any], at: str,
        connection: sqlite3.Connection | None = None,
    ) -> bool:
        with self._using_connection(connection) as db:
            existing = db.execute(
                "SELECT 1 FROM products WHERE source_id=? AND product_id=?",
                (source_id, product["product_id"]),
            ).fetchone()
            db.execute(
                """INSERT INTO products(source_id,product_id,title,url,image_url,first_seen_at,last_seen_at)
                   VALUES(?,?,?,?,?,?,?) ON CONFLICT(source_id,product_id) DO UPDATE SET
                     title=excluded.title,url=excluded.url,image_url=excluded.image_url,last_seen_at=excluded.last_seen_at""",
                (source_id, product["product_id"], product["title"], product["url"], product.get("image_url", ""), at, at),
            )
        return existing is None

    def products(self, source_id: str = "", connection: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
        with self._using_connection(connection) as db:
            rows = db.execute(
                "SELECT * FROM products WHERE (?='' OR source_id=?) ORDER BY last_seen_at DESC, title COLLATE NOCASE",
                (source_id, source_id),
            ).fetchall()
        return [{key: row[key] for key in row.keys()} for row in rows]

    def products_with_catalog_latest(self) -> list[dict[str, Any]]:
        """Read products and latest variant readings in one query/connection."""
        with self.connect() as db:
            rows = db.execute(
                """SELECT p.*,c.variant_id AS catalog_variant_id,c.payload_json AS catalog_payload_json
                   FROM products p LEFT JOIN catalog_latest c
                     ON c.source_id=p.source_id AND c.product_id=p.product_id
                   ORDER BY p.last_seen_at DESC,p.title COLLATE NOCASE,c.variant_id"""
            ).fetchall()
        products: dict[tuple[str, str], dict[str, Any]] = {}
        for row in rows:
            key = (row["source_id"], row["product_id"])
            item = products.get(key)
            if item is None:
                item = {name: row[name] for name in ("source_id", "product_id", "title", "url", "image_url", "first_seen_at", "last_seen_at")}
                item["variants"] = []
                products[key] = item
            payload = row["catalog_payload_json"]
            if payload:
                item["variants"].append(self.json_load(payload, {}))
        return list(products.values())

    def register_variant(
        self, source_id: str, product_id: str, variant_id: str, variant_title: str, at: str,
        connection: sqlite3.Connection | None = None,
    ) -> bool:
        with self._using_connection(connection) as db:
            existing = db.execute(
                "SELECT 1 FROM product_variants WHERE source_id=? AND product_id=? AND variant_id=?",
                (source_id, product_id, variant_id),
            ).fetchone()
            db.execute(
                """INSERT INTO product_variants(source_id,product_id,variant_id,variant_title,first_seen_at,last_seen_at)
                   VALUES(?,?,?,?,?,?) ON CONFLICT(source_id,product_id,variant_id) DO UPDATE SET
                     variant_title=excluded.variant_title,last_seen_at=excluded.last_seen_at""",
                (source_id, product_id, variant_id, variant_title, at, at),
            )
        return existing is None

    def latest_observation(
        self, source_id: str, product_id: str, variant_id: str,
        connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any] | None:
        with self._using_connection(connection) as db:
            row = db.execute(
                """SELECT payload_json FROM catalog_latest WHERE source_id=? AND product_id=? AND variant_id=?""",
                (source_id, product_id, variant_id),
            ).fetchone()
        return self.json_load(row["payload_json"], None) if row else None

    def latest_observations(
        self, source_id: str, product_id: str, variant_id: str | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> list[dict[str, Any]]:
        with self._using_connection(connection) as db:
            rows = db.execute(
                """SELECT payload_json FROM catalog_latest WHERE source_id=? AND product_id=?
                   AND (? IS NULL OR variant_id=?)
                   ORDER BY variant_id""",
                (source_id, product_id, variant_id, variant_id),
            ).fetchall()
        return [self.json_load(row["payload_json"], {}) for row in rows]

    def upsert_catalog_observation(
        self, source_id: str, observation: dict[str, Any],
        connection: sqlite3.Connection | None = None,
    ) -> None:
        with self._using_connection(connection) as db:
            db.execute(
                """INSERT INTO catalog_latest(source_id,product_id,variant_id,observed_at,payload_json)
                   VALUES(?,?,?,?,?) ON CONFLICT(source_id,product_id,variant_id) DO UPDATE SET
                     observed_at=excluded.observed_at,payload_json=excluded.payload_json
                   WHERE excluded.observed_at >= catalog_latest.observed_at""",
                (source_id, observation["product_id"], observation["variant_id"],
                 observation["observed_at"], self.json_dump(observation)),
            )

    def save_observation(
        self, source_id: str, observation: dict[str, Any],
        connection: sqlite3.Connection | None = None,
    ) -> None:
        encoded = self.json_dump(observation)
        available = observation.get("available")
        with self._using_connection(connection) as db:
            db.execute(
                """INSERT INTO observations(source_id,product_id,variant_id,observed_at,price,currency,status,
                     available,quantity,quantity_kind,payload_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    source_id, observation["product_id"], observation["variant_id"], observation["observed_at"],
                    observation.get("price"), observation.get("currency"), observation["status"],
                    None if available is None else int(available), observation.get("quantity"),
                    observation["quantity_kind"], encoded,
                ),
            )

    def observation_rows_since(self, source_id: str, product_id: str, since: str) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT variant_id,observed_at,price,currency,payload_json FROM observations
                   WHERE source_id=? AND product_id=? AND observed_at>=? AND price IS NOT NULL
                   ORDER BY variant_id,observed_at,id""",
                (source_id, product_id, since),
            ).fetchall()
        return [{key: row[key] for key in row.keys()} for row in rows]

    def add_watch(
        self, source_id: str, product_id: str, product_url: str, variant_id: str, label: str,
        *, cart_probe_enabled: bool | None = None,
    ) -> tuple[int, bool]:
        with self.connect() as db:
            row = db.execute(
                "SELECT id FROM watches WHERE source_id=? AND product_url=? AND variant_id=?",
                (source_id, product_url, variant_id),
            ).fetchone()
            if row:
                db.execute("UPDATE watches SET product_id=?,label=? WHERE id=?", (product_id, label, row["id"]))
                # Re-adding an existing watch must not silently pause a probe
                # the user enabled from its watch-card toggle. Enabling from
                # an add form remains supported; disabling is explicit via
                # set_cart_probe_enabled().
                if cart_probe_enabled:
                    db.execute(
                        "UPDATE watches SET cart_probe_enabled=? WHERE id=?",
                        (1, row["id"]),
                    )
                return int(row["id"]), False
            tracking_started = datetime.now(timezone.utc).isoformat(timespec="microseconds")
            cur = db.execute(
                """INSERT INTO watches(source_id,product_id,product_url,variant_id,label,
                       cart_probe_enabled,created_at) VALUES(?,?,?,?,?,?,?)""",
                (source_id, product_id, product_url, variant_id, label,
                 int(bool(cart_probe_enabled)), tracking_started),
            )
            return int(cur.lastrowid), True

    def set_cart_probe_enabled(self, watch_id: str | int, enabled: bool) -> bool:
        with self.connect() as db:
            cursor = db.execute(
                "UPDATE watches SET cart_probe_enabled=? WHERE id=?",
                (int(enabled), str(watch_id)),
            )
            return cursor.rowcount > 0

    def mark_watch_check_due(self, source_id: str, product_url: str, variant_id: str) -> None:
        now = utc_now()
        with self.connect() as db:
            db.execute(
                """INSERT INTO checks(source_id,product_url,variant_id,next_due_at)
                   VALUES(?,?,?,?) ON CONFLICT(source_id,product_url,variant_id)
                   DO UPDATE SET next_due_at=excluded.next_due_at""",
                (source_id, product_url, variant_id, now),
            )

    def claim_cart_probe(
        self, watch_id: int, variant_id: str, *, now: str | None = None,
        cooldown_seconds: int = 900,
    ) -> bool:
        """Atomically reserve a per-watch/per-variant probe cooldown."""
        attempt_at = now or utc_now()
        try:
            parsed = datetime.fromisoformat(attempt_at.replace("Z", "+00:00"))
        except (TypeError, ValueError) as exc:
            raise ValueError("Cart probe time must be ISO date/time text.") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("Cart probe time must include a time zone.")
        next_due = (parsed.astimezone(timezone.utc) + timedelta(seconds=max(60, int(cooldown_seconds)))).isoformat(timespec="microseconds")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT next_due_at FROM cart_probe_checks WHERE watch_id=? AND variant_id=?",
                (watch_id, variant_id),
            ).fetchone()
            if row and row["next_due_at"]:
                try:
                    due = datetime.fromisoformat(str(row["next_due_at"]).replace("Z", "+00:00"))
                except ValueError:
                    due = None
                if due is not None and due.tzinfo is not None and due > parsed.astimezone(timezone.utc):
                    return False
            db.execute(
                """INSERT INTO cart_probe_checks(watch_id,variant_id,last_attempt_at,next_due_at)
                   VALUES(?,?,?,?) ON CONFLICT(watch_id,variant_id) DO UPDATE SET
                     last_attempt_at=excluded.last_attempt_at,next_due_at=excluded.next_due_at""",
                (watch_id, variant_id, attempt_at, next_due),
            )
            return True

    def release_cart_probe_claim(self, watch_id: int, variant_id: str, *, attempted_at: str) -> None:
        """Undo only an unaccepted reservation owned by an interrupted handoff."""
        with self.connect() as db:
            db.execute(
                """UPDATE cart_probe_checks SET last_attempt_at=NULL,next_due_at=NULL
                   WHERE watch_id=? AND variant_id=? AND last_attempt_at=? AND last_success_at IS NULL""",
                (watch_id, variant_id, attempted_at),
            )

    def finish_cart_probe(
        self, watch_id: int, variant_id: str, *, success: bool,
        error_code: str = "", connection: sqlite3.Connection | None = None,
    ) -> None:
        with self._using_connection(connection) as db:
            if success:
                db.execute(
                    """UPDATE cart_probe_checks SET last_success_at=last_attempt_at,
                       failures=0,last_error='' WHERE watch_id=? AND variant_id=?""",
                    (watch_id, variant_id),
                )
            else:
                db.execute(
                    """UPDATE cart_probe_checks SET failures=failures+1,last_error=?
                       WHERE watch_id=? AND variant_id=?""",
                    (str(error_code or "cart_probe_failed")[:80], watch_id, variant_id),
                )

    def watches(self, connection: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
        with self._using_connection(connection) as db:
            rows = db.execute("SELECT * FROM watches ORDER BY created_at DESC,id DESC").fetchall()
        return [{key: row[key] for key in row.keys()} for row in rows]

    def watch(self, watch_id: str | int, connection: sqlite3.Connection | None = None) -> dict[str, Any] | None:
        with self._using_connection(connection) as db:
            row = db.execute("SELECT * FROM watches WHERE id=?", (str(watch_id),)).fetchone()
        return {key: row[key] for key in row.keys()} if row else None

    def update_watch_product(self, watch_id: int, product_id: str, connection: sqlite3.Connection | None = None) -> None:
        with self._using_connection(connection) as db:
            db.execute("UPDATE watches SET product_id=? WHERE id=? AND product_id=''", (product_id, watch_id))

    def watch_state(
        self, watch_id: int, variant_id: str, connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any] | None:
        with self._using_connection(connection) as db:
            row = db.execute("SELECT * FROM watch_states WHERE watch_id=? AND variant_id=?", (watch_id, variant_id)).fetchone()
        if not row:
            return None
        return {
            "watch_id": int(row["watch_id"]), "variant_id": row["variant_id"],
            "observation": self.json_load(row["observation_json"], {}), "updated_at": row["updated_at"],
        }

    def watch_latest_observations(
        self, watch_id: int, variant_id: str | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> list[dict[str, Any]]:
        """Return last raw successful readings owned by this watch, per variant."""
        with self._using_connection(connection) as db:
            rows = db.execute(
                """SELECT variant_id,observation_json FROM watch_states WHERE watch_id=?
                   AND (? IS NULL OR variant_id=?) ORDER BY variant_id""",
                (watch_id, variant_id, variant_id),
            ).fetchall()
        result = []
        for row in rows:
            stored = self.json_load(row["observation_json"], {})
            if not isinstance(stored, dict):
                continue
            raw = stored.get("latest_observation")
            if raw is None:
                # Rows written before watch states gained a raw-reading envelope.
                raw = stored.get("comparison") if "comparison" in stored else stored
            if isinstance(raw, dict):
                result.append(raw)
        return result

    def save_watch_state(
        self, watch_id: int, observation: dict[str, Any], connection: sqlite3.Connection | None = None,
    ) -> None:
        with self._using_connection(connection) as db:
            db.execute(
                """INSERT INTO watch_states(watch_id,variant_id,observation_json,updated_at) VALUES(?,?,?,?)
                   ON CONFLICT(watch_id,variant_id) DO UPDATE SET
                     observation_json=excluded.observation_json,updated_at=excluded.updated_at""",
                (watch_id, observation["variant_id"], self.json_dump(observation), observation["observed_at"]),
            )

    def complete_watch_baseline(self, watch_id: int, connection: sqlite3.Connection | None = None) -> None:
        with self._using_connection(connection) as db:
            db.execute("UPDATE watches SET baseline_complete=1 WHERE id=?", (watch_id,))

    def lowest_price_since(
        self, source_id: str, product_id: str, variant_id: str, currency: str, since: str,
        connection: sqlite3.Connection | None = None, *, comparison_context: str | None = None,
    ) -> tuple[str, str] | None:
        with self._using_connection(connection) as db:
            rows = db.execute(
                """SELECT price,observed_at,payload_json FROM observations WHERE source_id=? AND product_id=? AND variant_id=?
                   AND currency=? AND observed_at>=? AND price IS NOT NULL""",
                (source_id, product_id, variant_id, currency, since),
            ).fetchall()
        if comparison_context is not None:
            rows = [
                row for row in rows
                if self.json_load(row["payload_json"], {}).get("comparison_context") == comparison_context
            ]
        if not rows:
            return None
        lowest = min(Decimal(str(row["price"])) for row in rows)
        earliest = min(str(row["observed_at"]) for row in rows if Decimal(str(row["price"])) == lowest)
        return format(lowest.normalize(), "f"), earliest

    def remove_watch(self, watch_id: str | int) -> bool:
        with self.connect() as db:
            cur = db.execute("DELETE FROM watches WHERE id=?", (str(watch_id),))
        return cur.rowcount > 0

    def insert_event(
        self, event: dict[str, Any], outbox_payload: dict[str, Any] | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> int | None:
        with self._using_connection(connection) as db:
            cur = db.execute(
                """INSERT OR IGNORE INTO events(dedup_key,kind,source_id,product_id,variant_id,created_at,title,summary,url,details_json)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    event["dedup_key"], event["kind"], event.get("source_id", ""), event.get("product_id", ""),
                    event.get("variant_id", ""), event.get("created_at") or utc_now(), event.get("title", ""),
                    event.get("summary", ""), event.get("url", ""), self.json_dump(event.get("details", {})),
                ),
            )
            if cur.rowcount == 0:
                return None
            event_id = int(cur.lastrowid)
            if outbox_payload is not None:
                db.execute(
                    """INSERT INTO outbox(id,event_id,kind,payload_json,next_attempt_at,created_at)
                       VALUES(?,?,?,?,?,?)""",
                    (str(uuid.uuid4()), event_id, "alert", self.json_dump(outbox_payload), utc_now(), utc_now()),
                )
            return event_id

    def insert_test_outbox(self, payload: dict[str, Any]) -> str:
        outbox_id = str(uuid.uuid4())
        now = utc_now()
        with self.connect() as db:
            cur = db.execute(
                """INSERT INTO events(dedup_key,kind,source_id,product_id,variant_id,created_at,title,summary,url,details_json)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (f"test:{outbox_id}", "test_alert", "", "", "", now, "Test alert", "A user requested Premium Watch test alert.", "", "{}"),
            )
            event_id = int(cur.lastrowid)
            db.execute(
                "INSERT INTO outbox(id,event_id,kind,payload_json,next_attempt_at,created_at) VALUES(?,?,?,?,?,?)",
                (outbox_id, event_id, "test", self.json_dump(payload), now, now),
            )
        return outbox_id

    def events(self, limit: int = 200) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM events ORDER BY created_at DESC,id DESC LIMIT ?", (max(1, min(limit, 1000)),)).fetchall()
        result = []
        for row in rows:
            item = {key: row[key] for key in row.keys() if key != "details_json"}
            item["details"] = self.json_load(row["details_json"], {})
            result.append(item)
        return result

    def outbox(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT id,event_id,kind,status,attempts,next_attempt_at,last_error,created_at,delivered_at FROM outbox ORDER BY created_at DESC LIMIT ?",
                (max(1, min(limit, 500)),),
            ).fetchall()
        return [{key: row[key] for key in row.keys()} for row in rows]

    def due_outbox(self, now: str | None = None, limit: int = 25) -> list[dict[str, Any]]:
        at = now or utc_now()
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM outbox WHERE status IN ('pending','retry') AND next_attempt_at<=? ORDER BY created_at LIMIT ?",
                (at, max(1, min(limit, 100))),
            ).fetchall()
        return [{key: row[key] for key in row.keys()} for row in rows]

    def uncertain_outbox_count(self) -> int:
        with self.connect() as db:
            row = db.execute("SELECT COUNT(*) AS count FROM outbox WHERE status='uncertain'").fetchone()
        return int(row["count"] or 0)

    def claim_outbox_sending(self, outbox_id: str, *, now: str | None = None) -> bool:
        """Durably mark an alert in flight before its first network byte is sent."""
        at = now or utc_now()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute(
                """UPDATE outbox SET status='sending',attempts=attempts+1,last_error=NULL
                   WHERE id=? AND status IN ('pending','retry') AND next_attempt_at<=?""",
                (outbox_id, at),
            )
        return cursor.rowcount == 1

    def mark_outbox_uncertain(self, outbox_id: str, *, error: str = "Delivery outcome uncertain.") -> None:
        with self.connect() as db:
            db.execute(
                "UPDATE outbox SET status='uncertain',last_error=? WHERE id=? AND status='sending'",
                (error[:300], outbox_id),
            )

    def next_outbox_retry_at(self) -> str | None:
        with self.connect() as db:
            row = db.execute("SELECT MIN(next_attempt_at) AS due FROM outbox WHERE status='retry'").fetchone()
        return row["due"] if row else None

    def mark_outbox_sent(self, outbox_id: str) -> None:
        with self.connect() as db:
            db.execute("UPDATE outbox SET status='sent',delivered_at=?,last_error=NULL WHERE id=? AND status='sending'", (utc_now(), outbox_id))

    def mark_outbox_retry(self, outbox_id: str, *, attempts: int, next_attempt_at: str, error: str) -> None:
        with self.connect() as db:
            db.execute(
                "UPDATE outbox SET status='retry',attempts=?,next_attempt_at=?,last_error=? WHERE id=? AND status='sending'",
                (attempts, next_attempt_at, error[:300], outbox_id),
            )

    def mark_outbox_failed(self, outbox_id: str, *, attempts: int, error: str) -> None:
        with self.connect() as db:
            db.execute(
                "UPDATE outbox SET status='failed',attempts=?,last_error=? WHERE id=? AND status='sending'",
                (attempts, error[:300], outbox_id),
            )

    def settings(self, connection: sqlite3.Connection | None = None) -> dict[str, Any]:
        with self._using_connection(connection) as db:
            row = db.execute("SELECT * FROM app_settings WHERE id=1").fetchone()
        return {
            "webhook_protected": row["webhook_protected"],
            "mention_user_id": row["mention_user_id"] or "",
            "mention_role_id": row["mention_role_id"] or "",
            "notify_price_increases": bool(row["notify_price_increases"]),
            "auto_discovery_alerts": bool(row["auto_discovery_alerts"]),
            "updated_at": row["updated_at"],
        }

    def save_settings(self, settings: dict[str, Any]) -> None:
        accepted = {
            "webhook_protected", "mention_user_id", "mention_role_id",
            "notify_price_increases", "auto_discovery_alerts",
        }
        updates = {key: settings[key] for key in accepted if key in settings}
        if not updates:
            return
        updates["updated_at"] = utc_now()
        fields = []
        values = []
        for key, value in updates.items():
            if key in {"notify_price_increases", "auto_discovery_alerts"}:
                value = int(bool(value))
            fields.append(f"{key}=?")
            values.append(value)
        with self.connect() as db:
            db.execute(f"UPDATE app_settings SET {','.join(fields)} WHERE id=1", values)

    def set_state(self, key: str, value: str) -> None:
        with self.connect() as db:
            db.execute("INSERT INTO app_state(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def get_state(self, key: str) -> str | None:
        with self.connect() as db:
            row = db.execute("SELECT value FROM app_state WHERE key=?", (key,)).fetchone()
        return str(row["value"]) if row else None

    def get_or_create_execution_context_id(self) -> str:
        """Stable per-install executor identity; it is provenance, not a market claim."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT value FROM app_state WHERE key='execution_context_id'").fetchone()
            if row:
                return str(row["value"])
            value = str(uuid.uuid4())
            db.execute("INSERT INTO app_state(key,value) VALUES('execution_context_id',?)", (value,))
            return value

    def adopt_legacy_local_context(self, context_id: str) -> int:
        """Tag pre-provenance local history once, without adopting imported cloud rows."""
        context_id = self._safe_text(context_id, limit=120, name="execution context")
        if not context_id:
            raise ValueError("Execution context cannot be empty.")
        executor_context = "executor:" + context_id
        adopted = 0

        def stamp(observation: Any, market: Any = None) -> tuple[Any, bool]:
            if not isinstance(observation, dict) or observation.get("comparison_context") not in (None, ""):
                return observation, False
            value = dict(observation)
            market_context = value.get("market_context") or market
            if market_context not in (None, ""):
                value["market_context"] = market_context
                value["comparison_context"] = "market:" + self._canonical_digest(market_context)
            else:
                value["comparison_context"] = executor_context
            value.setdefault("observer_context", context_id)
            return value, True

        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            marker = db.execute("SELECT value FROM app_state WHERE key='legacy_local_context_adopted'").fetchone()
            if marker:
                return 0
            source_markets = {}
            for row in db.execute("SELECT source_id,source_json FROM sources").fetchall():
                source = self.json_load(row["source_json"], {})
                source_markets[row["source_id"]] = source.get("market_context") if isinstance(source, dict) else None
            for row in db.execute("SELECT id,source_id,payload_json FROM observations").fetchall():
                payload = self.json_load(row["payload_json"], {})
                updated, changed = stamp(payload, source_markets.get(row["source_id"]))
                if changed:
                    db.execute("UPDATE observations SET payload_json=? WHERE id=?", (self.json_dump(updated), row["id"]))
                    adopted += 1
            for row in db.execute(
                """SELECT s.watch_id,s.variant_id,s.observation_json,w.source_id
                   FROM watch_states s JOIN watches w ON w.id=s.watch_id"""
            ).fetchall():
                state = self.json_load(row["observation_json"], {})
                if not isinstance(state, dict):
                    continue
                changed = False
                if isinstance(state.get("comparison"), dict):
                    state["comparison"], did_change = stamp(state["comparison"], source_markets.get(row["source_id"]))
                    changed = changed or did_change
                if isinstance(state.get("latest_observation"), dict):
                    state["latest_observation"], did_change = stamp(state["latest_observation"], source_markets.get(row["source_id"]))
                    changed = changed or did_change
                if "comparison" not in state and "latest_observation" not in state:
                    state, changed = stamp(state, source_markets.get(row["source_id"]))
                if changed:
                    db.execute(
                        "UPDATE watch_states SET observation_json=? WHERE watch_id=? AND variant_id=?",
                        (self.json_dump(state), row["watch_id"], row["variant_id"]),
                    )
                    adopted += 1
            db.execute(
                "INSERT INTO app_state(key,value) VALUES('legacy_local_context_adopted',?)",
                (context_id,),
            )
        return adopted

    def check_state(
        self, source_id: str, product_url: str, variant_id: str,
        connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        with self._using_connection(connection) as db:
            row = db.execute(
                "SELECT * FROM checks WHERE source_id=? AND product_url=? AND variant_id=?",
                (source_id, product_url, variant_id),
            ).fetchone()
        return {key: row[key] for key in row.keys()} if row else {
            "source_id": source_id, "product_url": product_url, "variant_id": variant_id,
            "last_success_at": None, "next_due_at": None, "failures": 0, "last_error": "",
        }

    def update_check(self, source_id: str, product_url: str, variant_id: str, *, last_success_at: str | None = None,
                     next_due_at: str | None = None, failures: int | None = None, last_error: str | None = None,
                     connection: sqlite3.Connection | None = None) -> None:
        old = self.check_state(source_id, product_url, variant_id, connection=connection)
        values = {
            "last_success_at": last_success_at if last_success_at is not None else old.get("last_success_at"),
            "next_due_at": next_due_at if next_due_at is not None else old.get("next_due_at"),
            "failures": int(failures if failures is not None else old.get("failures", 0)),
            "last_error": last_error if last_error is not None else old.get("last_error", ""),
        }
        with self._using_connection(connection) as db:
            db.execute(
                """INSERT INTO checks(source_id,product_url,variant_id,last_success_at,next_due_at,failures,last_error)
                   VALUES(?,?,?,?,?,?,?) ON CONFLICT(source_id,product_url,variant_id) DO UPDATE SET
                     last_success_at=excluded.last_success_at,next_due_at=excluded.next_due_at,
                     failures=excluded.failures,last_error=excluded.last_error""",
                (source_id, product_url, variant_id, values["last_success_at"], values["next_due_at"], values["failures"], values["last_error"]),
            )

    def all_checks(self, connection: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
        with self._using_connection(connection) as db:
            rows = db.execute("SELECT * FROM checks").fetchall()
        return [{key: row[key] for key in row.keys()} for row in rows]

    @staticmethod
    def _safe_text(value: Any, *, limit: int, name: str) -> str:
        if not isinstance(value, str) or len(value) > limit or "\x00" in value:
            raise ValueError(f"Hosted snapshot contains invalid {name}.")
        return value

    @classmethod
    def _safe_timestamp(cls, value: Any, *, name: str, optional: bool = False) -> str | None:
        if value in (None, "") and optional:
            return None if value is None else ""
        text = cls._safe_text(value, limit=80, name=name)
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Hosted snapshot contains invalid {name}.") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError(f"Hosted snapshot contains invalid {name}.")
        return text

    @staticmethod
    def _safe_count(value: Any, *, name: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"Hosted snapshot contains invalid {name}.")
        return value

    @staticmethod
    def _safe_decimal(value: Any, *, name: str) -> str | None:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float, str)):
            raise ValueError(f"Hosted snapshot contains invalid {name}.")
        try:
            amount = Decimal(str(value))
        except Exception as exc:
            raise ValueError(f"Hosted snapshot contains invalid {name}.") from exc
        if not amount.is_finite() or amount < 0:
            raise ValueError(f"Hosted snapshot contains invalid {name}.")
        return format(amount.normalize(), "f")

    @classmethod
    def _safe_public_url(cls, value: Any) -> str:
        url = validate_public_http_url(cls._safe_text(value, limit=2000, name="URL"))
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        if any(_SENSITIVE_QUERY_KEY.search(key) for key, _ in pairs):
            raise ValueError("Hosted snapshots cannot contain credential-bearing URL parameters.")
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), ""))

    @classmethod
    def _safe_market_context(cls, value: Any) -> str | dict[str, str] | None:
        if value in (None, ""):
            return None
        if isinstance(value, str):
            return cls._safe_text(value, limit=120, name="market context")
        allowed = {"market", "country", "region", "locale", "shipping_country", "storefront"}
        if not isinstance(value, dict) or set(value) - allowed or len(value) > len(allowed):
            raise ValueError("Hosted snapshot contains invalid market context.")
        result = {}
        for key, item in value.items():
            if item not in (None, ""):
                result[key] = cls._safe_text(item, limit=80, name="market context value")
        return dict(sorted(result.items())) or None

    @classmethod
    def _safe_observation(cls, value: Any, *, comparison: bool = False) -> dict[str, Any]:
        if not isinstance(value, dict) or len(value) > 40:
            raise ValueError("Hosted snapshot contains an invalid observation.")
        allowed = _HOSTED_COMPARISON_FIELDS if comparison else _HOSTED_OBSERVATION_FIELDS
        if set(value) - allowed:
            raise ValueError("Hosted snapshot observation contains unsupported fields.")
        result: dict[str, Any] = {}
        text_limits = {
            "product_id": 240, "variant_id": 240, "product_title": 300, "variant_title": 240,
            "url": 2000, "image_url": 2000, "status": 40, "quantity_kind": 20,
            "currency": 3, "price": 40, "compare_at_price": 40, "detail": 800,
            "observed_at": 80, "status_observed_at": 80, "availability_observed_at": 80,
            "quantity_observed_at": 80, "price_observed_at": 80, "observer_context": 120,
            "comparison_context": 200,
        }
        for key, item in value.items():
            if key in {"market_context"}:
                context = cls._safe_market_context(item)
                if context is not None:
                    result[key] = context
            elif key in {"url", "image_url"}:
                if item not in (None, ""):
                    result[key] = cls._safe_public_url(item)
            elif key == "cart_probe":
                result[key] = normalize_cart_probe(item)
            elif key == "available":
                if item is not None and not isinstance(item, bool):
                    raise ValueError("Hosted snapshot availability must be true, false, or unknown.")
                result[key] = item
            elif key == "quantity":
                if item is not None and (isinstance(item, bool) or not isinstance(item, int) or item < 0):
                    raise ValueError("Hosted snapshot quantity is invalid.")
                result[key] = item
            elif key in {"price", "compare_at_price"}:
                result[key] = cls._safe_decimal(item, name=key)
            elif key == "currency" and item is None:
                result[key] = None
            elif key in {"observed_at", "status_observed_at", "availability_observed_at", "quantity_observed_at", "price_observed_at"}:
                result[key] = cls._safe_timestamp(item, name=key, optional=True)
            elif key in text_limits:
                result[key] = cls._safe_text(item, limit=text_limits[key], name=key)
            else:
                result[key] = item
        if result.get("status") not in {None, "unknown", "announced", "in_stock", "sold_out", "preorder", "backorder", "waitlist"}:
            raise ValueError("Hosted snapshot contains an unsupported status.")
        if result.get("quantity_kind") not in {None, "unknown", "exact", "threshold", "availability"}:
            raise ValueError("Hosted snapshot contains an unsupported quantity kind.")
        currency = result.get("currency")
        if currency and not re.fullmatch(r"[A-Z]{3}", currency):
            raise ValueError("Hosted snapshot contains an invalid currency.")
        return result

    @classmethod
    def _safe_watch_state(cls, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict) or set(value) - {"variant_id", "observed_at", "comparison", "latest_observation"}:
            raise ValueError("Hosted snapshot contains an invalid watch state.")
        result = {
            "variant_id": cls._safe_text(value.get("variant_id", ""), limit=240, name="variant ID"),
            "observed_at": cls._safe_timestamp(value.get("observed_at", ""), name="observation time"),
        }
        if "comparison" in value:
            result["comparison"] = cls._safe_observation(value["comparison"], comparison=True)
        if "latest_observation" in value:
            result["latest_observation"] = cls._safe_observation(value["latest_observation"])
        return result

    @classmethod
    def _safe_event(cls, value: Any) -> dict[str, Any]:
        fields = {"dedup_key", "kind", "source_id", "product_id", "variant_id", "created_at", "title", "summary", "url", "details"}
        if not isinstance(value, dict) or set(value) - fields:
            raise ValueError("Hosted snapshot contains an invalid event.")
        dedup = cls._safe_text(value.get("dedup_key", ""), limit=64, name="event fingerprint")
        if not re.fullmatch(r"[0-9a-f]{64}", dedup):
            raise ValueError("Hosted snapshot contains an invalid event fingerprint.")
        details = value.get("details") or {}
        if not isinstance(details, dict) or set(details) - _HOSTED_EVENT_DETAIL_FIELDS:
            raise ValueError("Hosted snapshot event contains unsupported details.")
        safe_details = {}
        for key, item in details.items():
            if key == "image_url" and item:
                safe_details[key] = cls._safe_public_url(item)
            elif item is None or isinstance(item, (bool, int)):
                safe_details[key] = item
            elif isinstance(item, float):
                if not math.isfinite(item):
                    raise ValueError("Hosted snapshot event detail is invalid.")
                safe_details[key] = item
            elif isinstance(item, str):
                safe_details[key] = cls._safe_text(item, limit=1500, name="event detail")
            else:
                raise ValueError("Hosted snapshot event detail is invalid.")
        url = value.get("url", "")
        return {
            "dedup_key": dedup,
            "kind": cls._safe_text(value.get("kind", ""), limit=80, name="event kind"),
            "source_id": cls._safe_text(value.get("source_id", ""), limit=160, name="source ID"),
            "product_id": cls._safe_text(value.get("product_id", ""), limit=240, name="product ID"),
            "variant_id": cls._safe_text(value.get("variant_id", ""), limit=240, name="variant ID"),
            "created_at": cls._safe_timestamp(value.get("created_at", ""), name="event time"),
            "title": cls._safe_text(value.get("title", ""), limit=256, name="event title"),
            "summary": cls._safe_text(value.get("summary", ""), limit=4000, name="event summary"),
            "url": cls._safe_public_url(url) if url else "",
            "details": safe_details,
        }

    @staticmethod
    def _canonical_digest(value: Any) -> str:
        payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    def _ensure_observation_context(
        cls, observation: Any, *, context_id: str, market_context: Any = None,
    ) -> Any:
        if not isinstance(observation, dict) or observation.get("comparison_context") not in (None, ""):
            return observation
        value = dict(observation)
        market = value.get("market_context") or market_context
        if market not in (None, ""):
            value["market_context"] = market
            value["comparison_context"] = "market:" + cls._canonical_digest(market)
        elif context_id:
            value["comparison_context"] = "executor:" + context_id
        if context_id:
            value.setdefault("observer_context", context_id)
        return value

    @staticmethod
    def _safe_discord_mention(value: Any, *, name: str) -> str:
        value = str(value or "").strip()
        if value and not re.fullmatch(r"[0-9]{17,20}", value):
            raise ValueError(f"Hosted snapshot {name} is invalid.")
        return value

    @classmethod
    def _hosted_config_revision(cls, sources: list[dict[str, Any]], watches: list[dict[str, Any]], settings: dict[str, Any]) -> str:
        source_configs = [
            {"id": row["id"], "config": row["config"]}
            for row in sorted(sources, key=lambda item: item["id"])
        ]
        watch_configs = [row["config"] for row in sorted(watches, key=lambda item: int(item["config"]["id"]))]
        revision_source = {
            "sources": source_configs,
            "watches": watch_configs,
            "settings": {
                "notify_price_increases": bool(settings["notify_price_increases"]),
                "auto_discovery_alerts": bool(settings["auto_discovery_alerts"]),
                "mention_user_id": cls._safe_discord_mention(settings.get("mention_user_id"), name="user mention ID"),
                "mention_role_id": cls._safe_discord_mention(settings.get("mention_role_id"), name="role mention ID"),
            },
        }
        return cls._canonical_digest(revision_source)

    def _hosted_sources_and_watches(
        self, connection: sqlite3.Connection, *, context_id: str = "",
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
        source_rows = connection.execute("SELECT * FROM sources ORDER BY source_id").fetchall()
        sources: list[dict[str, Any]] = []
        eligible: set[str] = set()
        for row in source_rows:
            raw = self.json_load(row["source_json"], {})
            platform = str(raw.get("platform", "")).lower()
            if platform not in HOSTED_PROVIDER_PLATFORMS:
                continue
            config = {field: raw[field] for field in _HOSTED_SOURCE_FIELDS if field in raw}
            config["id"] = row["source_id"]
            config["platform"] = platform
            config["url"] = self._safe_public_url(config.get("url", ""))
            config["name"] = self._safe_text(str(config.get("name") or row["source_id"]), limit=200, name="source name")
            config["discovery_enabled"] = bool(config.get("discovery_enabled", True))
            for key, default in (("discovery_interval", 900), ("product_interval", 300)):
                value = config.get(key, default)
                if isinstance(value, bool) or not isinstance(value, int) or not 15 <= value <= 86400:
                    raise ValueError("Hosted source interval is invalid.")
                config[key] = value
            for key in ("include_keywords", "exclude_keywords"):
                items = config.get(key, [])
                if not isinstance(items, list) or len(items) > 200:
                    raise ValueError("Hosted source keyword list is invalid.")
                config[key] = [self._safe_text(item, limit=120, name="source keyword") for item in items]
            if "currency_hint" in config:
                currency_hint = str(config["currency_hint"] or "").upper()
                if not re.fullmatch(r"[A-Z]{3}", currency_hint):
                    raise ValueError("Hosted source currency hint is invalid.")
                config["currency_hint"] = currency_hint
            if "market_context" in config:
                config["market_context"] = self._safe_market_context(config["market_context"])
            sources.append({
                "id": row["source_id"], "config": config,
                "local_enabled": bool(raw.get("enabled", True)),
                "baseline_complete": bool(row["baseline_complete"]),
                "last_discovery_at": row["last_discovery_at"],
                "next_discovery_at": row["next_discovery_at"],
                "discovery_failures": int(row["discovery_failures"] or 0),
                "discovery_status": row["discovery_status"],
                "discovery_last_success_at": row["discovery_last_success_at"],
            })
            eligible.add(row["source_id"])

        watches: list[dict[str, Any]] = []
        source_markets = {row["id"]: row["config"].get("market_context") for row in sources}
        for row in connection.execute("SELECT * FROM watches ORDER BY id").fetchall():
            if row["source_id"] not in eligible:
                continue
            config = {
                "id": int(row["id"]), "source_id": row["source_id"],
                "product_id": self._safe_text(row["product_id"] or "", limit=240, name="product ID"),
                "product_url": self._safe_public_url(row["product_url"]),
                "variant_id": self._safe_text(row["variant_id"] or "", limit=240, name="variant ID"),
                "label": self._safe_text(row["label"] or "", limit=240, name="watch label"),
                "cart_probe_enabled": bool(row["cart_probe_enabled"]),
                "created_at": self._safe_text(row["created_at"], limit=80, name="tracking start time"),
            }
            check = connection.execute(
                "SELECT last_success_at,next_due_at,failures FROM checks WHERE source_id=? AND product_url=? AND variant_id=?",
                (row["source_id"], row["product_url"], row["variant_id"]),
            ).fetchone()
            cart_checks = [
                {"variant_id": c["variant_id"], "last_attempt_at": c["last_attempt_at"],
                 "next_due_at": c["next_due_at"], "last_success_at": c["last_success_at"], "failures": int(c["failures"] or 0)}
                for c in connection.execute(
                    "SELECT * FROM cart_probe_checks WHERE watch_id=? ORDER BY variant_id", (row["id"],)
                ).fetchall()
            ]
            states = []
            for state in connection.execute(
                "SELECT variant_id,observation_json,updated_at FROM watch_states WHERE watch_id=? ORDER BY variant_id",
                (row["id"],),
            ).fetchall():
                observation = self.json_load(state["observation_json"], {})
                state_value = self._safe_watch_state(observation)
                for observation_key in ("comparison", "latest_observation"):
                    if observation_key in state_value:
                        state_value[observation_key] = self._ensure_observation_context(
                            state_value[observation_key], context_id=context_id,
                            market_context=source_markets.get(row["source_id"]),
                        )
                state_value["updated_at"] = state["updated_at"]
                states.append(state_value)
            watches.append({
                "config": config, "baseline_complete": bool(row["baseline_complete"]),
                "check": ({"last_success_at": check["last_success_at"], "next_due_at": check["next_due_at"], "failures": int(check["failures"] or 0)} if check else None),
                "cart_checks": cart_checks, "states": states,
            })
        settings_row = connection.execute(
            "SELECT notify_price_increases,auto_discovery_alerts,mention_user_id,mention_role_id FROM app_settings WHERE id=1"
        ).fetchone()
        settings = {
            "notify_price_increases": bool(settings_row["notify_price_increases"]),
            "auto_discovery_alerts": bool(settings_row["auto_discovery_alerts"]),
            "mention_user_id": settings_row["mention_user_id"] or "",
            "mention_role_id": settings_row["mention_role_id"] or "",
        }
        return sources, watches, settings

    def export_hosted_snapshot(self, *, context_id: str = "") -> dict[str, Any]:
        """Return bounded compressed JSON containing only hosted-eligible public state."""
        context_id = self._safe_text(context_id, limit=120, name="execution context")
        with self.connect() as connection:
            connection.execute("BEGIN")
            sources, watches, settings = self._hosted_sources_and_watches(connection, context_id=context_id)
            source_ids = {row["id"] for row in sources}
            source_markets = {row["id"]: row["config"].get("market_context") for row in sources}
            watch_configs = [row["config"] for row in watches]
            config_revision = self._hosted_config_revision(sources, watches, settings)

            products = []
            product_ids = []
            variants = []
            catalog_latest = []
            if source_ids:
                marks = ",".join("?" for _ in source_ids)
                params = tuple(sorted(source_ids))
                referenced_product_keys = {
                    (watch["source_id"], watch["product_id"])
                    for watch in watch_configs if watch.get("product_id")
                }
                referenced_variant_keys = {
                    (watch["source_id"], watch["variant_id"])
                    for watch in watch_configs if watch.get("variant_id")
                }
                for row in connection.execute(
                    f"""SELECT e.source_id,e.product_id,e.variant_id FROM outbox o
                        JOIN events e ON e.id=o.event_id
                        WHERE o.kind='alert' AND o.status IN ('pending','retry','sending','uncertain')
                          AND e.source_id IN ({marks})""", params,
                ):
                    if row["product_id"]:
                        referenced_product_keys.add((row["source_id"], row["product_id"]))
                    if row["variant_id"]:
                        referenced_variant_keys.add((row["source_id"], row["variant_id"]))
                seen_product_keys = set(referenced_product_keys)
                for row in connection.execute(
                    f"SELECT source_id,product_id FROM products WHERE source_id IN ({marks}) ORDER BY source_id,product_id", params,
                ):
                    seen_product_keys.add((row["source_id"], row["product_id"]))
                product_ids = [
                    {"source_id": source_id, "product_id": product_id}
                    for source_id, product_id in sorted(seen_product_keys)
                ]
                for row in connection.execute(f"SELECT * FROM products WHERE source_id IN ({marks}) ORDER BY source_id,product_id", params):
                    if (row["source_id"], row["product_id"]) not in referenced_product_keys:
                        continue
                    products.append({
                        "source_id": row["source_id"], "product_id": row["product_id"],
                        "title": row["title"], "url": self._safe_public_url(row["url"]),
                        "image_url": self._safe_public_url(row["image_url"]) if row["image_url"] else "",
                        "first_seen_at": row["first_seen_at"], "last_seen_at": row["last_seen_at"],
                    })
                for row in connection.execute(f"SELECT * FROM product_variants WHERE source_id IN ({marks}) ORDER BY source_id,product_id,variant_id", params):
                    if (
                        (row["source_id"], row["product_id"]) not in referenced_product_keys
                        and (row["source_id"], row["variant_id"]) not in referenced_variant_keys
                    ):
                        continue
                    variants.append({key: row[key] for key in ("source_id", "product_id", "variant_id", "variant_title", "first_seen_at", "last_seen_at")})
                for row in connection.execute(f"SELECT * FROM catalog_latest WHERE source_id IN ({marks}) ORDER BY source_id,product_id,variant_id", params):
                    if (
                        (row["source_id"], row["product_id"]) not in referenced_product_keys
                        and (row["source_id"], row["variant_id"]) not in referenced_variant_keys
                    ):
                        continue
                    latest_payload = self._safe_observation(self.json_load(row["payload_json"], {}))
                    latest_payload = self._ensure_observation_context(
                        latest_payload, context_id=context_id, market_context=source_markets.get(row["source_id"]),
                    )
                    catalog_latest.append({
                        "source_id": row["source_id"], "product_id": row["product_id"], "variant_id": row["variant_id"],
                        "observed_at": row["observed_at"], "payload": latest_payload,
                    })

            observation_groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
            for watch in watch_configs:
                sql = "SELECT * FROM observations WHERE source_id=? AND observed_at>=?"
                args: list[Any] = [watch["source_id"], watch["created_at"]]
                if watch["product_id"]:
                    sql += " AND product_id=?"
                    args.append(watch["product_id"])
                if watch["variant_id"]:
                    sql += " AND variant_id=?"
                    args.append(watch["variant_id"])
                sql += " ORDER BY observed_at DESC,id DESC"
                for row in connection.execute(sql, tuple(args)):
                    payload = self._safe_observation(self.json_load(row["payload_json"], {}))
                    payload = self._ensure_observation_context(
                        payload, context_id=context_id, market_context=source_markets.get(row["source_id"]),
                    )
                    context_key = json.dumps(payload.get("comparison_context"), sort_keys=True, separators=(",", ":"))
                    group_key = (
                        int(watch["id"]), row["source_id"], row["product_id"], row["variant_id"],
                        context_key, row["currency"],
                    )
                    observation_groups.setdefault(group_key, []).append({
                        "_row_id": int(row["id"]),
                        "source_id": row["source_id"], "product_id": row["product_id"], "variant_id": row["variant_id"],
                        "observed_at": row["observed_at"], "price": row["price"], "currency": row["currency"],
                        "status": row["status"], "available": None if row["available"] is None else bool(row["available"]), "quantity": row["quantity"],
                        "quantity_kind": row["quantity_kind"], "payload": payload,
                    })

            selected_observations: dict[int, dict[str, Any]] = {}
            for rows in observation_groups.values():
                recent = rows[:HOSTED_SNAPSHOT_RECENT_OBSERVATIONS_PER_GROUP]
                for row in recent:
                    selected_observations[row["_row_id"]] = row
                priced = [row for row in rows if row["price"] is not None]
                if priced:
                    low = min(Decimal(str(row["price"])) for row in priced)
                    low_row = min(
                        (row for row in priced if Decimal(str(row["price"])) == low),
                        key=lambda row: (row["observed_at"], row["_row_id"]),
                    )
                    selected_observations[low_row["_row_id"]] = low_row
            observations = [
                {key: value for key, value in row.items() if key != "_row_id"}
                for row in sorted(
                    selected_observations.values(),
                    key=lambda item: (item["source_id"], item["product_id"], item["variant_id"], item["observed_at"], item["currency"] or ""),
                )
            ]

            events_by_key: dict[str, dict[str, Any]] = {}
            outbox = []
            if source_ids:
                marks = ",".join("?" for _ in source_ids)
                params = tuple(sorted(source_ids))
                recent_events = connection.execute(
                    f"SELECT * FROM events WHERE source_id IN ({marks}) AND kind!='test_alert' ORDER BY id DESC LIMIT ?",
                    (*params, HOSTED_SNAPSHOT_RECENT_EVENTS),
                ).fetchall()
                for row in recent_events:
                    events_by_key[row["dedup_key"]] = self._safe_event({
                        "dedup_key": row["dedup_key"], "kind": row["kind"], "source_id": row["source_id"],
                        "product_id": row["product_id"], "variant_id": row["variant_id"], "created_at": row["created_at"],
                        "title": row["title"], "summary": row["summary"], "url": row["url"],
                        "details": self.json_load(row["details_json"], {}),
                    })
                outbox_rows = connection.execute(
                    f"""SELECT o.*,e.dedup_key AS e_dedup_key,e.kind AS e_kind,e.source_id AS e_source_id,
                              e.product_id AS e_product_id,e.variant_id AS e_variant_id,e.created_at AS e_created_at,
                              e.title AS e_title,e.summary AS e_summary,e.url AS e_url,e.details_json AS e_details_json
                        FROM outbox o
                        JOIN events e ON e.id=o.event_id
                        WHERE o.kind='alert' AND e.source_id IN ({marks})
                          AND o.status IN ('pending','retry','sending','uncertain')
                        ORDER BY o.created_at,o.id""", params
                ).fetchall()
                outbox_rows.extend(connection.execute(
                    f"""SELECT o.*,e.dedup_key AS e_dedup_key,e.kind AS e_kind,e.source_id AS e_source_id,
                              e.product_id AS e_product_id,e.variant_id AS e_variant_id,e.created_at AS e_created_at,
                              e.title AS e_title,e.summary AS e_summary,e.url AS e_url,e.details_json AS e_details_json
                        FROM outbox o
                        JOIN events e ON e.id=o.event_id
                        WHERE o.kind='alert' AND e.source_id IN ({marks}) AND o.status='sent'
                        ORDER BY COALESCE(o.delivered_at,o.created_at) DESC,o.id DESC LIMIT ?""",
                    (*params, HOSTED_SNAPSHOT_RECENT_SENT_OUTBOX),
                ).fetchall())
                for row in outbox_rows:
                    if row["e_dedup_key"] not in events_by_key:
                        events_by_key[row["e_dedup_key"]] = self._safe_event({
                            "dedup_key": row["e_dedup_key"], "kind": row["e_kind"], "source_id": row["e_source_id"],
                            "product_id": row["e_product_id"], "variant_id": row["e_variant_id"], "created_at": row["e_created_at"],
                            "title": row["e_title"], "summary": row["e_summary"], "url": row["e_url"],
                            "details": self.json_load(row["e_details_json"], {}),
                        })
                    payload = self._safe_event(self.json_load(row["payload_json"], {}))
                    status = "uncertain" if row["status"] == "sending" else row["status"]
                    if status not in _OUTBOX_STATUSES:
                        status = "uncertain"
                    outbox.append({
                        "id": self._safe_text(row["id"], limit=80, name="outbox ID"),
                        "event_dedup_key": row["e_dedup_key"], "status": status,
                        "attempts": int(row["attempts"] or 0), "next_attempt_at": row["next_attempt_at"],
                        "created_at": row["created_at"], "delivered_at": row["delivered_at"], "payload": payload,
                    })
            events = [events_by_key[key] for key in sorted(events_by_key)]

        payload = {
            "schema_version": HOSTED_SNAPSHOT_SCHEMA_VERSION, "config_revision": config_revision,
            "context_id": self._safe_text(context_id, limit=120, name="execution context"),
            "settings": settings, "sources": sources, "watches": watches,
            "catalog": {"product_ids": product_ids, "products": products, "product_variants": variants, "latest": catalog_latest},
            "observations": observations, "events": events, "outbox": outbox,
        }
        collections = {
            "sources": sources, "watches": watches, "product_ids": product_ids, "products": products,
            "product_variants": variants, "catalog_latest": catalog_latest,
            "observations": observations, "events": events, "outbox": outbox,
        }
        for name, limit in HOSTED_SNAPSHOT_ROW_LIMITS.items():
            if len(collections[name]) > limit:
                raise ValueError(f"Hosted snapshot exceeds the {name} row limit.")
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(raw) > HOSTED_SNAPSHOT_MAX_UNCOMPRESSED_BYTES:
            raise ValueError("Hosted snapshot exceeds the uncompressed size limit.")
        compressed = gzip.compress(raw, compresslevel=9, mtime=0)
        if len(compressed) > HOSTED_SNAPSHOT_MAX_COMPRESSED_BYTES:
            raise ValueError("Hosted snapshot exceeds the compressed size limit.")
        return {
            "schema_version": HOSTED_SNAPSHOT_SCHEMA_VERSION,
            "config_revision": config_revision,
            "context_id": payload["context_id"],
            "candidate_source_ids": sorted(row["id"] for row in sources),
            "encoding": "gzip+base64",
            "compressed_bytes": len(compressed),
            "uncompressed_bytes": len(raw),
            "payload_sha256": hashlib.sha256(raw).hexdigest(),
            "payload_b64": base64.b64encode(compressed).decode("ascii"),
        }

    @classmethod
    def _decode_hosted_snapshot(cls, snapshot: Any) -> dict[str, Any]:
        envelope_fields = {"schema_version", "config_revision", "context_id", "candidate_source_ids", "encoding", "compressed_bytes", "uncompressed_bytes", "payload_sha256", "payload_b64"}
        if not isinstance(snapshot, dict) or set(snapshot) != envelope_fields:
            raise ValueError("Hosted snapshot envelope is invalid.")
        if snapshot["schema_version"] != HOSTED_SNAPSHOT_SCHEMA_VERSION or snapshot["encoding"] != "gzip+base64":
            raise ValueError("Hosted snapshot version or encoding is unsupported.")
        if not re.fullmatch(r"[0-9a-f]{64}", str(snapshot["config_revision"])) or not re.fullmatch(r"[0-9a-f]{64}", str(snapshot["payload_sha256"])):
            raise ValueError("Hosted snapshot digest metadata is invalid.")
        candidates = snapshot["candidate_source_ids"]
        if not isinstance(candidates, list) or len(candidates) > HOSTED_SNAPSHOT_ROW_LIMITS["sources"] or any(not isinstance(item, str) for item in candidates) or candidates != sorted(set(candidates)):
            raise ValueError("Hosted snapshot candidate source list is invalid.")
        cls._safe_text(snapshot["context_id"], limit=120, name="execution context")
        compressed_size, raw_size = snapshot["compressed_bytes"], snapshot["uncompressed_bytes"]
        if any(isinstance(v, bool) or not isinstance(v, int) or v < 0 for v in (compressed_size, raw_size)):
            raise ValueError("Hosted snapshot size metadata is invalid.")
        if compressed_size > HOSTED_SNAPSHOT_MAX_COMPRESSED_BYTES or raw_size > HOSTED_SNAPSHOT_MAX_UNCOMPRESSED_BYTES:
            raise ValueError("Hosted snapshot exceeds the size limit.")
        payload_b64 = snapshot["payload_b64"]
        if not isinstance(payload_b64, str) or len(payload_b64) > ((HOSTED_SNAPSHOT_MAX_COMPRESSED_BYTES + 2) // 3) * 4:
            raise ValueError("Hosted snapshot compressed payload is too large.")
        try:
            compressed = base64.b64decode(payload_b64, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise ValueError("Hosted snapshot encoding is invalid.") from exc
        if len(compressed) != compressed_size:
            raise ValueError("Hosted snapshot compressed size does not match.")
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode="rb") as stream:
                raw = stream.read(HOSTED_SNAPSHOT_MAX_UNCOMPRESSED_BYTES + 1)
        except (OSError, EOFError) as exc:
            raise ValueError("Hosted snapshot compression is invalid.") from exc
        if len(raw) != raw_size or len(raw) > HOSTED_SNAPSHOT_MAX_UNCOMPRESSED_BYTES:
            raise ValueError("Hosted snapshot uncompressed size does not match.")
        digest = hashlib.sha256(raw).hexdigest()
        if not hmac.compare_digest(str(snapshot["payload_sha256"]), digest):
            raise ValueError("Hosted snapshot checksum does not match.")
        try:
            payload = json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("Hosted snapshot JSON is invalid.") from exc
        if not isinstance(payload, dict) or payload.get("schema_version") != HOSTED_SNAPSHOT_SCHEMA_VERSION:
            raise ValueError("Hosted snapshot payload version is unsupported.")
        if not hmac.compare_digest(str(payload.get("config_revision", "")), str(snapshot["config_revision"])):
            raise ValueError("Hosted snapshot configuration digest does not match its envelope.")
        if payload.get("context_id") != snapshot["context_id"]:
            raise ValueError("Hosted snapshot execution context does not match its envelope.")
        if snapshot["candidate_source_ids"] != sorted(row.get("id") for row in payload.get("sources", []) if isinstance(row, dict)):
            raise ValueError("Hosted snapshot candidate source IDs do not match its payload.")
        return payload

    def _validate_hosted_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        required = {"schema_version", "config_revision", "context_id", "settings", "sources", "watches", "catalog", "observations", "events", "outbox"}
        if set(payload) != required or not re.fullmatch(r"[0-9a-f]{64}", str(payload.get("config_revision", ""))):
            raise ValueError("Hosted snapshot payload fields are invalid.")
        clean = json.loads(json.dumps(payload, ensure_ascii=False))
        clean["context_id"] = self._safe_text(clean["context_id"], limit=120, name="execution context")
        setting_fields = {"notify_price_increases", "auto_discovery_alerts", "mention_user_id", "mention_role_id"}
        if not isinstance(clean["settings"], dict) or set(clean["settings"]) != setting_fields:
            raise ValueError("Hosted snapshot preferences are invalid.")
        for key in ("notify_price_increases", "auto_discovery_alerts"):
            if not isinstance(clean["settings"][key], bool):
                raise ValueError("Hosted snapshot preferences are invalid.")
        for key in ("mention_user_id", "mention_role_id"):
            clean["settings"][key] = self._safe_discord_mention(clean["settings"][key], name=key)
        if not isinstance(clean["sources"], list) or not isinstance(clean["watches"], list):
            raise ValueError("Hosted snapshot source/watch lists are invalid.")
        source_ids: set[str] = set()
        allowed_config = set(_HOSTED_SOURCE_FIELDS)
        for row in clean["sources"]:
            if not isinstance(row, dict) or set(row) != {"id", "config", "local_enabled", "baseline_complete", "last_discovery_at", "next_discovery_at", "discovery_failures", "discovery_status", "discovery_last_success_at"}:
                raise ValueError("Hosted snapshot source record is invalid.")
            sid = self._safe_text(row["id"], limit=160, name="source ID")
            if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", sid):
                raise ValueError("Hosted snapshot source ID is invalid.")
            config = row["config"]
            required_config = {"id", "name", "platform", "url", "discovery_enabled", "discovery_interval", "product_interval", "include_keywords", "exclude_keywords"}
            if not isinstance(config, dict) or set(config) - allowed_config or not required_config <= set(config) or config.get("id") != sid:
                raise ValueError("Hosted snapshot source configuration is invalid.")
            platform = str(config.get("platform", "")).lower()
            if platform not in HOSTED_PROVIDER_PLATFORMS or sid in source_ids:
                raise ValueError("Hosted snapshot contains an ineligible or duplicate source.")
            source_ids.add(sid)
            config["platform"] = platform
            config["url"] = self._safe_public_url(config["url"])
            config["name"] = self._safe_text(config["name"], limit=200, name="source name")
            if not isinstance(config["discovery_enabled"], bool):
                raise ValueError("Hosted source discovery setting is invalid.")
            for key in ("discovery_interval", "product_interval"):
                value = config[key]
                if isinstance(value, bool) or not isinstance(value, int) or not 15 <= value <= 86400:
                    raise ValueError("Hosted source interval is invalid.")
            for key in ("include_keywords", "exclude_keywords"):
                if not isinstance(config[key], list) or len(config[key]) > 200:
                    raise ValueError("Hosted source keyword list is invalid.")
                config[key] = [self._safe_text(item, limit=120, name="source keyword") for item in config[key]]
            if "currency_hint" in config and not re.fullmatch(r"[A-Z]{3}", str(config["currency_hint"])):
                raise ValueError("Hosted source currency hint is invalid.")
            if "market_context" in config:
                config["market_context"] = self._safe_market_context(config["market_context"])
            if not isinstance(row["local_enabled"], bool) or not isinstance(row["baseline_complete"], bool):
                raise ValueError("Hosted snapshot source state is invalid.")
            row["discovery_failures"] = self._safe_count(row["discovery_failures"], name="discovery failure count")
            if row["discovery_status"] not in {"waiting", "disabled", "healthy", "error"}:
                raise ValueError("Hosted snapshot discovery state is invalid.")
            for key in ("last_discovery_at", "next_discovery_at", "discovery_last_success_at"):
                row[key] = self._safe_timestamp(row[key], name=key, optional=True)
        watch_ids: set[int] = set()
        watch_configs: list[dict[str, Any]] = []
        for row in clean["watches"]:
            if not isinstance(row, dict) or set(row) != {"config", "baseline_complete", "check", "cart_checks", "states"}:
                raise ValueError("Hosted snapshot watch record is invalid.")
            config = row["config"]
            if not isinstance(config, dict) or set(config) != set(_HOSTED_WATCH_FIELDS):
                raise ValueError("Hosted snapshot watch configuration is invalid.")
            if isinstance(config["id"], bool) or not isinstance(config["id"], int):
                raise ValueError("Hosted snapshot watch ID is invalid.")
            if config["id"] < 1 or config["id"] in watch_ids or config["source_id"] not in source_ids:
                raise ValueError("Hosted snapshot contains an invalid or duplicate watch ID.")
            watch_ids.add(config["id"])
            config["source_id"] = self._safe_text(config["source_id"], limit=160, name="watch source ID")
            config["product_url"] = self._safe_public_url(config["product_url"])
            for key, limit in (("product_id", 240), ("variant_id", 240), ("label", 240)):
                self._safe_text(config[key], limit=limit, name=key)
            config["created_at"] = self._safe_timestamp(config["created_at"], name="watch tracking start")
            if not isinstance(config["cart_probe_enabled"], bool) or not isinstance(row["baseline_complete"], bool):
                raise ValueError("Hosted snapshot watch state is invalid.")
            if row["check"] is not None:
                if not isinstance(row["check"], dict) or set(row["check"]) != {"last_success_at", "next_due_at", "failures"}:
                    raise ValueError("Hosted snapshot watch schedule is invalid.")
                row["check"]["last_success_at"] = self._safe_timestamp(row["check"]["last_success_at"], name="watch last success", optional=True)
                row["check"]["next_due_at"] = self._safe_timestamp(row["check"]["next_due_at"], name="watch next due", optional=True)
                row["check"]["failures"] = self._safe_count(row["check"]["failures"], name="watch failure count")
            if not isinstance(row["cart_checks"], list) or len(row["cart_checks"]) > 25000 or not isinstance(row["states"], list) or len(row["states"]) > 25000:
                raise ValueError("Hosted snapshot watch evidence is invalid.")
            seen_cart_variants: set[str] = set()
            for cart in row["cart_checks"]:
                if not isinstance(cart, dict) or set(cart) != {"variant_id", "last_attempt_at", "next_due_at", "last_success_at", "failures"}:
                    raise ValueError("Hosted snapshot cart schedule is invalid.")
                cart["variant_id"] = self._safe_text(cart["variant_id"], limit=240, name="cart variant ID")
                if cart["variant_id"] in seen_cart_variants:
                    raise ValueError("Hosted snapshot cart schedule has duplicate variants.")
                seen_cart_variants.add(cart["variant_id"])
                for key in ("last_attempt_at", "next_due_at", "last_success_at"):
                    cart[key] = self._safe_timestamp(cart[key], name=key, optional=True)
                cart["failures"] = self._safe_count(cart["failures"], name="cart failure count")
            safe_states = []
            state_variants: set[str] = set()
            for state in row["states"]:
                if not isinstance(state, dict) or set(state) - {"variant_id", "observed_at", "comparison", "latest_observation", "updated_at"}:
                    raise ValueError("Hosted snapshot watch state is invalid.")
                safe_state = self._safe_watch_state({k: v for k, v in state.items() if k != "updated_at"})
                safe_state["updated_at"] = self._safe_timestamp(state.get("updated_at", safe_state["observed_at"]), name="watch state update")
                if safe_state["variant_id"] in state_variants:
                    raise ValueError("Hosted snapshot watch state has duplicate variants.")
                state_variants.add(safe_state["variant_id"])
                safe_states.append(safe_state)
            row["states"] = safe_states
            watch_configs.append(config)

        catalog = clean["catalog"]
        if not isinstance(catalog, dict) or set(catalog) != {"product_ids", "products", "product_variants", "latest"}:
            raise ValueError("Hosted snapshot catalog is invalid.")
        for key in ("product_ids", "products", "product_variants", "latest", "observations", "events", "outbox"):
            rows = catalog[key] if key in catalog else clean[key]
            if not isinstance(rows, list):
                raise ValueError(f"Hosted snapshot {key} collection is invalid.")
            limit_key = {"latest": "catalog_latest"}.get(key, key)
            limit = HOSTED_SNAPSHOT_ROW_LIMITS.get(limit_key, HOSTED_SNAPSHOT_ROW_LIMITS.get(key, 50_000))
            if len(rows) > limit:
                raise ValueError(f"Hosted snapshot {key} collection exceeds its row limit.")
        product_id_keys: set[tuple[str, str]] = set()
        for row in clean["catalog"]["product_ids"]:
            if not isinstance(row, dict) or set(row) != {"source_id", "product_id"}:
                raise ValueError("Hosted snapshot catalog product ID is invalid.")
            row["source_id"] = self._safe_text(row["source_id"], limit=160, name="product source ID")
            if row["source_id"] not in source_ids:
                raise ValueError("Hosted snapshot product ID source is ineligible.")
            row["product_id"] = self._safe_text(row["product_id"], limit=240, name="product ID")
            key = (row["source_id"], row["product_id"])
            if key in product_id_keys:
                raise ValueError("Hosted snapshot contains duplicate catalog product IDs.")
            product_id_keys.add(key)
        for row in clean["catalog"]["products"]:
            if not isinstance(row, dict) or set(row) != {"source_id", "product_id", "title", "url", "image_url", "first_seen_at", "last_seen_at"}:
                raise ValueError("Hosted snapshot product row is invalid.")
            row["source_id"] = self._safe_text(row["source_id"], limit=160, name="product source ID")
            if row["source_id"] not in source_ids:
                raise ValueError("Hosted snapshot product source is ineligible.")
            for key, limit in (("product_id", 240), ("title", 300)):
                row[key] = self._safe_text(row[key], limit=limit, name=key)
            row["url"] = self._safe_public_url(row["url"])
            row["image_url"] = self._safe_public_url(row["image_url"]) if row["image_url"] else ""
            row["first_seen_at"] = self._safe_timestamp(row["first_seen_at"], name="product first seen")
            row["last_seen_at"] = self._safe_timestamp(row["last_seen_at"], name="product last seen")
            if (row["source_id"], row["product_id"]) not in product_id_keys:
                raise ValueError("Hosted snapshot product metadata has no stable catalog ID.")
        for row in clean["catalog"]["product_variants"]:
            if not isinstance(row, dict) or set(row) != {"source_id", "product_id", "variant_id", "variant_title", "first_seen_at", "last_seen_at"}:
                raise ValueError("Hosted snapshot product variant row is invalid.")
            row["source_id"] = self._safe_text(row["source_id"], limit=160, name="variant source ID")
            if row["source_id"] not in source_ids:
                raise ValueError("Hosted snapshot variant source is ineligible.")
            for key, limit in (("product_id", 240), ("variant_id", 240), ("variant_title", 240)):
                row[key] = self._safe_text(row[key], limit=limit, name=key)
            row["first_seen_at"] = self._safe_timestamp(row["first_seen_at"], name="variant first seen")
            row["last_seen_at"] = self._safe_timestamp(row["last_seen_at"], name="variant last seen")
            if (row["source_id"], row["product_id"]) not in product_id_keys:
                raise ValueError("Hosted snapshot variant has no stable catalog product ID.")
        for row in clean["catalog"]["latest"]:
            if not isinstance(row, dict) or set(row) != {"source_id", "product_id", "variant_id", "observed_at", "payload"}:
                raise ValueError("Hosted snapshot catalog observation is invalid.")
            row["source_id"] = self._safe_text(row["source_id"], limit=160, name="catalog source ID")
            if row["source_id"] not in source_ids:
                raise ValueError("Hosted snapshot catalog source is ineligible.")
            row["product_id"] = self._safe_text(row["product_id"], limit=240, name="catalog product ID")
            row["variant_id"] = self._safe_text(row["variant_id"], limit=240, name="catalog variant ID")
            row["observed_at"] = self._safe_timestamp(row["observed_at"], name="catalog observation time")
            row["payload"] = self._safe_observation(row["payload"])
            if row["payload"].get("product_id") != row["product_id"] or row["payload"].get("variant_id") != row["variant_id"]:
                raise ValueError("Hosted snapshot catalog observation identity is inconsistent.")
            if (row["source_id"], row["product_id"]) not in product_id_keys:
                raise ValueError("Hosted snapshot catalog observation has no stable product ID.")
        for row in clean["observations"]:
            if not isinstance(row, dict) or set(row) != {"source_id", "product_id", "variant_id", "observed_at", "price", "currency", "status", "available", "quantity", "quantity_kind", "payload"}:
                raise ValueError("Hosted snapshot price/stock observation is invalid.")
            row["source_id"] = self._safe_text(row["source_id"], limit=160, name="observation source ID")
            if row["source_id"] not in source_ids:
                raise ValueError("Hosted snapshot observation source is ineligible.")
            row["product_id"] = self._safe_text(row["product_id"], limit=240, name="observation product ID")
            row["variant_id"] = self._safe_text(row["variant_id"], limit=240, name="observation variant ID")
            row["observed_at"] = self._safe_timestamp(row["observed_at"], name="observation time")
            row["price"] = self._safe_decimal(row["price"], name="price")
            if row["currency"] not in (None, ""):
                row["currency"] = self._safe_text(row["currency"], limit=3, name="currency").upper()
                if not re.fullmatch(r"[A-Z]{3}", row["currency"]):
                    raise ValueError("Hosted snapshot currency is invalid.")
            else:
                row["currency"] = None
            row["status"] = self._safe_text(row["status"], limit=40, name="availability status")
            if row["status"] not in {"unknown", "announced", "preorder", "in_stock", "sold_out", "backorder", "waitlist"}:
                raise ValueError("Hosted snapshot availability status is invalid.")
            if row["available"] is not None and not isinstance(row["available"], bool):
                raise ValueError("Hosted snapshot availability is invalid.")
            if row["quantity"] is not None:
                row["quantity"] = self._safe_count(row["quantity"], name="observation quantity")
            row["quantity_kind"] = self._safe_text(row["quantity_kind"], limit=20, name="quantity kind")
            if row["quantity_kind"] not in {"unknown", "exact", "threshold", "availability"}:
                raise ValueError("Hosted snapshot quantity kind is invalid.")
            row["payload"] = self._safe_observation(row["payload"])
            if row["payload"].get("product_id") != row["product_id"] or row["payload"].get("variant_id") != row["variant_id"] or row["payload"].get("observed_at") != row["observed_at"]:
                raise ValueError("Hosted snapshot observation identity is inconsistent.")
        clean["events"] = [self._safe_event(row) for row in clean["events"]]
        event_keys = {row["dedup_key"] for row in clean["events"]}
        for row in clean["events"]:
            if row["source_id"] not in source_ids:
                raise ValueError("Hosted snapshot event source is invalid.")
        for row in clean["outbox"]:
            fields = {"id", "event_dedup_key", "status", "attempts", "next_attempt_at", "created_at", "delivered_at", "payload"}
            if not isinstance(row, dict) or set(row) != fields or row["event_dedup_key"] not in event_keys:
                raise ValueError("Hosted snapshot outbox row is invalid.")
            self._safe_text(row["id"], limit=80, name="outbox ID")
            if row["status"] not in _OUTBOX_STATUSES or row["status"] == "sending":
                raise ValueError("Hosted snapshot outbox status is invalid.")
            row["payload"] = self._safe_event(row["payload"])
            if row["payload"]["dedup_key"] != row["event_dedup_key"]:
                raise ValueError("Hosted snapshot outbox payload does not match its event.")
        expected_revision = self._hosted_config_revision(clean["sources"], [{"config": item} for item in watch_configs], clean["settings"])
        if not hmac.compare_digest(expected_revision, str(clean["config_revision"])):
            raise ValueError("Hosted snapshot configuration digest is invalid.")
        return clean

    @staticmethod
    def _merge_outbox_status(current: str, incoming: str) -> str:
        priority = {"pending": 0, "retry": 1, "failed": 2, "uncertain": 3, "sending": 3, "sent": 4}
        if incoming == "sending":
            incoming = "uncertain"
        return current if priority.get(current, 0) >= priority.get(incoming, 0) else incoming

    def import_hosted_snapshot(
        self, snapshot: dict[str, Any], *, expected_config_revision: str, hosted: bool = False,
        ownership_check: Any = None,
    ) -> dict[str, Any]:
        """Transactionally merge an allowlisted hosted checkpoint after a config CAS."""
        payload = self._validate_hosted_payload(self._decode_hosted_snapshot(snapshot))
        source_markets = {row["id"]: row["config"].get("market_context") for row in payload["sources"]}
        remote_context_id = payload["context_id"]
        for row in payload["catalog"]["latest"]:
            row["payload"] = self._ensure_observation_context(
                row["payload"], context_id=remote_context_id,
                market_context=source_markets.get(row["source_id"]),
            )
        for row in payload["observations"]:
            row["payload"] = self._ensure_observation_context(
                row["payload"], context_id=remote_context_id,
                market_context=source_markets.get(row["source_id"]),
            )
        for watch in payload["watches"]:
            source_market = source_markets.get(watch["config"]["source_id"])
            for state in watch["states"]:
                for observation_key in ("comparison", "latest_observation"):
                    if observation_key in state:
                        state[observation_key] = self._ensure_observation_context(
                            state[observation_key], context_id=remote_context_id,
                            market_context=source_market,
                        )
        revision = payload["config_revision"]
        if not isinstance(expected_config_revision, str) or not hmac.compare_digest(revision, expected_config_revision):
            return {"status": "sync_needed", "reason": "expected_revision_mismatch", "config_revision": revision}
        allowed = lambda phase: ownership_check is None or bool(ownership_check(phase))
        if not allowed("import_before_write"):
            return {"status": "ownership_lost", "config_revision": revision}
        class _OwnershipLost(Exception):
            pass
        imported_counts = {"products": len(payload["catalog"]["products"]), "variants": len(payload["catalog"]["product_variants"]), "observations": len(payload["observations"]), "events": len(payload["events"]), "outbox": len(payload["outbox"])}
        try:
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                current_sources, current_watches, current_settings = self._hosted_sources_and_watches(db)
                current_revision = self._hosted_config_revision(current_sources, current_watches, current_settings)
                if current_revision != revision:
                    if not hosted:
                        return {"status": "sync_needed", "reason": "local_config_changed", "config_revision": current_revision}
                    has_data = any(db.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone() for table in ("watches", "products", "product_variants", "observations", "events", "outbox"))
                    if has_data:
                        return {"status": "sync_needed", "reason": "hosted_database_not_empty", "config_revision": current_revision}
                    db.execute("DELETE FROM sources")
                    db.execute("DELETE FROM browser_bridge_pairing")
                    db.execute("INSERT INTO browser_bridge_pairing(id,updated_at) VALUES(1,?)", (utc_now(),))
                    for source in payload["sources"]:
                        config = dict(source["config"])
                        config["enabled"] = bool(source["local_enabled"])
                        db.execute(
                            """INSERT INTO sources(source_id,source_json,baseline_complete,next_discovery_at,
                                 discovery_failures,discovery_status,discovery_last_success_at,updated_at)
                               VALUES(?,?,?,?,?,?,?,?)""",
                            (source["id"], self.json_dump(config), int(source["baseline_complete"]), source["next_discovery_at"],
                             source["discovery_failures"], source["discovery_status"], source["discovery_last_success_at"], utc_now()),
                        )
                    for watch in payload["watches"]:
                        config = watch["config"]
                        db.execute(
                            """INSERT INTO watches(id,source_id,product_id,product_url,variant_id,label,baseline_complete,
                                 cart_probe_enabled,created_at) VALUES(?,?,?,?,?,?,?,?,?)""",
                            (config["id"], config["source_id"], config["product_id"], config["product_url"], config["variant_id"],
                             config["label"], int(watch["baseline_complete"]), int(config["cart_probe_enabled"]), config["created_at"]),
                        )
                    db.execute(
                        "UPDATE app_settings SET notify_price_increases=?,auto_discovery_alerts=?,mention_user_id=?,mention_role_id=? WHERE id=1",
                        (
                            int(payload["settings"]["notify_price_increases"]),
                            int(payload["settings"]["auto_discovery_alerts"]),
                            payload["settings"]["mention_user_id"],
                            payload["settings"]["mention_role_id"],
                        ),
                    )
                    current_sources, current_watches, current_settings = self._hosted_sources_and_watches(db)
                    current_revision = self._hosted_config_revision(current_sources, current_watches, current_settings)
                    if current_revision != revision:
                        raise ValueError("Installed hosted configuration does not match its revision.")

                if not allowed("import_before_write"):
                    raise _OwnershipLost()
                placeholder_at = utc_now()
                for row in payload["catalog"]["product_ids"]:
                    db.execute(
                        """INSERT OR IGNORE INTO products(source_id,product_id,title,url,image_url,first_seen_at,last_seen_at)
                           VALUES(?,?, '', '', '', ?, ?)""",
                        (row["source_id"], row["product_id"], placeholder_at, placeholder_at),
                    )
                for row in payload["catalog"]["products"]:
                    db.execute(
                        """INSERT INTO products(source_id,product_id,title,url,image_url,first_seen_at,last_seen_at)
                           VALUES(?,?,?,?,?,?,?) ON CONFLICT(source_id,product_id) DO UPDATE SET
                             title=CASE WHEN excluded.title<>'' THEN excluded.title ELSE products.title END,
                             url=CASE WHEN excluded.url<>'' THEN excluded.url ELSE products.url END,
                             image_url=CASE WHEN excluded.image_url<>'' THEN excluded.image_url ELSE products.image_url END,
                             first_seen_at=MIN(products.first_seen_at,excluded.first_seen_at),
                             last_seen_at=MAX(products.last_seen_at,excluded.last_seen_at)""",
                        (row["source_id"], row["product_id"], row["title"], row["url"], row["image_url"], row["first_seen_at"], row["last_seen_at"]),
                    )
                for row in payload["catalog"]["product_variants"]:
                    db.execute(
                        """INSERT INTO product_variants(source_id,product_id,variant_id,variant_title,first_seen_at,last_seen_at)
                           VALUES(?,?,?,?,?,?) ON CONFLICT(source_id,product_id,variant_id) DO UPDATE SET
                             variant_title=excluded.variant_title,first_seen_at=MIN(product_variants.first_seen_at,excluded.first_seen_at),
                             last_seen_at=MAX(product_variants.last_seen_at,excluded.last_seen_at)""",
                        (row["source_id"], row["product_id"], row["variant_id"], row["variant_title"], row["first_seen_at"], row["last_seen_at"]),
                    )
                for row in payload["catalog"]["latest"]:
                    db.execute(
                        """INSERT INTO catalog_latest(source_id,product_id,variant_id,observed_at,payload_json)
                           VALUES(?,?,?,?,?) ON CONFLICT(source_id,product_id,variant_id) DO UPDATE SET
                             observed_at=excluded.observed_at,payload_json=excluded.payload_json
                           WHERE excluded.observed_at>=catalog_latest.observed_at""",
                        (row["source_id"], row["product_id"], row["variant_id"], row["observed_at"], self.json_dump(row["payload"])),
                    )
                for source in payload["sources"]:
                    db.execute(
                        """UPDATE sources SET baseline_complete=MAX(baseline_complete,?),
                             last_discovery_at=CASE WHEN last_discovery_at IS NULL OR last_discovery_at<? THEN ? ELSE last_discovery_at END,
                             next_discovery_at=?,discovery_failures=?,discovery_status=?,discovery_last_success_at=?
                           WHERE source_id=?""",
                        (int(source["baseline_complete"]), source["last_discovery_at"] or "", source["last_discovery_at"],
                         source["next_discovery_at"], source["discovery_failures"], source["discovery_status"],
                         source["discovery_last_success_at"], source["id"]),
                    )
                for watch in payload["watches"]:
                    config = watch["config"]
                    db.execute("UPDATE watches SET baseline_complete=MAX(baseline_complete,?) WHERE id=?", (int(watch["baseline_complete"]), config["id"]))
                    check = watch["check"]
                    if check is not None:
                        db.execute(
                            """INSERT INTO checks(source_id,product_url,variant_id,last_success_at,next_due_at,failures,last_error)
                               VALUES(?,?,?,?,?,?, '') ON CONFLICT(source_id,product_url,variant_id) DO UPDATE SET
                                 last_success_at=CASE WHEN checks.last_success_at IS NULL OR checks.last_success_at<excluded.last_success_at THEN excluded.last_success_at ELSE checks.last_success_at END,
                                 next_due_at=excluded.next_due_at,failures=MIN(checks.failures,excluded.failures),last_error=''""",
                            (config["source_id"], config["product_url"], config["variant_id"], check["last_success_at"], check["next_due_at"], check["failures"]),
                        )
                    for cart in watch["cart_checks"]:
                        db.execute(
                            """INSERT INTO cart_probe_checks(watch_id,variant_id,last_attempt_at,next_due_at,last_success_at,failures,last_error)
                               VALUES(?,?,?,?,?,?,'') ON CONFLICT(watch_id,variant_id) DO UPDATE SET
                                 last_attempt_at=excluded.last_attempt_at,next_due_at=excluded.next_due_at,
                                 last_success_at=excluded.last_success_at,failures=excluded.failures,last_error=''""",
                            (config["id"], cart["variant_id"], cart["last_attempt_at"], cart["next_due_at"], cart["last_success_at"], cart["failures"]),
                        )
                    for state in watch["states"]:
                        existing = db.execute("SELECT updated_at FROM watch_states WHERE watch_id=? AND variant_id=?", (config["id"], state["variant_id"])).fetchone()
                        updated_at = state.get("updated_at") or state["observed_at"]
                        if existing is None or (existing["updated_at"] or "") <= updated_at:
                            db.execute(
                                """INSERT INTO watch_states(watch_id,variant_id,observation_json,updated_at) VALUES(?,?,?,?)
                                   ON CONFLICT(watch_id,variant_id) DO UPDATE SET observation_json=excluded.observation_json,updated_at=excluded.updated_at""",
                                (config["id"], state["variant_id"], self.json_dump({k: v for k, v in state.items() if k != "updated_at"}), updated_at),
                            )

                for row in payload["observations"]:
                    encoded = self.json_dump(row["payload"])
                    existing = db.execute(
                        "SELECT payload_json FROM observations WHERE source_id=? AND product_id=? AND variant_id=? AND observed_at=?",
                        (row["source_id"], row["product_id"], row["variant_id"], row["observed_at"]),
                    ).fetchall()
                    if any(self.json_load(item["payload_json"], {}) == row["payload"] for item in existing):
                        continue
                    available = row["available"]
                    db.execute(
                        """INSERT INTO observations(source_id,product_id,variant_id,observed_at,price,currency,status,available,quantity,quantity_kind,payload_json)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                        (row["source_id"], row["product_id"], row["variant_id"], row["observed_at"], row["price"], row["currency"], row["status"],
                         None if available is None else int(available), row["quantity"], row["quantity_kind"], encoded),
                    )
                event_ids: dict[str, int] = {}
                for event in payload["events"]:
                    db.execute(
                        """INSERT OR IGNORE INTO events(dedup_key,kind,source_id,product_id,variant_id,created_at,title,summary,url,details_json)
                           VALUES(?,?,?,?,?,?,?,?,?,?)""",
                        (event["dedup_key"], event["kind"], event["source_id"], event["product_id"], event["variant_id"], event["created_at"],
                         event["title"], event["summary"], event["url"], self.json_dump(event["details"])),
                    )
                    event_row = db.execute("SELECT id FROM events WHERE dedup_key=?", (event["dedup_key"],)).fetchone()
                    event_ids[event["dedup_key"]] = int(event_row["id"])
                for row in payload["outbox"]:
                    event_id = event_ids.get(row["event_dedup_key"])
                    current = db.execute("SELECT status,attempts,next_attempt_at,delivered_at FROM outbox WHERE id=?", (row["id"],)).fetchone()
                    status = row["status"]
                    if status == "sending":
                        status = "uncertain"
                    if current is None:
                        db.execute(
                            """INSERT INTO outbox(id,event_id,kind,payload_json,status,attempts,next_attempt_at,created_at,delivered_at,last_error)
                               VALUES(?,?,'alert',?,?,?,?,?,?,?)""",
                            (row["id"], event_id, self.json_dump(row["payload"]), status, row["attempts"], row["next_attempt_at"], row["created_at"], row["delivered_at"],
                             "Delivery outcome uncertain after ownership handoff." if status == "uncertain" else None),
                        )
                    else:
                        merged_status = self._merge_outbox_status(current["status"], status)
                        delivered_at = current["delivered_at"] or row["delivered_at"]
                        next_at = max(str(current["next_attempt_at"] or ""), str(row["next_attempt_at"] or ""))
                        db.execute(
                            "UPDATE outbox SET status=?,attempts=MAX(attempts,?),next_attempt_at=?,delivered_at=?,last_error=? WHERE id=?",
                            (merged_status, row["attempts"], next_at, delivered_at,
                             "Delivery outcome uncertain after ownership handoff." if merged_status == "uncertain" else None, row["id"]),
                        )
                if not allowed("import_before_commit"):
                    raise _OwnershipLost()
        except _OwnershipLost:
            return {"status": "ownership_lost", "config_revision": revision}
        return {"status": "imported", "config_revision": revision, "counts": imported_counts}


def dedup_key(parts: list[Any]) -> str:
    raw = "\0".join(str(part or "") for part in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def safe_error(exc: BaseException) -> str:
    text = " ".join(str(exc).split())
    if not text:
        text = type(exc).__name__
    # Provider errors can contain request URLs; keep hosts and embedded tokens out of diagnostics.
    import re
    text = re.sub(r"https?://[^\s)\]}]+", "[source link]", text, flags=re.I)
    text = re.sub(r"(?i)(token|webhook|authorization|password)\s*[=:]\s*[^\s,;]+", r"\1=[hidden]", text)
    return text[:280]
