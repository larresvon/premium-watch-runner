from __future__ import annotations

import hashlib
import hmac
import json
import queue
import re
import secrets
import threading
import time
import uuid
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit

from . import security
from .engine import has_signal, listing_event, merge_comparison_state, observation_events, variant_event
from .models import (
    PremiumWatchError,
    ProviderError,
    normalize_cart_probe,
    normalize_observation,
    normalize_product,
    normalize_time,
    utc_now,
)
from .notifier import WebhookDeliveryError, build_payload, post_webhook
from .storage import Database, HOSTED_PROVIDER_PLATFORMS, safe_error


_SOURCE_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_DISCORD_ID = re.compile(r"^[0-9]{17,20}$")
_FALLBACK_PLATFORMS = {"shopify", "youngcart", "kimchidvd", "cafe24", "invision"}


def _load_browser_bridge_sections() -> dict[str, dict[str, str]]:
    try:
        from .private_bridge_defaults import BROWSER_BRIDGE_SECTIONS
    except ModuleNotFoundError as exc:
        if exc.name != f"{__package__}.private_bridge_defaults":
            raise
        return {}
    return BROWSER_BRIDGE_SECTIONS


_BROWSER_BRIDGE_SECTIONS = _load_browser_bridge_sections()
_EXTENSION_ORIGIN = re.compile(r"^chrome-extension://([a-p]{32})$")
_PAIRING_CODE = re.compile(r"^[A-Z2-9]{8}$")
_TOPIC_ID = re.compile(r"^[0-9]{1,20}$")
_TOPIC_PATH = re.compile(r"/(?:topic|threads?)/([0-9]+)(?:[-/]|$)", re.IGNORECASE)
_BROWSER_BRIDGE_SECTION_URL = re.compile(
    r"^https://mediapsychos\.com/forum/(?P<forum_id>[1-9][0-9]{0,5})-"
    r"(?P<slug>[a-z0-9]+(?:-[a-z0-9]+)*)/\?sortby=start_date&sortdirection=desc$"
)
_BRIDGE_FAILURES = {
    "login_required": "The browser bridge reports that the forum tab is signed out.",
    "challenge": "The browser bridge encountered a forum site challenge.",
    "incomplete": "The browser bridge could not complete the forum listing scan.",
    "tab_closed": "The monitored forum tab is closed or unavailable.",
    "stale": "The browser bridge report was too old to accept.",
}
_PAIR_CODE_SECONDS = 300
_BRIDGE_STALE_INTERVALS = 2
_MAX_BRIDGE_TOPICS = 2000
_CART_PROBE_COOLDOWN_SECONDS = 900
_CART_PROBE_REQUEST_QUANTITY = 10
_CART_PROBE_SAFE_SECONDS = 48.0
_RUN_ONCE_DELIVERY_RESERVE_SECONDS = 20.0
_MAX_BRIDGE_BODY = 512 * 1024


class _StaleBridgeCapture(ValueError):
    """An otherwise valid bridge report older than the last accepted snapshot."""


class _ServiceOwnershipLost(RuntimeError):
    """The coordinator fence was lost before state could be accepted."""


class _VerificationSourceEmpty(ProviderError):
    """A public discovery response had no rows to prove catalog coverage."""

    hosted_error_code = "source_empty"


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _bool(value: Any, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if value in (0, 1):
        return bool(value)
    raise ValueError(f"{field} must be true or false.")


class PremiumService:
    """Persistent local monitor and its serialized worker lifecycle."""

    def __init__(
        self, data_dir: Path, sources_file: Path, *, execution_context_id: str | None = None,
        ownership_check: Callable[[str], bool] | None = None,
    ):
        self.data_dir = Path(data_dir)
        self.sources_file = Path(sources_file)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db = Database(self.data_dir / "premium_watch.sqlite3")
        self.execution_context_id = str(execution_context_id or self.db.get_or_create_execution_context_id())[:120]
        self.db.adopt_legacy_local_context(self.execution_context_id)
        self.hosted_mode = False
        self.ownership_check = ownership_check
        self._hosted_webhook_url: str | None = None
        self._hosting_controller: Any = None
        self._hosting_lease_released = True
        self._hosting_checkpoint_failed = False
        self._last_unit_error_code = ""
        self._provider_error = ""
        try:
            from .providers import ProviderRegistry
            self.providers = ProviderRegistry(session_dir=self.data_dir / "sessions")
        except Exception as exc:
            self.providers = None
            self._provider_error = safe_error(exc)
        self._seed_sources()
        self._lifecycle_lock = threading.RLock()
        self._cycle_lock = threading.Lock()
        self._delivery_lock = threading.Lock()
        self._worker: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._manual_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1)
        self._last_cycle_at = self.db.get_state("last_cycle_at")
        self._provider_close_lock = threading.RLock()
        self._provider_close_requested = False
        self._provider_closed = False
        self._provider_close_error = ""
        self._provider_close_thread: threading.Thread | None = None

    def _seed_sources(self) -> None:
        try:
            raw = json.loads(self.sources_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if isinstance(raw, dict):
            rows = raw.get("sources", [])
        else:
            rows = raw
        if not isinstance(rows, list):
            return
        for item in rows:
            if not isinstance(item, dict) or not item.get("id"):
                continue
            try:
                source = self._validate_source(item, allow_missing_platform_registry=True)
            except (TypeError, ValueError):
                continue
            self.db.seed_source(source)

    def set_ownership_check(self, ownership_check: Callable[[str], bool] | None) -> None:
        if ownership_check is not None and not callable(ownership_check):
            raise TypeError("Ownership check must be callable or None.")
        self.ownership_check = ownership_check

    def set_hosting_controller(self, controller: Any | None) -> None:
        """Attach the local ownership/heartbeat controller without coupling service to its storage."""
        if controller is not None and not callable(getattr(controller, "before_local_work", None)):
            raise TypeError("Hosting controller must provide before_local_work().")
        self._hosting_controller = controller
        self._hosting_lease_released = controller is None
        self._hosting_checkpoint_failed = False

    def _controller_before_local_work(self, phase: str) -> bool:
        controller = self._hosting_controller
        if controller is None:
            return True
        try:
            result = controller.before_local_work(phase)
            if isinstance(result, dict):
                return bool(result.get("allowed"))
            return bool(result)
        except Exception:
            return False

    def _controller_after_local_work(self, progress: dict[str, Any]) -> bool:
        controller = self._hosting_controller
        callback = getattr(controller, "after_local_work", None) if controller is not None else None
        if not callable(callback) or self.hosted_mode:
            return True
        try:
            accepted = callback(self, dict(progress))
            if accepted is False:
                self._hosting_checkpoint_failed = True
                return False
            return True
        except Exception:
            # A failed sync must not undo already accepted local state.
            self._hosting_checkpoint_failed = True
            return False

    def _provider_deadline_scope(self, deadline: float | None):
        if deadline is None:
            return nullcontext()
        scope = getattr(self.providers, "deadline_scope", None)
        if not callable(scope):
            return nullcontext()
        return scope(deadline)

    def _release_local_hosting_lease(self) -> None:
        controller = self._hosting_controller
        callback = getattr(controller, "release_local_lease", None) if controller is not None else None
        if not callable(callback) or self._hosting_lease_released:
            return
        self._hosting_lease_released = True
        try:
            callback()
        except Exception:
            return

    def _ownership_allowed(self, phase: str) -> bool:
        controller = self._hosting_controller if not self.hosted_mode else None
        if controller is not None:
            if self._hosting_checkpoint_failed and phase != "heartbeat":
                return False
            if not self._controller_before_local_work(phase):
                return False
            if phase == "heartbeat":
                self._hosting_checkpoint_failed = False
            callback_owner = getattr(self.ownership_check, "__self__", None)
            controller_monitor = getattr(controller, "_monitor", None)
            if (
                self.ownership_check is not None
                and callback_owner is not None
                and callback_owner is controller_monitor
                and getattr(self.ownership_check, "__name__", "") == "fenced"
            ):
                # HostingController.before_local_work already performed this
                # monitor fence; avoid making the same GitHub read twice.
                return True
        if self.ownership_check is None:
            return True
        try:
            result = self.ownership_check(phase)
            if isinstance(result, dict):
                return bool(result.get("allowed"))
            return bool(result)
        except Exception:
            return False

    def set_hosted_webhook(self, value: str | None) -> None:
        """Keep a hosted webhook in memory only; it never enters SQLite or snapshots."""
        value = str(value or "").strip()
        self._hosted_webhook_url = security.validate_webhook_url(value) if value else None

    def export_hosted_snapshot(self) -> dict[str, Any]:
        return self.db.export_hosted_snapshot(context_id=self.execution_context_id)

    def import_hosted_snapshot(
        self, snapshot: dict[str, Any], *, expected_config_revision: str, hosted: bool = False,
        ownership_check: Callable[[str], bool] | None = None,
    ) -> dict[str, Any]:
        checker = ownership_check if ownership_check is not None else self.ownership_check
        result = self.db.import_hosted_snapshot(
            snapshot, expected_config_revision=expected_config_revision, hosted=hosted,
            ownership_check=checker,
        )
        if result.get("status") == "imported" and hosted:
            self.hosted_mode = True
        return result

    @property
    def running(self) -> bool:
        return bool(self._worker and self._worker.is_alive() and not self._stop_event.is_set())

    def start(self) -> dict[str, Any]:
        with self._lifecycle_lock:
            with self._provider_close_lock:
                if self._provider_close_requested:
                    if not self._provider_closed:
                        return {"running": False, "started": False, "error": "Provider cleanup is still finishing."}
                    # ProviderRegistry supports a later explicit restart after close().
                    self._provider_close_requested = False
                    self._provider_closed = False
                    self._provider_close_error = ""
                    self._provider_close_thread = None
            if self.running:
                return {"running": True, "started": False}
            if self._worker and self._worker.is_alive():
                if self._stop_event.is_set():
                    self._worker.join(timeout=25)
                if self._worker.is_alive():
                    return {"running": False, "started": False, "error": "The previous worker is still stopping."}
            self._stop_event.clear()
            self._hosting_lease_released = False
            self._wake_event.set()
            self._worker = threading.Thread(target=self._worker_loop, name="PremiumWatchWorker", daemon=True)
            self._worker.start()
        return {"running": True, "started": True}

    def stop(self) -> dict[str, Any]:
        with self._lifecycle_lock:
            worker = self._worker
            if not worker or not worker.is_alive():
                self._stop_event.set()
                self._release_local_hosting_lease()
                return {"running": False, "stopped": False}
            self._stop_event.set()
            self._wake_event.set()
        if worker is not threading.current_thread():
            worker.join(timeout=25)
        if not worker.is_alive():
            self._release_local_hosting_lease()
        return {"running": self.running, "stopped": not worker.is_alive()}

    def close(self) -> dict[str, Any]:
        """Stop polling, then release explicit provider resources once checks have ended."""
        with self._lifecycle_lock:
            with self._provider_close_lock:
                if self._provider_close_requested:
                    return self._provider_close_result()
                self._provider_close_requested = True
            self.stop()
            worker = self._worker
            if worker and worker.is_alive():
                closer = threading.Thread(
                    target=self._close_provider_after_worker,
                    args=(worker,),
                    name="PremiumWatchProviderClose",
                    daemon=False,
                )
                with self._provider_close_lock:
                    self._provider_close_thread = closer
                closer.start()
                return {"closed": False, "closing": True}
            return self._close_provider_registry()

    def _close_provider_after_worker(self, worker: threading.Thread) -> None:
        worker.join()
        with self._lifecycle_lock:
            self._close_provider_registry()

    def _close_provider_registry(self) -> dict[str, Any]:
        with self._provider_close_lock:
            if self._provider_closed:
                return self._provider_close_result()
            try:
                close = getattr(self.providers, "close", None)
                if callable(close):
                    close()
            except Exception as exc:
                self._provider_close_error = safe_error(exc)
            self._provider_closed = True
            return self._provider_close_result()

    def _provider_close_result(self) -> dict[str, Any]:
        result = {"closed": self._provider_closed, "closing": self._provider_close_requested and not self._provider_closed}
        if self._provider_close_error:
            result["error"] = self._provider_close_error
        return result

    def get_state(self) -> dict[str, Any]:
        sources = self.db.sources()
        settings = self.db.settings()
        watches = []
        for watch in self.db.watches():
            source_id = watch["source_id"]
            product_id = watch["product_id"]
            latest = self.db.watch_latest_observations(
                int(watch["id"]), watch["variant_id"] if watch["variant_id"] else None
            ) if product_id else []
            lows: dict[tuple[str, str], tuple[Decimal, str, str]] = {}
            for row in self.db.observation_rows_since(source_id, product_id, watch["created_at"]) if product_id else []:
                variant_id = str(row["variant_id"] or "")
                currency = str(row["currency"] or "")
                if watch["variant_id"] and variant_id != watch["variant_id"]:
                    continue
                if not currency or row["price"] is None:
                    continue
                key = (variant_id, currency)
                value = Decimal(str(row["price"]))
                found = lows.get(key)
                if found is None or value < found[0]:
                    lows[key] = (value, str(row["observed_at"]), str((row.get("payload_json") and Database.json_load(row["payload_json"], {}).get("variant_title")) or ""))
            historical_lows = [
                {
                    "variant_id": variant_id,
                    "variant_title": title,
                    "currency": currency,
                    "price": format(value.normalize(), "f"),
                    "since": watch["created_at"],
                    "observed_at": since,
                }
                for (variant_id, currency), (value, since, title) in sorted(lows.items())
            ]
            item = dict(watch)
            item["id"] = str(watch["id"])
            item["baseline_complete"] = bool(watch.get("baseline_complete"))
            item["cart_probe_enabled"] = bool(watch.get("cart_probe_enabled"))
            item["tracking_started_at"] = watch["created_at"]
            if item["cart_probe_enabled"]:
                latest = [dict(row) for row in latest]
                for row in latest:
                    if not isinstance(row.get("cart_probe"), dict):
                        row["cart_probe"] = self._waiting_cart_probe()
            item["latest_observations"] = latest
            item["latest_observation"] = latest[0] if len(latest) == 1 else None
            item["historical_lows"] = historical_lows
            watches.append(item)
        products = self.db.products_with_catalog_latest()
        public_settings = {
            "discord_configured": bool(settings["webhook_protected"]),
            "mention_user_id": settings["mention_user_id"],
            "mention_role_id": settings["mention_role_id"],
            "notify_price_increases": settings["notify_price_increases"],
            "auto_discovery_alerts": settings["auto_discovery_alerts"],
        }
        return {
            "running": self.running,
            "last_cycle_at": self._last_cycle_at,
            "next_cycle_at": self._next_cycle_at() if self.running else None,
            "settings": public_settings,
            "sources": sources,
            "products": products,
            "watches": watches,
            "events": self.db.events(),
            "outbox": self.db.outbox(),
            "browser_bridge": self.browser_bridge_status(),
        }

    def browser_bridge_sections_payload(self) -> dict[str, Any]:
        sections_by_id = self._browser_bridge_sections_by_id()
        reports = {row["source_id"]: row for row in self.db.browser_bridge_sections()}
        sections = []
        intervals = []
        for source_id in sorted(sections_by_id):
            configured = sections_by_id[source_id]
            report = reports.get(source_id) or {}
            intervals.append(int(configured["discovery_interval"]))
            sections.append({
                "source_id": source_id,
                "section_url": configured["section_url"],
                "scan_scope": configured["scan_scope"],
                "name": configured["name"],
                "forum_id": configured["forum_id"],
                "enabled": bool(configured["enabled"]),
                "baseline_complete": bool(report.get("baseline_complete")),
                "cursor_topic_id": str(report.get("cursor_topic_id") or "") if report.get("baseline_complete") else "",
            })
        return {
            "sections": sections,
            "poll_interval_seconds": min(intervals) if intervals else 900,
        }

    @staticmethod
    def _browser_bridge_section_for_source(source: dict[str, Any]) -> dict[str, Any] | None:
        source_id = str(source.get("id") or "")
        if not _SOURCE_ID.fullmatch(source_id) or source.get("platform") != "invision":
            return None
        url = str(source.get("url") or "")
        configured = _BROWSER_BRIDGE_SECTIONS.get(source_id)
        if configured:
            if url != configured["url"]:
                return None
            forum_id = configured["forum_id"]
            scan_scope = configured["scan_scope"]
        else:
            if len(url) > 512:
                return None
            match = _BROWSER_BRIDGE_SECTION_URL.fullmatch(url)
            if not match:
                return None
            forum_id = match.group("forum_id")
            scan_scope = "latest_page"
        return {
            "source_id": source_id,
            "name": " ".join(str(source.get("name") or "").split()),
            "forum_id": forum_id,
            "url": url,
            "section_url": url,
            "scan_scope": scan_scope,
            "enabled": bool(source.get("enabled", True)),
            "discovery_interval": int(source.get("discovery_interval", 900)),
        }

    def _browser_bridge_sections_by_id(self) -> dict[str, dict[str, Any]]:
        candidates: dict[str, dict[str, Any]] = {}
        forum_ids: dict[str, list[str]] = {}
        for source in self.db.sources():
            configured = self._browser_bridge_section_for_source(source)
            if not configured:
                continue
            source_id = configured["source_id"]
            candidates[source_id] = configured
            forum_ids.setdefault(configured["forum_id"], []).append(source_id)
        ambiguous_ids = {
            source_id
            for source_ids in forum_ids.values() if len(source_ids) > 1
            for source_id in source_ids
        }
        return {
            source_id: configured
            for source_id, configured in candidates.items()
            if source_id not in ambiguous_ids
        }

    def browser_bridge_status(self) -> dict[str, Any]:
        credentials = self.db.browser_bridge_credentials()
        paired = bool(credentials.get("token_hash") and credentials.get("extension_origin"))
        sections_by_id = self._browser_bridge_sections_by_id()
        reports = {row["source_id"]: row for row in self.db.browser_bridge_sections()}
        now = datetime.now(timezone.utc)
        sections = []
        for source_id in sorted(sections_by_id):
            configured = sections_by_id[source_id]
            report = reports.get(source_id) or {}
            if not paired:
                status = "unpaired"
            else:
                last_attempt = _parse_time(report.get("last_attempt_at"))
                if last_attempt is None:
                    status = "waiting"
                else:
                    stale_after = max(600, int(configured["discovery_interval"]) * _BRIDGE_STALE_INTERVALS)
                    if (now - last_attempt).total_seconds() > stale_after:
                        status = "stale"
                    elif report.get("status") == "healthy":
                        status = "healthy"
                    elif report.get("status") in _BRIDGE_FAILURES:
                        status = report["status"]
                    else:
                        status = "error"
            sections.append({
                "source_id": source_id,
                "name": configured["name"],
                "section_url": configured["section_url"],
                "forum_id": configured["forum_id"],
                "scan_scope": configured["scan_scope"],
                "status": status,
                "enabled": bool(configured["enabled"]),
                "baseline_complete": bool(report.get("baseline_complete")),
                "last_reported_at": report.get("last_attempt_at"),
                "last_success_at": report.get("last_success_at"),
                "last_error": str(report.get("last_error") or "") if status in _BRIDGE_FAILURES or status == "error" else "",
                "topic_count": int(report.get("last_topic_count") or 0),
                "cursor_topic_id": str(report.get("cursor_topic_id") or ""),
                "can_enable": bool(paired and status == "healthy" and report.get("baseline_complete")),
            })
        can_enable = paired and any(section["can_enable"] for section in sections)
        active_statuses = [section["status"] for section in sections if section["enabled"]]
        if not paired:
            status = "unpaired"
        elif active_statuses and all(value == "healthy" for value in active_statuses):
            status = "healthy"
        elif any(value == "stale" for value in active_statuses):
            status = "stale"
        elif any(value in _BRIDGE_FAILURES and value != "stale" for value in active_statuses):
            status = "error"
        else:
            status = "waiting"
        return {
            "paired": paired,
            "paired_at": credentials.get("paired_at") if paired else None,
            "status": status,
            "can_enable_sources": bool(can_enable),
            "sections": sections,
        }

    def save_settings(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("Settings must be an object.")
        updates: dict[str, Any] = {}
        if "discord_webhook_url" in payload:
            webhook = str(payload.get("discord_webhook_url") or "").strip()
            if webhook:
                webhook = security.validate_webhook_url(webhook)
                updates["webhook_protected"] = security.protect_secret(webhook)
        for name in ("mention_user_id", "mention_role_id"):
            if name in payload:
                value = str(payload.get(name) or "").strip()
                if value and not _DISCORD_ID.fullmatch(value):
                    raise ValueError(f"{name.replace('_', ' ').title()} must be a Discord ID or blank.")
                updates[name] = value
        for name in ("notify_price_increases", "auto_discovery_alerts"):
            if name in payload:
                updates[name] = _bool(payload[name], name.replace("_", " ").title())
        self.db.save_settings(updates)
        if self.running:
            self._wake_event.set()
        return {"ok": True, "settings": self.get_state()["settings"]}

    def issue_browser_bridge_pairing_code(self) -> dict[str, Any]:
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        code = "".join(secrets.choice(alphabet) for _ in range(8))
        now = datetime.now(timezone.utc)
        expires = (now + timedelta(seconds=_PAIR_CODE_SECONDS)).isoformat(timespec="microseconds")
        self.db.set_browser_bridge_pair_code(hashlib.sha256(code.encode("ascii")).hexdigest(), expires)
        return {"ok": True, "code": code, "expires_at": expires}

    def pair_browser_bridge(self, code: str, origin: str) -> dict[str, Any]:
        match = _EXTENSION_ORIGIN.fullmatch(str(origin or ""))
        normalized_code = str(code or "").strip().upper()
        if not match or not _PAIRING_CODE.fullmatch(normalized_code):
            raise ValueError("The pairing request is invalid or expired.")
        token = secrets.token_urlsafe(32)
        now = utc_now()
        consumed = self.db.consume_browser_bridge_pair_code(
            hashlib.sha256(normalized_code.encode("ascii")).hexdigest(),
            now=now,
            token_hash=hashlib.sha256(token.encode("ascii")).hexdigest(),
            origin=origin,
        )
        if not consumed:
            raise ValueError("The pairing request is invalid or expired.")
        sections = self.browser_bridge_sections_payload()
        return {"ok": True, "token": token, **sections}

    def unpair_browser_bridge(self) -> dict[str, Any]:
        self.db.revoke_browser_bridge()
        return {"ok": True, "paired": False}

    def browser_bridge_authentication_status(self, token: str, origin: str) -> str:
        if not _EXTENSION_ORIGIN.fullmatch(str(origin or "")):
            return "origin_rejected"
        candidate = str(token or "")
        if not 32 <= len(candidate) <= 128:
            return "token_rejected"
        record = self.db.browser_bridge_credentials()
        saved_hash = str(record.get("token_hash") or "")
        saved_origin = str(record.get("extension_origin") or "")
        if not saved_hash or not saved_origin:
            return "revoked"
        candidate_hash = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(saved_hash, candidate_hash):
            return "token_rejected"
        if not hmac.compare_digest(saved_origin, origin):
            return "origin_mismatch"
        return "authenticated"

    def browser_bridge_authenticate(self, token: str, origin: str) -> bool:
        return self.browser_bridge_authentication_status(token, origin) == "authenticated"

    def _record_browser_bridge_failure(self, source_id: str, status: str) -> dict[str, Any]:
        status = status if status in _BRIDGE_FAILURES else "incomplete"
        attempted_at = utc_now()
        message = _BRIDGE_FAILURES[status]
        with self.db.connect() as connection:
            source = self.db.source(source_id, connection=connection)
            if not source:
                raise ValueError("Unknown browser bridge section.")
            failures = int(source.get("discovery_failures", 0)) + 1
            self.db.record_browser_bridge_error(
                source_id, attempted_at=attempted_at, status=status, error=message, connection=connection,
            )
            self.db.update_source_health(
                source_id, discovery_failures=failures, discovery_status="error",
                discovery_last_error=message, connection=connection,
            )
        return {"ok": True, "accepted": False, "source_id": source_id, "status": status}

    @staticmethod
    def _normalize_browser_topic(
        section: dict[str, Any], raw: Any,
    ) -> tuple[dict[str, Any], str, str, bool]:
        if not isinstance(raw, dict) or set(raw) - {"topic_id", "title", "url", "started_at", "is_pinned"}:
            raise ValueError("invalid topic shape")
        is_pinned = raw.get("is_pinned")
        if not isinstance(is_pinned, bool):
            raise ValueError("missing or ambiguous topic pin state")
        topic_id = str(raw.get("topic_id") or "").strip()
        if not _TOPIC_ID.fullmatch(topic_id) or int(topic_id) <= 0:
            raise ValueError("invalid topic ID")
        topic_id = str(int(topic_id))
        title = " ".join(str(raw.get("title") or "").split())
        if not title or len(title) > 300:
            raise ValueError("invalid topic title")
        topic_url = str(raw.get("url") or "").strip()
        parsed = urlsplit(topic_url)
        match = _TOPIC_PATH.search(parsed.path)
        if (
            parsed.scheme.lower() != "https" or parsed.hostname != "mediapsychos.com" or
            parsed.username or parsed.password or parsed.port not in (None, 443) or
            parsed.fragment or not match or str(int(match.group(1))) != topic_id
        ):
            raise ValueError("invalid topic URL")
        canonical_url = f"https://mediapsychos.com{parsed.path}"
        if "started_at" in raw and raw.get("started_at") not in (None, ""):
            normalize_time(raw["started_at"], default_now=False)
        product_id = f"invision:{section['forum_id']}:{topic_id}"
        return ({
            "product_id": product_id,
            "title": title,
            "url": canonical_url,
            "image_url": "",
            "variants": [],
        }, topic_id, normalize_time(raw["started_at"], default_now=False) if raw.get("started_at") else "", is_pinned)

    def ingest_browser_bridge_report(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("The browser report must be a JSON object.")
        source_id = str(payload.get("source_id") or "")
        source = self.db.source(source_id)
        if not source:
            raise ValueError("Unknown browser bridge section.")
        section = self._browser_bridge_sections_by_id().get(source_id)
        if not section or source.get("platform") != "invision" or source.get("url") != section["section_url"]:
            raise ValueError("The configured forum section does not match the browser bridge contract.")

        allowed_fields = {
            "source_id", "captured_at", "section_url", "report_id", "scan_mode", "complete",
            "pagination_complete", "pages_scanned", "overlap_topic_id", "status", "topics",
        }
        if set(payload) - allowed_fields or payload.get("section_url") != section["section_url"]:
            return self._record_browser_bridge_failure(source_id, "incomplete")
        try:
            report_id = str(uuid.UUID(str(payload.get("report_id") or "")))
        except (TypeError, ValueError, AttributeError):
            return self._record_browser_bridge_failure(source_id, "incomplete")
        if self.db.browser_bridge_report_accepted(source_id, report_id):
            return {
                "ok": True, "accepted": True, "idempotent": True, "source_id": source_id,
                "baseline_complete": True, "new_topics": 0,
            }

        try:
            captured_at = normalize_time(payload.get("captured_at"), default_now=False)
            capture_dt = _parse_time(captured_at)
            now_dt = datetime.now(timezone.utc)
            if capture_dt is None or (now_dt - capture_dt).total_seconds() > 900 or (capture_dt - now_dt).total_seconds() > 120:
                return self._record_browser_bridge_failure(source_id, "stale")
            complete = _bool(payload.get("complete"), "Complete")
            if not complete:
                status = str(payload.get("status") or "incomplete")
                return self._record_browser_bridge_failure(source_id, status)
            if payload.get("status") not in (None, ""):
                return self._record_browser_bridge_failure(source_id, "incomplete")
            scan_mode = str(payload.get("scan_mode") or "")
            scan_scope = section["scan_scope"]
            allowed_modes = {"full", "overlap"} if scan_scope == "full" else {"latest_page"}
            if scan_mode not in allowed_modes:
                return self._record_browser_bridge_failure(source_id, "incomplete")
            pages_scanned = payload.get("pages_scanned")
            if isinstance(pages_scanned, bool) or not isinstance(pages_scanned, int):
                return self._record_browser_bridge_failure(source_id, "incomplete")
            if (scan_mode == "latest_page" and pages_scanned != 1) or (
                scan_mode != "latest_page" and not 1 <= pages_scanned <= 40
            ):
                return self._record_browser_bridge_failure(source_id, "incomplete")
            pagination_complete = payload.get("pagination_complete")
            if not isinstance(pagination_complete, bool):
                return self._record_browser_bridge_failure(source_id, "incomplete")
            if (
                (scan_mode == "full" and not pagination_complete) or
                (scan_mode in {"overlap", "latest_page"} and pagination_complete)
            ):
                return self._record_browser_bridge_failure(source_id, "incomplete")
            raw_topics = payload.get("topics")
            if not isinstance(raw_topics, list) or not 1 <= len(raw_topics) <= _MAX_BRIDGE_TOPICS:
                return self._record_browser_bridge_failure(source_id, "incomplete")
            normalized_by_id: dict[str, tuple[dict[str, Any], str, bool]] = {}
            ordered_ids: list[str] = []
            ordered_unpinned_times: list[datetime | None] = []
            for raw in raw_topics:
                product, topic_id, started_at, is_pinned = self._normalize_browser_topic(section, raw)
                existing = normalized_by_id.get(topic_id)
                if existing:
                    if (
                        existing[0]["url"] != product["url"] or existing[0]["title"] != product["title"] or
                        existing[2] != is_pinned
                    ):
                        raise ValueError("conflicting duplicate topic")
                    continue
                normalized_by_id[topic_id] = (product, started_at, is_pinned)
                ordered_ids.append(topic_id)
                if not is_pinned:
                    ordered_unpinned_times.append(_parse_time(started_at) if started_at else None)
            if not ordered_ids:
                return self._record_browser_bridge_failure(source_id, "incomplete")
            unpinned_ids = [topic_id for topic_id in ordered_ids if not normalized_by_id[topic_id][2]]
            if scan_mode != "latest_page" and not unpinned_ids:
                return self._record_browser_bridge_failure(source_id, "incomplete")
            if len(ordered_unpinned_times) > 1 and all(ordered_unpinned_times) and any(
                ordered_unpinned_times[index] < ordered_unpinned_times[index + 1]
                for index in range(len(ordered_unpinned_times) - 1)
            ):
                return self._record_browser_bridge_failure(source_id, "incomplete")
            overlap_id = str(payload.get("overlap_topic_id") or "").strip()
            if scan_mode == "overlap" and not _TOPIC_ID.fullmatch(overlap_id):
                return self._record_browser_bridge_failure(source_id, "incomplete")
            if scan_mode in {"full", "latest_page"} and overlap_id:
                return self._record_browser_bridge_failure(source_id, "incomplete")
        except (TypeError, ValueError):
            return self._record_browser_bridge_failure(source_id, "incomplete")

        try:
            with self.db.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                current_source = self.db.source(source_id, connection=connection) or source
                if (
                    current_source.get("platform") != "invision" or
                    current_source.get("url") != section["section_url"]
                ):
                    raise ValueError("The configured forum section changed during the browser report.")
                current_bridge = self.db.browser_bridge_section(source_id, connection=connection) or {}
                if self.db.browser_bridge_report_accepted(source_id, report_id, connection=connection):
                    return {
                        "ok": True, "accepted": True, "idempotent": True, "source_id": source_id,
                        "baseline_complete": True, "new_topics": 0,
                    }
                last_capture = _parse_time(current_bridge.get("last_capture_at"))
                if last_capture and capture_dt <= last_capture:
                    raise _StaleBridgeCapture("stale capture")
                if scan_mode == "overlap":
                    cursor = str(current_bridge.get("cursor_topic_id") or "")
                    if (
                        not current_bridge.get("baseline_complete") or overlap_id != cursor or
                        overlap_id not in normalized_by_id or normalized_by_id[overlap_id][2] or
                        unpinned_ids[-1] != overlap_id or ordered_ids[-1] != overlap_id
                    ):
                        raise ValueError("invalid overlap cursor")
                normalized = [normalize_product(normalized_by_id[topic_id][0], source=current_source) for topic_id in ordered_ids]
                completed_at = utc_now()
                allow_events = self._browser_bridge_events_enabled(
                    previously_baselined=bool(current_bridge.get("baseline_complete")),
                    source=current_source,
                )
                new_topics = self._apply_discovery(
                    current_source, normalized, completed_at, connection=connection,
                    was_baselined_override=bool(current_bridge.get("baseline_complete")),
                    allow_events=allow_events,
                )
                self.db.record_browser_bridge_success(
                    source_id, attempted_at=completed_at, captured_at=captured_at,
                    topic_count=len(ordered_ids),
                    cursor_topic_id=unpinned_ids[0] if scan_mode != "latest_page" and unpinned_ids else "",
                    report_id=report_id, connection=connection,
                )
        except _StaleBridgeCapture:
            return self._record_browser_bridge_failure(source_id, "stale")
        except ValueError:
            return self._record_browser_bridge_failure(source_id, "incomplete")
        except Exception:
            self._record_browser_bridge_failure(source_id, "incomplete")
            return {"ok": False, "accepted": False, "source_id": source_id, "status": "incomplete"}
        return {
            "ok": True, "accepted": True, "idempotent": False, "source_id": source_id,
            "baseline_complete": True, "topic_count": len(ordered_ids), "new_topics": new_topics,
        }

    def _browser_bridge_events_enabled(self, *, previously_baselined: bool,
                                      source: dict[str, Any]) -> bool:
        # Each forum has its own quiet baseline. A newly added or repaired forum
        # must not suppress alerts from another forum that is already baselined.
        return bool(
            previously_baselined and source.get("enabled", True) and
            source.get("discovery_enabled", True)
        )

    def upsert_source(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("Source must be an object.")
        source_id = str(payload.get("id") or "").strip().lower()
        previous = self.db.source(source_id) if source_id else None
        merged = dict(previous or {})
        merged.update(payload)
        source = self._validate_source(merged)
        previous_section = self._browser_bridge_section_for_source(previous) if previous else None
        if previous_section and (
            source.get("platform") != "invision" or
            source.get("url") != previous_section["section_url"]
        ):
            raise ValueError(
                "A configured Media Psychos forum source must keep its section URL and platform; use a new source ID for another forum."
            )
        if source_id in _BROWSER_BRIDGE_SECTIONS and (
            source.get("platform") != "invision" or
            source.get("url") != _BROWSER_BRIDGE_SECTIONS[source_id]["url"]
        ):
            raise ValueError("This forum section must keep its configured Media Psychos listing URL.")
        if source.get("platform") == "invision":
            section = self._browser_bridge_section_for_source(source)
            if not section:
                raise ValueError(
                    "Media Psychos forum sources must use the exact HTTPS forum listing URL sorted by start date descending."
                )
            for other in self.db.sources():
                if other["id"] == source_id or other.get("platform") != "invision":
                    continue
                other_section = self._browser_bridge_section_for_source(other)
                if other_section and other_section["forum_id"] == section["forum_id"]:
                    raise ValueError("A Media Psychos forum ID can be configured only once.")
            if source.get("enabled") and previous and not bool(previous.get("enabled", False)):
                bridge_section = next((
                    row for row in self.browser_bridge_status()["sections"]
                    if row["source_id"] == source_id
                ), None)
                if not bridge_section or not bridge_section.get("can_enable"):
                    raise ValueError("Verify this forum section with the paired browser extension before enabling forum alerts.")
        self.db.upsert_source(source)
        if previous and bool(previous.get("discovery_enabled", True)) != source["discovery_enabled"]:
            if source["discovery_enabled"]:
                # Re-enabling catalog polling schedules a prompt retry, while retaining
                # the previous error until a complete scan proves discovery healthy.
                self.db.update_source_health(
                    source_id, discovery_status="waiting", next_discovery_at=utc_now(),
                )
            else:
                prior_error = str((previous or {}).get("discovery_last_error") or "").strip()
                if source.get("platform") == "kimchidvd":
                    reason = "Catalog incomplete; selected product checks available."
                else:
                    reason = "Catalog discovery is paused; selected product checks remain available."
                if prior_error and prior_error not in reason:
                    reason += f" Last scan error: {prior_error}"
                self.db.update_source_health(
                    source_id, discovery_status="disabled", discovery_last_error=reason,
                )
        if self.running:
            self._wake_event.set()
        stored = self.db.source(source["id"])
        return {"ok": True, "source": stored}

    def add_watch(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("Watch entry must be an object.")
        source_id = str(payload.get("source_id") or "").strip()
        source = self.db.source(source_id)
        if not source:
            raise ValueError("Choose a configured source before adding a watch.")
        if source.get("platform") == "invision":
            raise ValueError("Forum group-buy topics are tracked through browser discovery, not product watches.")
        product_url = security.validate_public_http_url(str(payload.get("product_url") or ""))
        if urlsplit(product_url).scheme.lower() != "https":
            raise ValueError("Retailer product URLs must use HTTPS.")
        product_id = str(payload.get("product_id") or "").strip()
        if len(product_id) > 240:
            raise ValueError("Product ID is too long.")
        variant_id = str(payload.get("variant_id") or "").strip()
        if len(variant_id) > 240:
            raise ValueError("Variant ID is too long.")
        label = " ".join(str(payload.get("label") or "").split())[:160]
        cart_probe_enabled = None
        if "cart_probe_enabled" in payload:
            cart_probe_enabled = _bool(payload.get("cart_probe_enabled"), "Cart probe")
            if cart_probe_enabled and str(source.get("platform") or "").lower() != "shopify":
                raise ValueError("Cart probing is only available for Shopify watches.")
        watch_id, created = self.db.add_watch(
            source_id, product_id, product_url, variant_id, label,
            cart_probe_enabled=cart_probe_enabled,
        )
        if cart_probe_enabled:
            self.db.mark_watch_check_due(source_id, product_url, variant_id)
        if self.running:
            self._wake_event.set()
        return {"ok": True, "created": created, "watch_id": str(watch_id)}

    def set_cart_probe(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Toggle one watched Shopify product's anonymous cart probe."""
        if not isinstance(payload, dict):
            raise ValueError("Cart probe update must be an object.")
        watch_id = str(payload.get("watch_id") or "").strip()
        if not watch_id:
            raise ValueError("Choose a watch before changing its cart probe.")
        enabled = _bool(payload.get("enabled"), "Cart probe")
        watch = self.db.watch(watch_id)
        if watch is None:
            raise ValueError("The selected watch no longer exists.")
        source = self.db.source(str(watch.get("source_id") or ""))
        if enabled and (not source or str(source.get("platform") or "").lower() != "shopify"):
            raise ValueError("Cart probing is only available for Shopify watches.")
        if not self.db.set_cart_probe_enabled(watch_id, enabled):
            raise ValueError("The selected watch no longer exists.")
        if enabled:
            self.db.mark_watch_check_due(
                str(watch["source_id"]), str(watch["product_url"]), str(watch.get("variant_id") or "")
            )
        if self.running:
            self._wake_event.set()
        return {"ok": True, "watch_id": watch_id, "cart_probe_enabled": enabled}

    def remove_watch(self, watch_id: str | int) -> dict[str, Any]:
        removed = self.db.remove_watch(watch_id)
        return {"ok": True, "removed": removed}

    def check_now(self, source_id: str = "") -> dict[str, Any]:
        selected = str(source_id or "").strip()
        if selected:
            source = self.db.source(selected)
            if not source:
                raise ValueError("Unknown source.")
            if not source.get("enabled", True):
                raise ValueError(source.get("disabled_reason") or "Enable this source before checking it.")
            if source.get("platform") == "invision":
                raise ValueError("Forum sections are checked through the paired browser extension.")
        request_id = str(uuid.uuid4())
        try:
            self._manual_queue.put_nowait({"request_id": request_id, "source_id": selected})
        except queue.Full:
            return {"ok": False, "queued": False, "error": "A manual check is already waiting in the queue."}
        self._wake_event.set()
        if not self.running:
            self.start()
        return {"ok": True, "queued": True, "request_id": request_id}

    def send_test_alert(self) -> dict[str, Any]:
        try:
            webhook = self._webhook_url()
        except Exception:
            return {"ok": False, "queued": False, "error": "The saved Discord webhook cannot be unlocked on this Windows account."}
        if not webhook:
            return {"ok": False, "queued": False, "error": "Save a Discord webhook before sending a test alert."}
        now = utc_now()
        event = {
            "kind": "test_alert", "created_at": now, "title": "Premium Watch test alert",
            "summary": "Discord delivery is connected to this separate Premium Watch channel.",
            "url": "", "details": {"detail": "This message was sent because you clicked Test alert."},
        }
        outbox_id = self.db.insert_test_outbox(event)
        if self.running:
            self._wake_event.set()
        else:
            threading.Thread(
                target=self._deliver_test_outbox, args=(outbox_id,),
                name="PremiumWatchTestAlert", daemon=True,
            ).start()
        return {"ok": True, "queued": True, "outbox_id": outbox_id}

    def begin_forum_login(self) -> dict[str, Any]:
        method = getattr(self.providers, "begin_forum_login", None)
        if not callable(method):
            return {"ok": False, "error": "Interactive forum sign-in is unavailable in this provider build."}
        return method()

    def finish_forum_login(self) -> dict[str, Any]:
        method = getattr(self.providers, "finish_forum_login", None)
        if not callable(method):
            return {"ok": False, "error": "Interactive forum sign-in is unavailable in this provider build."}
        return method()

    def forum_login_status(self) -> dict[str, Any]:
        method = getattr(self.providers, "forum_login_status", None)
        if not callable(method):
            return {"available": False, "authenticated": False, "message": "Interactive forum sign-in is unavailable in this provider build."}
        return method()

    def _validate_source(self, payload: dict[str, Any], *, allow_missing_platform_registry: bool = False) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("Source must be an object.")
        source_id = str(payload.get("id") or "").strip().lower()
        if not _SOURCE_ID.fullmatch(source_id):
            raise ValueError("Source ID must use lowercase letters, digits, underscores, or hyphens.")
        name = " ".join(str(payload.get("name") or "").split())
        if not name or len(name) > 120:
            raise ValueError("Source name is required and must be at most 120 characters.")
        platform = str(payload.get("platform") or "").strip().lower()
        supported = getattr(self.providers, "supported_platforms", None)
        if supported:
            supported_set = {str(value).lower() for value in supported}
        else:
            supported_set = _FALLBACK_PLATFORMS
        if platform not in supported_set and not allow_missing_platform_registry:
            raise ValueError("Source platform is not supported by the installed provider registry.")
        if platform not in supported_set and allow_missing_platform_registry:
            # Seeded sources may be loaded before a provider module is importable.
            if platform not in _FALLBACK_PLATFORMS:
                raise ValueError("Source platform is not supported by the installed provider registry.")
        url = security.validate_public_http_url(str(payload.get("url") or ""))
        if urlsplit(url).scheme.lower() != "https":
            raise ValueError("Retailer source URLs must use HTTPS.")
        enabled = _bool(payload.get("enabled", True), "Enabled")
        discovery_enabled = _bool(payload.get("discovery_enabled", True), "Discovery enabled")
        discovery_interval = _interval(payload.get("discovery_interval", 900), "Discovery interval", 60, 86_400)
        product_interval = _interval(payload.get("product_interval", 300), "Product interval", 15, 86_400)
        include = _keywords(payload.get("include_keywords", []), "Include keywords")
        exclude = _keywords(payload.get("exclude_keywords", []), "Exclude keywords")
        normalized = {
            "id": source_id,
            "name": name,
            "platform": platform,
            "url": url,
            "enabled": enabled,
            "discovery_enabled": discovery_enabled,
            "discovery_interval": discovery_interval,
            "product_interval": product_interval,
            "include_keywords": include,
            "exclude_keywords": exclude,
        }
        if payload.get("currency_hint") not in (None, ""):
            currency_hint = str(payload["currency_hint"]).strip().upper()
            if not re.fullmatch(r"[A-Z]{3}", currency_hint):
                raise ValueError("Currency hint must be a three-letter ISO code.")
            normalized["currency_hint"] = currency_hint
        if payload.get("disabled_reason"):
            normalized["disabled_reason"] = " ".join(str(payload["disabled_reason"]).split())[:240]
        return normalized

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            handled_manual = False
            if not self._ownership_allowed("heartbeat"):
                self._wake_event.wait(2.0)
                self._wake_event.clear()
                continue
            # Deliver already-due alerts before a potentially long provider cycle.
            # Keep the post-cycle drain below for alerts created by this cycle.
            self._drain_outbox()
            if self._stop_event.is_set():
                break
            try:
                request = self._manual_queue.get_nowait()
            except queue.Empty:
                request = None
            if request:
                handled_manual = True
                self._run_cycle(source_id=request["source_id"], force=True)
            else:
                self._run_cycle(force=False)
            self._drain_outbox()
            if self._stop_event.is_set():
                break
            self._wake_event.clear()
            timeout = 1.0 if handled_manual else self._seconds_to_next_cycle()
            self._wake_event.wait(max(0.2, min(5.0, timeout)))

    def _stamp_observation_context(self, source: dict[str, Any], observation: dict[str, Any]) -> dict[str, Any]:
        market = observation.get("market_context") or source.get("market_context")
        if market not in (None, ""):
            observation["market_context"] = market
            context_key = "market:" + Database._canonical_digest(market)
        else:
            observation.pop("market_context", None)
            context_key = "executor:" + self.execution_context_id
        observation["observer_context"] = self.execution_context_id
        observation["comparison_context"] = context_key
        return observation

    @staticmethod
    def _time_budget(value: float, *, name: str, maximum: float = 600.0) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 1 <= float(value) <= maximum:
            raise ValueError(f"{name} must be between 1 and {int(maximum)} seconds.")
        return float(value)

    @staticmethod
    def _hosted_task_cursor(tasks: list[dict[str, Any]], cursor: str | None) -> list[dict[str, Any]]:
        ordered = sorted(tasks, key=lambda item: item["key"])
        if not cursor or not ordered:
            return ordered
        split = next((index for index, task in enumerate(ordered) if task["key"] > cursor), 0)
        return ordered[split:] + ordered[:split]

    @staticmethod
    def _split_run_cursor(cursor: str | None, valid_task_keys: set[str]) -> tuple[str, str]:
        """Decode the ordinary task cursor and the independent cart rotation key.

        The composite spelling stays within the hosted runner's existing safe
        cursor alphabet, while old one-part cursors remain valid.
        """
        value = cursor if isinstance(cursor, str) else ""
        match = re.fullmatch(r"(?P<task>[dw]:[A-Za-z0-9_-]{1,160})_cartw_(?P<watch_id>\d{1,16})", value)
        if match and match.group("task") in valid_task_keys:
            return match.group("task"), "w:" + match.group("watch_id").zfill(12)
        return value, ""

    @staticmethod
    def _join_run_cursor(task_cursor: str, cart_cursor: str) -> str:
        if task_cursor and re.fullmatch(r"w:\d{1,16}", cart_cursor or ""):
            return f"{task_cursor}_cartw_{cart_cursor[2:]}"
        return task_cursor

    @staticmethod
    def _market_context_id(source: dict[str, Any], observations: Iterable[dict[str, Any]] = ()) -> str:
        values = []
        if source.get("market_context") not in (None, ""):
            values.append(source["market_context"])
        for observation in observations:
            if observation.get("market_context") not in (None, ""):
                values.append(observation["market_context"])
        unique = {Database._canonical_digest(value) for value in values}
        if len(unique) == 1:
            return next(iter(unique))[:16]
        return "mixed" if unique else "unknown"

    @staticmethod
    def _verification_error_code(exc: BaseException) -> str:
        if getattr(exc, "hosted_error_code", "") == "source_empty":
            return "source_empty"
        if isinstance(exc, TimeoutError):
            return "timeout"
        if isinstance(exc, ValueError):
            return "invalid_provider_result"
        if isinstance(exc, ProviderError):
            return "provider_error"
        code = str(getattr(exc, "code", "") or "").strip().lower()
        return code if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code) else "provider_check_failed"

    def _notify_checkpoint(
        self, callback: Callable[[dict[str, Any]], Any] | None, metadata: dict[str, Any],
    ) -> bool:
        if callback is None:
            return True
        try:
            return callback(metadata) is not False
        except Exception:
            return False

    def _cart_probe_time_allowance(self, watch: dict[str, Any]) -> float:
        if not watch.get("cart_probe_enabled") or str((self.db.source(watch["source_id"]) or {}).get("platform") or "").lower() != "shopify":
            return 15.0
        # Reserve a bounded product read, the full add/read/clear/verify
        # sequence, and cleanup margin before starting this indivisible unit.
        return 24.0 + _CART_PROBE_SAFE_SECONDS + 20.0

    def run_once(
        self, *, source_ids: Iterable[str] | None = None, max_seconds: float = 180,
        max_checks: int = 20, cursor: str | None = None, deliver: bool = True,
        checkpoint_callback: Callable[[dict[str, Any]], Any] | None = None,
    ) -> dict[str, Any]:
        """Run bounded due work once, rotating the cursor to avoid starvation."""
        budget = self._time_budget(max_seconds, name="Run budget")
        if isinstance(max_checks, bool) or not isinstance(max_checks, int) or not 1 <= max_checks <= 500:
            raise ValueError("Maximum checks must be between 1 and 500.")
        sources = {
            row["id"]: row for row in self.db.sources()
            if str(row.get("platform", "")).lower() in HOSTED_PROVIDER_PLATFORMS
        }
        if source_ids is None:
            selected = set(sources)
        else:
            selected = set(source_ids)
            if any(not isinstance(item, str) for item in selected) or not selected <= set(sources):
                raise ValueError("Hosted source selection contains an ineligible source ID.")
        if not self.hosted_mode:
            selected = {sid for sid in selected if bool(sources[sid].get("enabled", True))}
        watches = [row for row in self.db.watches() if row["source_id"] in selected]
        now = datetime.now(timezone.utc)
        tasks: list[dict[str, Any]] = []
        for sid in sorted(selected):
            source = sources[sid]
            if source.get("discovery_enabled", True) and _is_due(source.get("next_discovery_at"), now):
                tasks.append({"key": "d:" + sid, "kind": "discovery", "source_id": sid})
        for watch in watches:
            check = self.db.check_state(watch["source_id"], watch["product_url"], watch["variant_id"])
            if _is_due(check.get("next_due_at"), now):
                tasks.append({"key": "w:" + str(int(watch["id"])).zfill(12), "kind": "watch", "source_id": watch["source_id"], "watch_id": int(watch["id"]), "watch": watch})
        valid_task_keys = {"d:" + sid for sid in selected}
        valid_task_keys.update("w:" + str(int(watch["id"])).zfill(12) for watch in watches)
        task_cursor, cart_rotation_cursor = self._split_run_cursor(cursor, valid_task_keys)
        tasks = self._hosted_task_cursor(tasks, task_cursor)
        # A due cart probe is an indivisible add/read/clear/verify unit. Give
        # one due opted-in Shopify watch the first slot in each fair slice. Its
        # rotation cursor is independent from the ordinary task cursor because
        # later discovery work can otherwise overwrite the cart position.
        cart_tasks = sorted((
            task for task in tasks
            if task["kind"] == "watch"
            and task["watch"].get("cart_probe_enabled")
            and str(sources[task["source_id"]].get("platform") or "").lower() == "shopify"
        ), key=lambda item: item["key"])
        if cart_rotation_cursor and cart_tasks:
            cart_split = next((index for index, task in enumerate(cart_tasks) if task["key"] > cart_rotation_cursor), 0)
            cart_tasks = cart_tasks[cart_split:] + cart_tasks[:cart_split]
        priority_cart = cart_tasks[0] if cart_tasks else None
        cart_index = tasks.index(priority_cart) if priority_cart is not None else None
        if cart_index is not None and cart_index > 0:
            tasks = [tasks[cart_index], *tasks[:cart_index], *tasks[cart_index + 1:]]
        deadline = time.monotonic() + budget
        scan_deadline = deadline - (_RUN_ONCE_DELIVERY_RESERVE_SECONDS if deliver else 0.0)
        processed = discovered = observed = delivered = 0
        last_task_cursor = task_cursor
        last_cart_cursor = cart_rotation_cursor
        last_cursor = self._join_run_cursor(last_task_cursor, last_cart_cursor)
        due_by_source: dict[str, int] = {}
        for task in tasks:
            due_by_source[task["source_id"]] = due_by_source.get(task["source_id"], 0) + 1
        result_by_source: dict[str, dict[str, Any]] = {
            sid: {
                "source_id": sid, "status": "complete", "error_code": "", "discovery": "not_due",
                "attempted_tasks": 0, "watches_checked": 0, "observations": 0,
            }
            for sid in sorted(selected)
        }
        status = "complete"
        stop_reason = ""

        if not self._ownership_allowed("run_once_start"):
            return {"status": "ownership_lost", "stop_reason": "ownership_lost", "checked_at": utc_now(), "processed": 0, "discovered": 0, "observed": 0, "delivered": 0, "uncertain_alert_count": self.db.uncertain_outbox_count(), "cursor": last_cursor, "source_results": list(result_by_source.values())}
        if not self._cycle_lock.acquire(blocking=False):
            return {"status": "busy", "stop_reason": "busy", "checked_at": utc_now(), "processed": 0, "discovered": 0, "observed": 0, "delivered": 0, "uncertain_alert_count": self.db.uncertain_outbox_count(), "cursor": last_cursor, "source_results": list(result_by_source.values())}
        try:
            for task in tasks:
                if self._stop_event.is_set():
                    status = "paused"
                    stop_reason = "paused"
                    break
                allowance = self._cart_probe_time_allowance(task["watch"]) if task["kind"] == "watch" else 10.0
                if processed >= max_checks or scan_deadline - time.monotonic() < allowance:
                    status = "partial"
                    stop_reason = "budget_exhausted"
                    break
                if not self._ownership_allowed("scan_poll"):
                    status = "ownership_lost"
                    stop_reason = "ownership_lost"
                    break
                sid = task["source_id"]
                outcome = result_by_source[sid]
                outcome["attempted_tasks"] += 1
                self._last_unit_error_code = ""
                if task["kind"] == "discovery":
                    count = self._discover(sources[sid], deadline=scan_deadline)
                    if count is None:
                        outcome["discovery"] = "failed"
                        error_code = self._last_unit_error_code or "discovery_failed"
                    else:
                        outcome["discovery"] = "complete"
                        discovered += count
                        error_code = ""
                else:
                    count = self._check_one(sources[sid], task["watch"], deadline=scan_deadline)
                    if count is None:
                        error_code = self._last_unit_error_code or "watch_check_failed"
                    else:
                        outcome["watches_checked"] += 1
                        outcome["observations"] += count
                        observed += count
                        error_code = ""
                if error_code == "ownership_lost" or not self._ownership_allowed("scan_checkpoint"):
                    status = "ownership_lost"
                    stop_reason = "ownership_lost"
                    break
                if error_code:
                    outcome["status"] = "partial"
                    outcome["error_code"] = error_code
                    status = "partial"
                if not self._ownership_allowed("scan_checkpoint"):
                    status = "ownership_lost"
                    stop_reason = "ownership_lost"
                    break
                processed += 1
                last_task_cursor = task["key"]
                if (
                    task["kind"] == "watch"
                    and task["watch"].get("cart_probe_enabled")
                    and str(sources[sid].get("platform") or "").lower() == "shopify"
                ):
                    last_cart_cursor = task["key"]
                last_cursor = self._join_run_cursor(last_task_cursor, last_cart_cursor)
                if not self._notify_checkpoint(checkpoint_callback, {
                    "phase": "scan_checkpoint", "cursor": last_cursor, "processed": processed,
                    "discovered": discovered, "observed": observed, "source_id": sid,
                    "watch_id": task.get("watch_id"),
                }):
                    status = "partial"
                    stop_reason = "checkpoint_failed"
                    break
            for sid, total in due_by_source.items():
                outcome = result_by_source[sid]
                if outcome["status"] == "complete" and outcome["discovery"] == "failed":
                    outcome["status"] = "partial"
                completed_for_source = 0
                for task in tasks[:processed]:
                    completed_for_source += int(task["source_id"] == sid)
                if completed_for_source < total:
                    outcome["status"] = "partial"
                    if not outcome["error_code"]:
                        outcome["error_code"] = stop_reason or "partial_run"
            can_deliver = status in {"complete", "partial"} and stop_reason not in {"ownership_lost", "paused", "checkpoint_failed"}
            if deliver and can_deliver and deadline - time.monotonic() >= 15.0:
                delivered = self._deliver_outbox(
                    deadline=deadline, hosted_only=self.hosted_mode,
                    checkpoint_callback=checkpoint_callback, cursor=last_cursor,
                    progress={"processed": processed, "discovered": discovered, "observed": observed},
                )
                if getattr(self, "_last_delivery_status", "complete") != "complete":
                    status = "partial"
                    stop_reason = getattr(self, "_last_delivery_status", "delivery_incomplete")
        finally:
            self._cycle_lock.release()
        return {
            "status": status, "stop_reason": stop_reason, "checked_at": utc_now(), "processed": processed,
            "discovered": discovered, "observed": observed, "delivered": delivered,
            "uncertain_alert_count": self.db.uncertain_outbox_count(),
            "cursor": last_cursor, "source_results": list(result_by_source.values()),
        }

    def verify_hosted_sources(
        self, source_ids: Iterable[str], *, max_seconds: float = 180, max_checks: int = 20,
        cursor: str | None = None,
        completed_task_results: Iterable[dict[str, Any]] = (),
        checkpoint_callback: Callable[[dict[str, Any]], Any] | None = None,
    ) -> dict[str, Any]:
        """Read-only provider compatibility check with task-level resumable progress."""
        budget = self._time_budget(max_seconds, name="Verification budget")
        if isinstance(max_checks, bool) or not isinstance(max_checks, int) or not 1 <= max_checks <= 500:
            raise ValueError("Maximum verification checks must be between 1 and 500.")
        candidates = {
            row["id"]: row for row in self.db.sources()
            if str(row.get("platform", "")).lower() in HOSTED_PROVIDER_PLATFORMS
        }
        selected = set(source_ids)
        if any(not isinstance(item, str) for item in selected) or not selected <= set(candidates):
            raise ValueError("Verification selection contains an ineligible source ID.")
        tasks: list[dict[str, Any]] = []
        for sid in sorted(selected):
            source = candidates[sid]
            # Verification is read-only and must prove the public provider even
            # when routine discovery is intentionally disabled in local config.
            tasks.append({"key": "d:" + sid, "kind": "discovery", "source_id": sid})
            for watch in self.db.watches():
                if watch["source_id"] == sid:
                    tasks.append({"key": "w:" + str(int(watch["id"])).zfill(12), "kind": "watch", "source_id": sid, "watch": watch})
        if len(tasks) > 500:
            raise ValueError("Verification task set exceeds the safe progress limit.")
        tasks_by_key = {task["key"]: task for task in tasks}
        if len(tasks_by_key) != len(tasks):
            raise ValueError("Verification task identities are not unique.")

        coverage_keys = {"discovered_products", "discovered_variants", "watches_checked", "observations"}
        try:
            prior_rows = list(completed_task_results)
        except TypeError as exc:
            raise ValueError("Verification task progress must be a list.") from exc
        if len(prior_rows) > 500:
            raise ValueError("Verification task progress exceeds the safe limit.")
        task_results: dict[str, dict[str, Any]] = {}
        task_fields = {"task_key", "source_id", "task_kind", "passed", "error_code", "coverage", "market_context_id", "checked_at"}
        for item in prior_rows:
            if not isinstance(item, dict) or set(item) != task_fields:
                raise ValueError("Verification task progress contains unsupported fields.")
            key = item.get("task_key")
            task = tasks_by_key.get(key) if isinstance(key, str) else None
            if task is None or key in task_results:
                raise ValueError("Verification task progress does not match the current selection.")
            if item.get("source_id") != task["source_id"] or item.get("task_kind") != task["kind"]:
                raise ValueError("Verification task progress identity does not match.")
            if type(item.get("passed")) is not bool:
                raise ValueError("Verification task progress has an invalid result.")
            error_code = item.get("error_code")
            if not isinstance(error_code, str) or (error_code and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", error_code) is None):
                raise ValueError("Verification task progress has an invalid error code.")
            if item["passed"] and error_code not in {"", "none"}:
                raise ValueError("Verification task result and error code disagree.")
            if not item["passed"] and error_code in {"", "none"}:
                raise ValueError("Verification task result and error code disagree.")
            error_code = "" if item["passed"] else error_code
            coverage = item.get("coverage")
            if not isinstance(coverage, dict) or set(coverage) != coverage_keys:
                raise ValueError("Verification task progress has invalid coverage.")
            normalized_coverage = {}
            for name, count in coverage.items():
                if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= 100_000:
                    raise ValueError("Verification task progress has invalid coverage.")
                normalized_coverage[name] = count
            context_id = item.get("market_context_id")
            if not isinstance(context_id, str) or not (
                context_id in {"unknown", "mixed"} or re.fullmatch(r"[0-9a-f]{16}", context_id)
            ):
                raise ValueError("Verification task progress has an invalid market context.")
            checked_at = item.get("checked_at")
            if not isinstance(checked_at, str) or _parse_time(checked_at) is None:
                raise ValueError("Verification task progress has an invalid checked time.")
            task_results[key] = {
                "task_key": key, "source_id": task["source_id"], "task_kind": task["kind"],
                "passed": item["passed"], "error_code": error_code,
                "coverage": normalized_coverage, "market_context_id": context_id,
                "checked_at": checked_at,
            }

        # Only prior successful units are skipped. A failed unit is retried on
        # the next bounded invocation, while successful catalog/watch reads do
        # not have to be repeated to finish the current configuration revision.
        pending_tasks = [task for task in tasks if not task_results.get(task["key"], {}).get("passed")]
        pending_tasks = self._hosted_task_cursor(pending_tasks, cursor)
        deadline = time.monotonic() + budget
        status = "complete"
        stop_reason = ""
        checked = 0
        last_cursor = cursor or ""
        if not self._ownership_allowed("verify_start"):
            return {"status": "ownership_lost", "checked_at": utc_now(), "cursor": last_cursor, "task_results": list(task_results.values()), "completed_task_keys": [], "sources": []}
        if self.providers is None:
            status = "error"
            stop_reason = "provider_registry_unavailable"
            now = utc_now()
            for task in pending_tasks:
                task_results[task["key"]] = {
                    "task_key": task["key"], "source_id": task["source_id"], "task_kind": task["kind"],
                    "passed": False, "error_code": "provider_registry_unavailable",
                    "coverage": {name: 0 for name in coverage_keys},
                    "market_context_id": self._market_context_id(candidates[task["source_id"]]),
                    "checked_at": now,
                }
        for task in (pending_tasks if self.providers is not None else []):
            if checked >= max_checks or deadline - time.monotonic() < 10.0:
                status = "partial"
                stop_reason = "budget_exhausted"
                break
            if not self._ownership_allowed("verify_poll"):
                status = "ownership_lost"
                stop_reason = "ownership_lost"
                break
            sid = task["source_id"]
            source = candidates[sid]
            context_observations: list[dict[str, Any]] = []
            coverage = {name: 0 for name in coverage_keys}
            task_error_code = ""
            try:
                if task["kind"] == "discovery":
                    with self._provider_deadline_scope(deadline):
                        rows = self.providers.discover(source)
                    if not isinstance(rows, list):
                        raise ProviderError("Provider returned an invalid discovery result.")
                    normalized = [normalize_product(item, source=source) for item in rows]
                    if not normalized:
                        raise _VerificationSourceEmpty("Public discovery returned no products.")
                    coverage["discovered_products"] = len(normalized)
                    coverage["discovered_variants"] = sum(len(variants) for _, variants in normalized)
                    context_observations.extend(observation for _, variants in normalized for observation in variants)
                else:
                    watch = task["watch"]
                    with self._provider_deadline_scope(deadline):
                        rows = self.providers.check(source, watch["product_url"], watch.get("variant_id", ""))
                    if not isinstance(rows, list) or not rows:
                        raise ProviderError("Provider returned no observations for this product.")
                    normalized = [normalize_observation(item, source=source) for item in rows]
                    product_ids = {item["product_id"] for item in normalized}
                    if len(product_ids) != 1 or (watch["product_id"] and watch["product_id"] not in product_ids):
                        raise ProviderError("Provider returned a different product for this watch.")
                    if watch["variant_id"] and not any(item["variant_id"] == watch["variant_id"] for item in normalized):
                        raise ProviderError("The selected edition was not present in the provider response.")
                    coverage["watches_checked"] = 1
                    coverage["observations"] = len(normalized)
                    context_observations.extend(normalized)
            except Exception as exc:
                if any(cls.__name__ == "ProviderDeadlineExceeded" for cls in type(exc).__mro__):
                    if not self._ownership_allowed("verify_checkpoint"):
                        status = "ownership_lost"
                        stop_reason = "ownership_lost"
                    else:
                        status = "partial"
                        stop_reason = "budget_exhausted"
                    break
                task_error_code = self._verification_error_code(exc)
            if not self._ownership_allowed("verify_checkpoint"):
                status = "ownership_lost"
                stop_reason = "ownership_lost"
                break
            task_result = {
                "task_key": task["key"], "source_id": sid, "task_kind": task["kind"],
                "passed": not task_error_code, "error_code": task_error_code,
                "coverage": coverage,
                "market_context_id": self._market_context_id(source, context_observations),
                "checked_at": utc_now(),
            }
            task_results[task["key"]] = task_result
            checked += 1
            last_cursor = task["key"]
            current_source_result = self._verification_source_result(sid, tasks, task_results, stop_reason="")
            callback_data: dict[str, Any] = {
                "phase": "verify_checkpoint", "cursor": last_cursor, "processed": checked,
                "source_id": sid, "task_result": task_result,
            }
            if current_source_result is not None and self._verification_source_complete(sid, tasks, task_results):
                callback_data["source_complete"] = True
                callback_data["source_result"] = current_source_result
            if not self._notify_checkpoint(checkpoint_callback, {
                **callback_data,
            }):
                status = "partial"
                stop_reason = "checkpoint_failed"
                break

        source_results = [
            row for sid in sorted(selected)
            if (row := self._verification_source_result(sid, tasks, task_results, stop_reason=stop_reason)) is not None
        ]
        completed_keys = sorted(key for key, row in task_results.items() if row["passed"])
        if status == "complete" and any(not row["passed"] for row in source_results):
            status = "partial"
            stop_reason = "source_incomplete"
        return {
            "status": status, "stop_reason": stop_reason, "checked_at": utc_now(), "cursor": last_cursor,
            "task_results": [task_results[key] for key in sorted(task_results)],
            "completed_task_keys": completed_keys, "sources": source_results,
        }

    @staticmethod
    def _verification_source_complete(
        source_id: str, tasks: list[dict[str, Any]], task_results: dict[str, dict[str, Any]],
    ) -> bool:
        keys = [task["key"] for task in tasks if task["source_id"] == source_id]
        return bool(keys) and all(key in task_results for key in keys)

    @classmethod
    def _verification_source_result(
        cls, source_id: str, tasks: list[dict[str, Any]], task_results: dict[str, dict[str, Any]], *, stop_reason: str,
    ) -> dict[str, Any] | None:
        source_tasks = [task for task in tasks if task["source_id"] == source_id]
        rows = [task_results[task["key"]] for task in source_tasks if task["key"] in task_results]
        if not rows:
            return None
        complete = cls._verification_source_complete(source_id, tasks, task_results)
        failures = [row for row in rows if not row["passed"]]
        coverage = {
            key: sum(row["coverage"][key] for row in rows)
            for key in ("discovered_products", "discovered_variants", "watches_checked", "observations")
        }
        contexts = {row["market_context_id"] for row in rows}
        if contexts == {"unknown"}:
            context_id = "unknown"
        elif "mixed" in contexts or "unknown" in contexts or len(contexts) > 1:
            context_id = "mixed"
        elif contexts:
            context_id = next(iter(contexts))
        else:
            context_id = "unknown"
        checked_at = max(rows, key=lambda row: _parse_time(row["checked_at"]) or datetime.min.replace(tzinfo=timezone.utc))["checked_at"]
        return {
            "source_id": source_id,
            "passed": complete and not failures,
            "checked_at": checked_at,
            "coverage": coverage,
            "error_code": failures[0]["error_code"] if failures else ("" if complete else stop_reason or "verification_incomplete"),
            "market_context_id": context_id,
        }

    def _run_cycle(self, *, source_id: str = "", force: bool = False) -> None:
        if not self._cycle_lock.acquire(blocking=False):
            return
        try:
            now = datetime.now(timezone.utc)
            for source in self.db.sources():
                if self._stop_event.is_set():
                    break
                if source_id and source["id"] != source_id:
                    continue
                if not bool(source.get("enabled", True)):
                    if source.get("discovery_status") != "disabled":
                        self.db.update_source_health(
                            source["id"], discovery_status="disabled",
                        )
                    continue
                # Invision sources are owned by the paired browser bridge. Never invoke the
                # ordinary HTTP or Playwright provider from the polling worker for them.
                if source.get("platform") == "invision":
                    continue
                due = bool(source.get("discovery_enabled", True)) and (force or _is_due(source.get("next_discovery_at"), now))
                if due:
                    self._discover(source)
                    if self._last_unit_error_code in {"ownership_lost", "checkpoint_failed"}:
                        break
                self._check_source_watches(source, force=force)
                if self._last_unit_error_code in {"ownership_lost", "checkpoint_failed"}:
                    break
            self._last_cycle_at = utc_now()
            # This is a local UI timestamp, not an accepted monitoring
            # checkpoint; an idle cycle must not read or write the remote ledger.
            self.db.set_state("last_cycle_at", self._last_cycle_at)
        finally:
            self._cycle_lock.release()

    def _discover(self, source: dict[str, Any], *, deadline: float | None = None) -> int | None:
        self._last_unit_error_code = ""
        if not self._ownership_allowed("discovery_poll"):
            self._last_unit_error_code = "ownership_lost"
            return None
        if self.providers is None:
            exc = ProviderError(self._provider_error or "Provider registry is unavailable.")
            self._discovery_failed(source, exc, _parse_time(source.get("next_discovery_at")))
            self._last_unit_error_code = self._verification_error_code(exc)
            return None
        try:
            with self._provider_deadline_scope(deadline):
                rows = self.providers.discover(source)
            if not isinstance(rows, list):
                raise ProviderError("Provider returned an invalid discovery result.")
            # Validate every row before changing the accepted baseline.
            normalized = [normalize_product(item, source=source) for item in rows]
            normalized = [
                (product, [self._stamp_observation_context(source, observation) for observation in variants])
                for product, variants in normalized
            ]
            completed_at = utc_now()
            # Accepted catalog rows, their alerts, and discovery health commit as one unit.
            # If any write fails, the prior complete baseline stays intact and the scan retries.
            with self.db.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                count = self._apply_discovery(source, normalized, completed_at, connection=connection)
                if not self._ownership_allowed("discovery_commit"):
                    raise _ServiceOwnershipLost()
            if not self._controller_after_local_work({
                "phase": "discovery_checkpoint", "source_id": source["id"], "discovered": len(normalized),
            }):
                self._last_unit_error_code = "checkpoint_failed"
                return None
            return len(normalized)
        except _ServiceOwnershipLost:
            self._last_unit_error_code = "ownership_lost"
            return None
        except Exception as exc:
            self._discovery_failed(source, exc, _parse_time(source.get("next_discovery_at")))
            self._last_unit_error_code = self._verification_error_code(exc)
            return None

    def _apply_discovery(
        self, source: dict[str, Any], normalized: list[tuple[dict[str, Any], list[dict[str, Any]]]],
        completed_at: str, *, connection: Any, was_baselined_override: bool | None = None,
        allow_events: bool = True,
    ) -> int:
        settings = self.db.settings(connection=connection)
        latest_source = self.db.source(source["id"], connection=connection) or source
        was_baselined = bool(latest_source.get("baseline_complete")) if was_baselined_override is None else was_baselined_override
        next_at = _after_seconds(completed_at, int(source.get("discovery_interval", 900)))
        new_events = 0
        for product, variants in normalized:
            is_new = self.db.upsert_product(source["id"], product, completed_at, connection=connection)
            if was_baselined and is_new and allow_events:
                event = listing_event(source, product, completed_at)
                inserted = self.db.insert_event(
                    event,
                    dict(event) if settings["auto_discovery_alerts"] else None,
                    connection=connection,
                )
                new_events += int(inserted is not None)
            for observation in variants:
                self._register_variant(source, product, observation, is_new, connection=connection)
                self.db.upsert_catalog_observation(source["id"], observation, connection=connection)
        self.db.update_source_health(
            source["id"], baseline_complete=True,
            last_discovery_at=completed_at, next_discovery_at=next_at, discovery_failures=0,
            discovery_status="healthy", discovery_last_error="",
            discovery_last_success_at=completed_at, connection=connection,
        )
        return new_events

    def _discovery_failed(self, source: dict[str, Any], exc: BaseException, next_old: datetime | None) -> None:
        if not self._ownership_allowed("discovery_failure_checkpoint"):
            return
        current = self.db.source(source["id"]) or source
        failures = int(current.get("discovery_failures", 0)) + 1
        base = max(60, int(source.get("discovery_interval", 900)))
        delay = min(base * (2 ** min(failures - 1, 8)), 21_600)
        now = utc_now()
        self.db.update_source_health(
            source["id"], next_discovery_at=_after_seconds(now, delay),
            discovery_failures=failures, discovery_status="error", discovery_last_error=safe_error(exc),
        )

    def _check_source_watches(self, source: dict[str, Any], *, force: bool) -> None:
        for watch in self.db.watches():
            if self._stop_event.is_set():
                return
            if watch["source_id"] != source["id"]:
                continue
            check = self.db.check_state(source["id"], watch["product_url"], watch["variant_id"])
            if force or _is_due(check.get("next_due_at"), datetime.now(timezone.utc)):
                self._check_one(source, watch)
                if self._last_unit_error_code in {"ownership_lost", "checkpoint_failed"}:
                    return

    def _check_one(self, source: dict[str, Any], watch: dict[str, Any], *, deadline: float | None = None) -> int | None:
        self._last_unit_error_code = ""
        if not self._ownership_allowed("watch_poll"):
            self._last_unit_error_code = "ownership_lost"
            return None
        source = self.db.source(str(source.get("id") or "")) or source
        watch = self.db.watch(watch.get("id", "")) or watch
        if self.providers is None:
            exc = ProviderError(self._provider_error or "Provider registry is unavailable.")
            self._check_failed(source, watch, exc)
            self._last_unit_error_code = self._verification_error_code(exc)
            return None
        try:
            with self._provider_deadline_scope(deadline):
                rows = self.providers.check(source, watch["product_url"], watch.get("variant_id", ""))
            if not isinstance(rows, list) or not rows:
                raise ProviderError("Provider returned no observations for this product.")
            normalized = [self._stamp_observation_context(source, normalize_observation(item, source=source)) for item in rows]
            product_ids = {item["product_id"] for item in normalized}
            if len(product_ids) != 1:
                raise ProviderError("Provider returned observations for more than one product.")
            product_id = next(iter(product_ids))
            if watch["product_id"] and watch["product_id"] != product_id:
                raise ProviderError("The product ID changed for this watch; the prior good observations were kept.")
            if watch["variant_id"] and not any(item["variant_id"] == watch["variant_id"] for item in normalized):
                raise ProviderError("The selected edition was not present in the complete provider response.")
            if not self._ownership_allowed("watch_provider_checkpoint"):
                self._last_unit_error_code = "ownership_lost"
                return None
            current_watch_for_probe = self.db.watch(watch["id"]) or watch
            cart_probe_by_variant = self._probe_watched_variants(
                source, current_watch_for_probe, normalized, deadline=deadline
            )
            if self._last_unit_error_code == "ownership_lost":
                self._last_unit_error_code = "ownership_lost"
                return None
            product = {
                "product_id": product_id,
                "title": normalized[0]["product_title"],
                "url": normalized[0]["url"],
                "image_url": normalized[0].get("image_url", ""),
            }
            completed_at = utc_now()
            interval = max(15, int(source.get("product_interval", 300)))
            next_at = _after_seconds(completed_at, interval)
            # Keep product, observation, transition, outbox, and baseline writes atomic.
            with self.db.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                current_watch = self.db.watch(watch["id"], connection=connection)
                if current_watch is None:
                    return 0
                current_source = self.db.source(source["id"], connection=connection) or source
                if current_watch["product_id"] and current_watch["product_id"] != product_id:
                    raise ProviderError("The product ID changed for this watch; the prior good observations were kept.")
                if current_watch["variant_id"] and not any(
                    item["variant_id"] == current_watch["variant_id"] for item in normalized
                ):
                    raise ProviderError("The selected edition was not present in the complete provider response.")
                product_is_new = self.db.upsert_product(source["id"], product, completed_at, connection=connection)
                self.db.update_watch_product(int(current_watch["id"]), product_id, connection=connection)
                initializing_watch_ids = (
                    {int(current_watch["id"])} if not current_watch.get("baseline_complete") else set()
                )
                for observation in normalized:
                    self.db.upsert_catalog_observation(source["id"], observation, connection=connection)
                    self._register_variant(
                        current_source, product, observation, product_is_new,
                        connection=connection,
                    )
                    self._record_observation(
                        current_source, observation, initialize_watch_ids=initializing_watch_ids,
                        cart_probe_by_variant=cart_probe_by_variant,
                        cart_probe_watch_id=int(current_watch["id"]),
                        connection=connection,
                    )
                if not current_watch.get("baseline_complete"):
                    self.db.complete_watch_baseline(int(current_watch["id"]), connection=connection)
                self.db.update_check(
                    source["id"], current_watch["product_url"], current_watch["variant_id"],
                    last_success_at=completed_at, next_due_at=next_at, failures=0, last_error="",
                    connection=connection,
                )
                self._refresh_source_after_check(source["id"], completed_at, connection=connection)
                if not self._ownership_allowed("watch_commit"):
                    raise _ServiceOwnershipLost()
            if not self._controller_after_local_work({
                "phase": "watch_checkpoint", "source_id": source["id"], "watch_id": int(watch["id"]),
                "observations": len(normalized),
            }):
                self._last_unit_error_code = "checkpoint_failed"
                return None
            return len(normalized)
        except _ServiceOwnershipLost:
            self._last_unit_error_code = "ownership_lost"
            return None
        except Exception as exc:
            self._check_failed(source, watch, exc)
            self._last_unit_error_code = self._verification_error_code(exc)
            return None

    @staticmethod
    def _waiting_cart_probe() -> dict[str, Any]:
        return normalize_cart_probe({
            "status": "waiting", "outcome": None, "accepted_quantity": None,
            "requested_quantity": _CART_PROBE_REQUEST_QUANTITY,
            "confirmed_at": None, "last_attempt_at": None, "error": None,
        })

    @staticmethod
    def _cart_probe_error_code(exc: BaseException) -> str:
        value = str(getattr(exc, "code", "cart_probe_failed") or "cart_probe_failed").strip().lower()
        return value if re.fullmatch(r"[a-z][a-z0-9_]{0,79}", value) else "cart_probe_failed"

    def _previous_cart_probe(self, watch_id: int, variant_id: str) -> dict[str, Any] | None:
        state = self.db.watch_state(watch_id, variant_id)
        if not isinstance(state, dict) or not isinstance(state.get("observation"), dict):
            return None
        stored = state["observation"]
        latest = stored.get("latest_observation") if isinstance(stored.get("latest_observation"), dict) else {}
        value = latest.get("cart_probe") if isinstance(latest, dict) else None
        if not isinstance(value, dict):
            comparison = stored.get("comparison") if isinstance(stored.get("comparison"), dict) else {}
            value = comparison.get("cart_probe") if isinstance(comparison, dict) else None
        return dict(value) if isinstance(value, dict) else None

    def _probe_watched_variants(
        self, source: dict[str, Any], watch: dict[str, Any], observations: list[dict[str, Any]],
        *, deadline: float | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Probe only opt-in Shopify watch variants; public observations remain unchanged."""
        if (
            not watch.get("cart_probe_enabled")
            or str(source.get("platform") or "").lower() != "shopify"
        ):
            return {}
        result: dict[str, dict[str, Any]] = {}
        watch_id = int(watch["id"])
        provider = getattr(self.providers, "probe_cart", None)
        for observation in observations:
            if deadline is not None and deadline - time.monotonic() < _CART_PROBE_SAFE_SECONDS:
                break
            variant_id = str(observation.get("variant_id") or "")
            if watch.get("variant_id") and variant_id != str(watch["variant_id"]):
                continue
            previous = self._previous_cart_probe(watch_id, variant_id)
            if observation.get("available") is not True:
                if previous and previous.get("confirmed_at"):
                    result[variant_id] = normalize_cart_probe({
                        **previous,
                        "status": "stale",
                        "error": "public_variant_unavailable",
                    })
                elif previous:
                    result[variant_id] = normalize_cart_probe({
                        **previous, "status": "waiting", "error": None,
                    })
                else:
                    result[variant_id] = self._waiting_cart_probe()
                continue
            if not self._ownership_allowed("cart_probe_claim"):
                self._last_unit_error_code = "ownership_lost"
                return result
            attempted_at = utc_now()
            if not self.db.claim_cart_probe(
                watch_id, variant_id, cooldown_seconds=_CART_PROBE_COOLDOWN_SECONDS, now=attempted_at,
            ):
                continue
            try:
                if not callable(provider):
                    raise ProviderError("Cart probe support is unavailable in this build.")
                raw = provider(
                    source, str(watch["product_url"]), variant_id,
                    requested_quantity=_CART_PROBE_REQUEST_QUANTITY,
                )
                if not isinstance(raw, dict):
                    raise ValueError("Cart probe returned an invalid result.")
                probe = normalize_cart_probe({
                    "status": "confirmed",
                    "outcome": raw.get("outcome"),
                    "accepted_quantity": raw.get("accepted_quantity"),
                    "requested_quantity": raw.get("requested_quantity"),
                    "confirmed_at": normalize_time(raw.get("observed_at"), default_now=False),
                    "last_attempt_at": attempted_at,
                    "error": None,
                    "market_context": raw.get("market_context", source.get("market_context")),
                })
                if not self._ownership_allowed("cart_probe_checkpoint"):
                    self.db.release_cart_probe_claim(watch_id, variant_id, attempted_at=attempted_at)
                    self._last_unit_error_code = "ownership_lost"
                    return result
                self.db.finish_cart_probe(watch_id, variant_id, success=True)
            except Exception as exc:
                if not self._ownership_allowed("cart_probe_failure_checkpoint"):
                    self.db.release_cart_probe_claim(watch_id, variant_id, attempted_at=attempted_at)
                    self._last_unit_error_code = "ownership_lost"
                    return result
                error_code = self._cart_probe_error_code(exc)
                if previous and previous.get("confirmed_at"):
                    probe = normalize_cart_probe({
                        "status": "stale",
                        "outcome": previous.get("outcome"),
                        "accepted_quantity": previous.get("accepted_quantity"),
                        "requested_quantity": previous.get("requested_quantity", _CART_PROBE_REQUEST_QUANTITY),
                        "confirmed_at": previous.get("confirmed_at"),
                        "last_attempt_at": attempted_at,
                        "error": error_code,
                    })
                else:
                    probe = normalize_cart_probe({
                        "status": "error", "outcome": None, "accepted_quantity": None,
                        "requested_quantity": _CART_PROBE_REQUEST_QUANTITY,
                        "confirmed_at": None, "last_attempt_at": attempted_at,
                        "error": error_code,
                    })
                self.db.finish_cart_probe(watch_id, variant_id, success=False, error_code=error_code)
            result[variant_id] = probe
        return result

    def _check_failed(self, source: dict[str, Any], watch: dict[str, Any], exc: BaseException) -> None:
        if not self._ownership_allowed("watch_failure_checkpoint"):
            return
        old = self.db.check_state(source["id"], watch["product_url"], watch["variant_id"])
        failures = int(old.get("failures", 0)) + 1
        base = max(15, int(source.get("product_interval", 300)))
        delay = min(base * (2 ** min(failures - 1, 8)), 21_600)
        error = safe_error(exc)
        self.db.update_check(
            source["id"], watch["product_url"], watch["variant_id"],
            next_due_at=_after_seconds(utc_now(), delay), failures=failures, last_error=error,
        )
        self.db.update_source_health(source["id"], status="warning", last_error=error)

    def _refresh_source_after_check(self, source_id: str, completed_at: str, *, connection: Any = None) -> None:
        source = self.db.source(source_id, connection=connection) or {}
        errors = [
            row for row in self.db.all_checks(connection=connection)
            if row.get("source_id") == source_id and row.get("last_error")
        ]
        if errors:
            self.db.update_source_health(
                source_id, status="warning", last_success_at=completed_at,
                last_error=str(errors[-1]["last_error"]), connection=connection,
            )
        elif source.get("baseline_complete"):
            self.db.update_source_health(
                source_id, status="healthy", last_success_at=completed_at, last_error="",
                connection=connection,
            )
        else:
            self.db.update_source_health(source_id, last_success_at=completed_at, connection=connection)

    def _record_observation(
        self, source: dict[str, Any], observation: dict[str, Any], *,
        initialize_watch_ids: set[int] | None = None,
        cart_probe_by_variant: dict[str, dict[str, Any]] | None = None,
        cart_probe_watch_id: int | None = None,
        connection: Any = None,
    ) -> None:
        initialize_watch_ids = initialize_watch_ids or set()
        cart_probe_by_variant = cart_probe_by_variant or {}
        signal = has_signal(observation)
        source_id = source["id"]
        product_id = observation["product_id"]
        watches = [
            row for row in self.db.watches(connection=connection)
            if row["source_id"] == source_id
            and (not row["product_id"] or row["product_id"] == product_id)
            and (not row["variant_id"] or row["variant_id"] == observation["variant_id"])
        ]
        settings = self.db.settings(connection=connection)
        for watch in watches:
            own_probe = None
            if (
                cart_probe_watch_id is not None
                and int(watch["id"]) == cart_probe_watch_id
                and bool(watch.get("cart_probe_enabled"))
            ):
                own_probe = cart_probe_by_variant.get(observation["variant_id"])
            if not watch.get("baseline_complete"):
                if int(watch["id"]) in initialize_watch_ids:
                    watch_observation = dict(observation)
                    if own_probe is not None:
                        watch_observation["cart_probe"] = own_probe
                    self.db.save_watch_state(
                        int(watch["id"]),
                        {
                            "variant_id": observation["variant_id"],
                            "observed_at": observation["observed_at"],
                            "comparison": merge_comparison_state(None, watch_observation),
                            "latest_observation": watch_observation,
                        },
                        connection=connection,
                    )
                continue
            previous_state = self.db.watch_state(
                int(watch["id"]), observation["variant_id"], connection=connection
            )
            stored = previous_state["observation"] if previous_state else None
            previous = (
                stored.get("comparison") if isinstance(stored, dict) and "comparison" in stored else stored
            )
            context_matches = previous is None or previous.get("comparison_context") == observation.get("comparison_context")
            comparison_previous = previous if context_matches else None
            previous_latest = (
                stored.get("latest_observation")
                if isinstance(stored, dict) and isinstance(stored.get("latest_observation"), dict)
                else {}
            )
            watch_observation = dict(observation)
            cart_probe = own_probe
            if cart_probe is None and context_matches and isinstance(previous_latest.get("cart_probe"), dict):
                cart_probe = previous_latest["cart_probe"]
            if cart_probe is not None:
                watch_observation["cart_probe"] = cart_probe
            current_comparison = (
                merge_comparison_state(comparison_previous, watch_observation)
                if signal else dict(comparison_previous or merge_comparison_state(None, watch_observation))
            )
            previous_low = None
            if comparison_previous and observation.get("currency") and watch.get("created_at") and signal:
                minimum = self.db.lowest_price_since(
                    source_id, product_id, observation["variant_id"], observation["currency"],
                    watch["created_at"], connection=connection,
                    comparison_context=observation.get("comparison_context"),
                )
                previous_low = minimum[0] if minimum else None
            if signal and comparison_previous:
                for event, should_notify in observation_events(
                    source, comparison_previous, current_comparison, previous_low=previous_low,
                    tracking_started_at=watch.get("created_at", ""),
                    notify_price_increases=bool(settings["notify_price_increases"]),
                ):
                    self._store_event(event, notify=should_notify, connection=connection)
            self.db.save_watch_state(
                    int(watch["id"]),
                    {
                        "variant_id": observation["variant_id"],
                        "observed_at": observation["observed_at"],
                        "comparison": current_comparison,
                        "latest_observation": watch_observation,
                    },
                connection=connection,
            )
        if signal and watches:
            self.db.save_observation(source_id, observation, connection=connection)

    def _register_variant(
        self,
        source: dict[str, Any],
        product: dict[str, Any],
        observation: dict[str, Any],
        product_is_new: bool,
        *, connection: Any = None,
    ) -> None:
        first_seen = self.db.register_variant(
            source["id"], product["product_id"], observation.get("variant_id", ""),
            observation.get("variant_title", ""), observation["observed_at"], connection=connection,
        )
        if not first_seen or product_is_new:
            return
        watches = [
            row for row in self.db.watches(connection=connection)
            if row["source_id"] == source["id"] and row["product_id"] == product["product_id"]
            and not row["variant_id"] and row.get("baseline_complete")
        ]
        if watches:
            notify = bool(self.db.settings(connection=connection)["auto_discovery_alerts"])
            self._store_event(variant_event(source, observation), notify=notify, connection=connection)

    def _store_event(self, event: dict[str, Any], *, notify: bool, connection: Any = None) -> None:
        payload = dict(event)
        self.db.insert_event(event, payload if notify else None, connection=connection)

    def _next_cycle_at(self) -> str | None:
        values: list[str] = []
        sources = self.db.sources()
        enabled_ids = {
            source["id"] for source in sources
            if source.get("enabled", True) and source.get("platform") != "invision"
        }
        for source in sources:
            if source["id"] in enabled_ids and source.get("discovery_enabled", True) and source.get("next_discovery_at"):
                values.append(source["next_discovery_at"])
        for row in self.db.all_checks():
            if row.get("source_id") in enabled_ids and row.get("next_due_at"):
                values.append(row["next_due_at"])
        if self.db.settings().get("webhook_protected"):
            retry_at = self.db.next_outbox_retry_at()
            if retry_at:
                values.append(retry_at)
        return min(values) if values else None

    def _seconds_to_next_cycle(self) -> float:
        next_at = _parse_time(self._next_cycle_at())
        if next_at is None:
            return 1.0
        return max(0.2, (next_at - datetime.now(timezone.utc)).total_seconds())

    def _webhook_url(self) -> str | None:
        if self._hosted_webhook_url:
            return self._hosted_webhook_url
        if self.hosted_mode:
            return None
        protected = self.db.settings().get("webhook_protected")
        if not protected:
            return None
        return security.validate_webhook_url(security.unprotect_secret(protected))

    def _deliver_test_outbox(self, outbox_id: str) -> None:
        self._deliver_outbox(target_id=outbox_id)

    def _drain_outbox(self) -> None:
        self._deliver_outbox()

    def _deliver_outbox(
        self, *, target_id: str = "", deadline: float | None = None,
        hosted_only: bool = False,
        checkpoint_callback: Callable[[dict[str, Any]], Any] | None = None,
        cursor: str = "", progress: dict[str, Any] | None = None,
    ) -> int:
        self._last_delivery_status = "complete"
        delivered = 0
        now = utc_now()
        rows = self.db.due_outbox(now, 100 if target_id else 25)
        if target_id:
            rows = [row for row in rows if row["id"] == target_id]
        if hosted_only:
            rows = [row for row in rows if row.get("kind") == "alert"]
        if not rows:
            return 0

        def checkpoint_result(row_id: str, result: str) -> bool:
            metadata = {
                "phase": "delivery_result_checkpoint", "outbox_id": row_id,
                "cursor": cursor, "delivered": delivered, "result": result,
            }
            callback_ok = self._notify_checkpoint(checkpoint_callback, metadata)
            controller_ok = True
            if not self.hosted_mode:
                controller_ok = self._controller_after_local_work(metadata)
            return callback_ok and controller_ok

        def defer_before_post(row: dict[str, Any], error: str) -> bool:
            # These branches prove that no Discord request began. Keep the
            # alert due for a later fenced attempt instead of stranding it as
            # an ambiguous delivery.
            attempts = int(row["attempts"]) + 1
            delay = min(30 * (2 ** min(attempts - 1, 7)), 3600)
            self.db.mark_outbox_retry(
                row["id"], attempts=attempts,
                next_attempt_at=_after_seconds(utc_now(), delay), error=error,
            )
            if not checkpoint_result(row["id"], "retry"):
                self._last_delivery_status = "checkpoint_failed"
                return False
            return True

        if not self._delivery_lock.acquire(blocking=False):
            self._last_delivery_status = "busy"
            return 0
        try:
            if not self._ownership_allowed("delivery_start"):
                self._last_delivery_status = "ownership_lost"
                return 0
            try:
                webhook = self._webhook_url()
            except Exception:
                for row in rows:
                    if row["status"] == "retry":
                        self.db.mark_outbox_retry(
                            row["id"], attempts=int(row["attempts"]) + 1,
                            next_attempt_at=_after_seconds(utc_now(), 3600),
                            error="Saved Discord webhook could not be unlocked.",
                        )
                        if not checkpoint_result(row["id"], "retry"):
                            self._last_delivery_status = "checkpoint_failed"
                            break
                return 0
            if not webhook:
                return 0
            settings = self.db.settings()
            mentions = {
                "mention_user_id": settings["mention_user_id"],
                "mention_role_id": settings["mention_role_id"],
            }
            for row in rows:
                if hosted_only and row.get("kind") != "alert":
                    continue
                remaining = float("inf") if deadline is None else deadline - time.monotonic()
                if remaining < 15.0:
                    self._last_delivery_status = "budget_exhausted"
                    break
                if not self._ownership_allowed("delivery_claim"):
                    self._last_delivery_status = "ownership_lost"
                    break
                event = Database.json_load(row["payload_json"], {})
                try:
                    payload = build_payload(event, **mentions)
                except Exception as exc:
                    if not self.db.claim_outbox_sending(row["id"]):
                        continue
                    if not defer_before_post(row, safe_error(exc)):
                        break
                    continue
                if not self.db.claim_outbox_sending(row["id"]):
                    continue
                if not self._notify_checkpoint(checkpoint_callback, {
                    "phase": "sending_checkpoint", "outbox_id": row["id"],
                    "cursor": cursor, "delivered": delivered, **(progress or {}),
                }):
                    defer_before_post(row, "Sending checkpoint was not accepted before delivery; retry scheduled.")
                    self._last_delivery_status = "checkpoint_failed"
                    break
                if not self.hosted_mode and not self._controller_after_local_work({
                    "phase": "sending_checkpoint", "outbox_id": row["id"], "cursor": cursor,
                }):
                    defer_before_post(row, "Local state sync was not accepted before delivery; retry scheduled.")
                    self._last_delivery_status = "checkpoint_failed"
                    break
                if not self._ownership_allowed("delivery_before_post"):
                    defer_before_post(row, "Ownership ended before delivery; retry deferred.")
                    self._last_delivery_status = "ownership_lost"
                    break
                if deadline is not None and deadline - time.monotonic() < 12.0:
                    if not defer_before_post(row, "Run deadline reached before delivery started; retry scheduled."):
                        self._last_delivery_status = "checkpoint_failed"
                    if self._last_delivery_status != "complete":
                        break
                    continue
                post_started = False
                try:
                    post_started = True
                    post_webhook(webhook, payload)
                except WebhookDeliveryError as exc:
                    attempts = int(row["attempts"]) + 1
                    error = safe_error(exc)
                    if exc.uncertain:
                        self.db.mark_outbox_uncertain(row["id"], error=error)
                        self._last_delivery_status = "delivery_uncertain"
                    elif not exc.retryable or attempts >= 12:
                        self.db.mark_outbox_failed(row["id"], attempts=attempts, error=error)
                    else:
                        delay = exc.retry_after or min(30 * (2 ** min(attempts - 1, 7)), 3600)
                        self.db.mark_outbox_retry(
                            row["id"], attempts=attempts,
                            next_attempt_at=_after_seconds(utc_now(), delay), error=error,
                        )
                    if not checkpoint_result(
                        row["id"], "uncertain" if exc.uncertain else ("failed" if not exc.retryable else "retry"),
                    ):
                        self._last_delivery_status = "checkpoint_failed"
                    if exc.uncertain or self._last_delivery_status != "complete":
                        break
                    continue
                except Exception as exc:
                    error = safe_error(exc)
                    if post_started:
                        self.db.mark_outbox_uncertain(row["id"], error=error)
                        self._last_delivery_status = "delivery_uncertain"
                    else:
                        if not defer_before_post(row, error):
                            self._last_delivery_status = "checkpoint_failed"
                        if self._last_delivery_status != "complete":
                            break
                        continue
                    if not checkpoint_result(row["id"], "uncertain"):
                        self._last_delivery_status = "checkpoint_failed"
                    if self._last_delivery_status != "complete":
                        break
                    continue
                delivered += 1
                if not self._ownership_allowed("delivery_commit"):
                    # The POST response is known, but the coordinator no longer
                    # accepts this generation's state update. Keep it non-retryable.
                    self.db.mark_outbox_uncertain(
                        row["id"], error="Ownership ended after delivery; the accepted result was not checkpointed.",
                    )
                    checkpoint_result(row["id"], "uncertain")
                    self._last_delivery_status = "ownership_lost"
                    break
                self.db.mark_outbox_sent(row["id"])
                if not self._notify_checkpoint(checkpoint_callback, {
                    "phase": "delivery_result_checkpoint", "outbox_id": row["id"],
                    "cursor": cursor, "delivered": delivered, "result": "sent",
                }):
                    self._last_delivery_status = "checkpoint_failed"
                    break
                if not self.hosted_mode:
                    if not self._controller_after_local_work({
                        "phase": "delivery_checkpoint", "outbox_id": row["id"], "delivered": delivered,
                    }):
                        self._last_delivery_status = "checkpoint_failed"
                        break
        finally:
            self._delivery_lock.release()
        return delivered


def _interval(value: Any, name: str, minimum: int, maximum: int) -> int:
    try:
        integer = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a whole number of seconds.") from exc
    if isinstance(value, bool) or str(value).strip() != str(integer) or not minimum <= integer <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum} seconds.")
    return integer


def _keywords(value: Any, name: str) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, str):
        value = value.splitlines()
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list of words.")
    if len(value) > 50:
        raise ValueError(f"{name} can contain at most 50 words.")
    result = []
    for item in value:
        word = " ".join(str(item).split())[:100]
        if word and word.casefold() not in {x.casefold() for x in result}:
            result.append(word)
    return result


def _after_seconds(value: str | datetime, seconds: int | float) -> str:
    parsed = value if isinstance(value, datetime) else _parse_time(value)
    if parsed is None:
        parsed = datetime.now(timezone.utc)
    return (parsed + timedelta(seconds=max(0, float(seconds)))).isoformat(timespec="seconds")


def _is_due(value: str | None, now: datetime) -> bool:
    parsed = _parse_time(value)
    return parsed is None or parsed <= now
