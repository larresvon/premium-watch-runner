"""Private GitHub ledger and fenced ownership for the hosted Premium Watch fallback.

This module deliberately stores only a compressed, versioned application snapshot
and a small allow-listed control record. It never reads the local SQLite file or
the saved webhook itself.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import gzip
import json
import os
import re
import zlib
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


# Generic in-memory/test default. A real ledger always receives its repository.
REPOSITORY = "owner/repository"
BRANCH = "premium-watch-state"
STATE_PATH = "state/monitor.json"
SNAPSHOT_PATH = "state/snapshot.json.gz"
STATUS_PATH = "STATUS.md"
OFFLINE_SECONDS = 600
LEASE_SECONDS = 300
HEARTBEAT_SECONDS = 120
MAX_STATE_BYTES = 200_000
MAX_SNAPSHOT_COMPRESSED = 1_000_000
MAX_SNAPSHOT_UNCOMPRESSED = 10_000_000
MAX_CORE_SNAPSHOT_COMPRESSED = 500_000
MAX_CORE_SNAPSHOT_UNCOMPRESSED = 10_000_000
MAX_API_RESPONSE = 13_000_000
MAX_MONTHS = 3
MAX_RUN_IDS_PER_MONTH = 100
MAX_VERIFICATION_TASKS = 500
STATE_VERSION = 1

_STATE_KEYS = {
    "schema_version", "repository", "armed", "paused", "generation",
    "config_revision", "snapshot", "verification", "lease",
    "windows_heartbeat", "hosted_last_attempt", "hosted_last_success",
    "hosted_cursor", "selected_source_ids", "source_results", "progress", "budget", "monthly_minutes",
    "monthly_runs", "run_ids", "uncertain_alert_count", "status_revision",
    "last_error_code", "updated_at",
}
_SECRET_KEY = re.compile(r"token|secret|password|cookie|session|bridge|pairing|credential|webhook|authorization|cart.?contents", re.I)
_ERROR_CODES = {
    "budget_blocked", "config_changed", "lease_conflict", "pc_online",
    "verification_required", "source_blocked", "source_timeout",
    "source_incomplete", "market_context_mismatch", "provider_unavailable",
    "hosted_partial", "hosted_failed", "shared_state_invalid", "local_only",
    "cart_context_unverified", "none",
}


class HostingError(RuntimeError):
    """Shared monitoring state is invalid, unavailable, or no longer owned."""


class Conflict(HostingError):
    """The shared state changed before a compare-and-swap write."""


class NotFound(HostingError):
    """The requested shared file does not exist."""


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: datetime | None = None) -> str:
    return (value or now_utc()).astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_time(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("timestamp")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("timestamp")
    return result.astimezone(timezone.utc)


def recent(value: object, seconds: int, *, now: datetime | None = None) -> bool:
    try:
        age = ((now or now_utc()).astimezone(timezone.utc) - parse_time(value)).total_seconds()
        return 0 <= age < seconds
    except (TypeError, ValueError, OverflowError):
        return False


def _json_bytes(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise HostingError("Shared monitoring data is not valid JSON.") from None


def _reject_secret_fields(value: object, *, depth: int = 0) -> None:
    """Reject credential/session fields anywhere in a core-exported snapshot."""
    if depth > 24:
        raise HostingError("Shared monitoring data is nested too deeply.")
    if isinstance(value, dict):
        if len(value) > 50_000:
            raise HostingError("Shared monitoring data contains too many fields.")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 160 or _SECRET_KEY.search(key):
                raise HostingError("Shared monitoring data contains a field that cannot be uploaded.")
            _reject_secret_fields(item, depth=depth + 1)
    elif isinstance(value, list):
        if len(value) > 100_000:
            raise HostingError("Shared monitoring data contains too many rows.")
        for item in value:
            _reject_secret_fields(item, depth=depth + 1)
    elif isinstance(value, str):
        if len(value) > 200_000 or "\x00" in value:
            raise HostingError("Shared monitoring data contains an oversized text value.")
    elif value is not None and type(value) not in (bool, int, float):
        raise HostingError("Shared monitoring data contains an unsupported value.")


def pack_snapshot(snapshot: dict) -> tuple[bytes, int]:
    """Compress one validated core snapshot into a separately stored Git blob."""
    if not isinstance(snapshot, dict):
        raise HostingError("The application snapshot is missing.")
    _reject_secret_fields(snapshot)
    _validate_core_snapshot(snapshot)
    raw = _json_bytes(snapshot)
    if len(raw) > MAX_SNAPSHOT_UNCOMPRESSED:
        raise HostingError("The application snapshot exceeds its private storage limit.")
    packed = gzip.compress(raw, compresslevel=6, mtime=0)
    if len(packed) > MAX_SNAPSHOT_COMPRESSED:
        raise HostingError("The compressed application snapshot exceeds its private storage limit.")
    return packed, len(raw)


def unpack_snapshot(value: object) -> dict:
    try:
        if isinstance(value, str):
            packed = base64.b64decode(value, validate=True)
        elif isinstance(value, (bytes, bytearray)):
            packed = bytes(value)
        else:
            raise ValueError("encoding")
        if len(packed) > MAX_SNAPSHOT_COMPRESSED:
            raise ValueError("size")
        reader = zlib.decompressobj(16 + zlib.MAX_WBITS)
        raw = reader.decompress(packed, MAX_SNAPSHOT_UNCOMPRESSED + 1)
        if len(raw) > MAX_SNAPSHOT_UNCOMPRESSED or not reader.eof or reader.unused_data or reader.unconsumed_tail:
            raise ValueError("size")
        snapshot = json.loads(raw, object_pairs_hook=_no_duplicate_keys)
        if not isinstance(snapshot, dict):
            raise ValueError("snapshot")
        _reject_secret_fields(snapshot)
        _validate_core_snapshot(snapshot)
        return snapshot
    except (ValueError, TypeError, UnicodeDecodeError, zlib.error, RecursionError):
        raise HostingError("The shared application snapshot could not be validated.") from None


def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _validate_core_snapshot(snapshot: dict) -> None:
    """Validate the core's inner compression envelope before it enters Git."""
    if "encoding" not in snapshot:
        return
    try:
        expected = {
            "schema_version", "config_revision", "context_id", "candidate_source_ids",
            "encoding", "compressed_bytes", "uncompressed_bytes", "payload_sha256", "payload_b64",
        }
        if set(snapshot) != expected or snapshot["schema_version"] != 1:
            raise ValueError("envelope shape")
        if not _digest(snapshot["config_revision"]) or snapshot["encoding"] != "gzip+base64":
            raise ValueError("envelope version")
        context = snapshot["context_id"]
        if not isinstance(context, str) or len(context) > 120:
            raise ValueError("context")
        if not _digest(snapshot["payload_sha256"]):
            raise ValueError("payload digest")
        compressed_bytes = snapshot["compressed_bytes"]
        uncompressed_bytes = snapshot["uncompressed_bytes"]
        if type(compressed_bytes) is not int or not 1 <= compressed_bytes <= MAX_CORE_SNAPSHOT_COMPRESSED:
            raise ValueError("compressed size")
        if type(uncompressed_bytes) is not int or not 1 <= uncompressed_bytes <= MAX_CORE_SNAPSHOT_UNCOMPRESSED:
            raise ValueError("uncompressed size")
        encoded = snapshot["payload_b64"]
        if not isinstance(encoded, str) or len(encoded) > ((MAX_CORE_SNAPSHOT_COMPRESSED + 2) // 3) * 4:
            raise ValueError("payload encoding")
        compressed = base64.b64decode(encoded, validate=True)
        if len(compressed) != compressed_bytes:
            raise ValueError("compressed byte count")
        reader = zlib.decompressobj(16 + zlib.MAX_WBITS)
        raw = reader.decompress(compressed, MAX_CORE_SNAPSHOT_UNCOMPRESSED + 1)
        if (
            len(raw) != uncompressed_bytes
            or len(raw) > MAX_CORE_SNAPSHOT_UNCOMPRESSED
            or not reader.eof
            or reader.unused_data
            or reader.unconsumed_tail
            or hashlib.sha256(raw).hexdigest() != snapshot["payload_sha256"]
        ):
            raise ValueError("payload size or digest")
        payload = json.loads(raw, object_pairs_hook=_no_duplicate_keys)
        _reject_secret_fields(payload)
        if (
            not isinstance(payload, dict)
            or payload.get("schema_version") != 1
            or payload.get("config_revision") != snapshot["config_revision"]
            or payload.get("context_id") != context
            or not isinstance(payload.get("sources"), list)
            or set(payload) != {
                "schema_version", "config_revision", "context_id", "settings", "sources",
                "watches", "catalog", "observations", "events", "outbox",
            }
        ):
            raise ValueError("payload schema")
        settings = payload.get("settings")
        base_settings = {"notify_price_increases", "auto_discovery_alerts"}
        safe_settings = base_settings | {"mention_user_id", "mention_role_id"}
        if (
            not isinstance(settings, dict)
            or not base_settings.issubset(settings)
            or not set(settings).issubset(safe_settings)
            or any(type(settings[name]) is not bool for name in base_settings)
            or any(
                name in settings
                and (
                    not isinstance(settings[name], str)
                    or (settings[name] != "" and re.fullmatch(r"[0-9]{17,20}", settings[name]) is None)
                )
                for name in ("mention_user_id", "mention_role_id")
            )
        ):
            raise ValueError("settings schema")
        source_ids = [row.get("id") for row in payload["sources"] if isinstance(row, dict)]
        if len(source_ids) != len(payload["sources"]) or any(
            not isinstance(row.get("config"), dict)
            or row["config"].get("platform") not in {"shopify", "youngcart", "kimchidvd", "cafe24"}
            for row in payload["sources"]
        ):
            raise ValueError("source shape")
        candidates = _candidate_ids(snapshot)
        if sorted(source_ids) != candidates or len(set(source_ids)) != len(source_ids):
            raise ValueError("source allowlist")
    except HostingError:
        raise
    except (ValueError, TypeError, KeyError, UnicodeDecodeError, zlib.error, RecursionError):
        raise HostingError("The allow-listed application snapshot failed its size, digest, or source validation.") from None


def _candidate_ids(snapshot: dict) -> list[str]:
    value = snapshot.get("candidate_source_ids", [])
    if not isinstance(value, list) or len(value) > 200:
        raise HostingError("The application snapshot has an invalid public-source allowlist.")
    ids = list(value)
    if any(not isinstance(item, str) or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", item) is None for item in ids):
        raise HostingError("The application snapshot has an invalid public-source allowlist.")
    if len(set(ids)) != len(ids):
        raise HostingError("The application snapshot has duplicate public-source IDs.")
    return sorted(ids)


def initial_state(
    snapshot: dict, *, snapshot_blob_sha: str = "", budget: dict | None = None,
    at: datetime | None = None, repository: str = REPOSITORY,
) -> dict:
    """Build an unarmed, unpaused ledger state around the service's allow-list."""
    revision = snapshot.get("config_revision") if isinstance(snapshot, dict) else None
    if not _digest(revision) or snapshot.get("schema_version") != 1:
        raise HostingError("The application snapshot has no valid configuration fingerprint.")
    candidates = _candidate_ids(snapshot)
    packed, uncompressed_bytes = pack_snapshot(snapshot)
    moment = timestamp(at)
    state = {
        "schema_version": STATE_VERSION,
        "repository": repository,
        "armed": False,
        "paused": False,
        "generation": 0,
        "config_revision": revision,
        "snapshot": {
            "blob_sha": snapshot_blob_sha,
            "config_revision": revision,
            "compressed_sha256": hashlib.sha256(packed).hexdigest(),
            "compressed_bytes": len(packed),
            "uncompressed_bytes": uncompressed_bytes,
        },
        "verification": None,
        "lease": None,
        "windows_heartbeat": None,
        "hosted_last_attempt": None,
        "hosted_last_success": None,
        "hosted_cursor": {"config_revision": revision, "task_key": "", "updated_at": moment},
        "selected_source_ids": candidates,
        "source_results": [],
        "progress": {"eligible_sources": 0, "checked_sources": 0, "completed_sources": 0, "failed_sources": 0, "uncertain_alert_count": 0, "error_codes": []},
        "budget": _normalize_budget(budget or {}),
        "monthly_minutes": {},
        "monthly_runs": {},
        "run_ids": {},
        "uncertain_alert_count": 0,
        "status_revision": 1,
        "last_error_code": "none",
        "updated_at": moment,
    }
    validate_state(state, expected_repository=repository)
    return state


def _normalize_budget(value: dict) -> dict:
    """Retain only safe, coarse budget-guard metadata in the shared branch."""
    if not isinstance(value, dict):
        raise HostingError("The hosted budget guard is invalid.")
    valid_until = value.get("valid_until")
    cap = value.get("monthly_minutes_cap", 0)
    blocked = bool(value.get("blocked", True))
    if valid_until is not None:
        try:
            valid_until = timestamp(parse_time(valid_until))
        except (ValueError, TypeError):
            raise HostingError("The hosted budget receipt date is invalid.") from None
    if type(cap) is not int or not 0 <= cap <= 2_000:
        raise HostingError("The hosted budget cap is invalid.")
    return {
        "valid_until": valid_until,
        "monthly_minutes_cap": cap,
        "reserved_minutes": 0,
        "blocked": blocked,
    }


def validate_state(state: object, *, expected_repository: str | None = None) -> None:
    """Validate the small ledger envelope and every value used by ownership code."""
    try:
        if not isinstance(state, dict) or set(state) != _STATE_KEYS:
            raise ValueError("state keys")
        repository = state.get("repository")
        if (
            state["schema_version"] != STATE_VERSION
            or not isinstance(repository, str)
            or re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", repository) is None
            or (expected_repository is not None and repository.casefold() != expected_repository.casefold())
        ):
            raise ValueError("version or repository")
        if type(state["armed"]) is not bool or type(state["paused"]) is not bool:
            raise ValueError("flags")
        if type(state["generation"]) is not int or not 0 <= state["generation"] <= 2**63 - 1:
            raise ValueError("generation")
        if not _digest(state["config_revision"]):
            raise ValueError("revision")
        snapshot = state["snapshot"]
        if not isinstance(snapshot, dict) or set(snapshot) != {
            "blob_sha", "config_revision", "compressed_sha256", "compressed_bytes", "uncompressed_bytes",
        }:
            raise ValueError("snapshot pointer")
        if not isinstance(snapshot["blob_sha"], str) or (snapshot["blob_sha"] and re.fullmatch(r"[0-9a-f]{40}", snapshot["blob_sha"]) is None):
            raise ValueError("snapshot blob sha")
        if snapshot["config_revision"] != state["config_revision"]:
            raise ValueError("snapshot revision")
        if not isinstance(snapshot["compressed_sha256"], str) or re.fullmatch(r"[0-9a-f]{64}", snapshot["compressed_sha256"]) is None:
            raise ValueError("snapshot hash")
        if type(snapshot["compressed_bytes"]) is not int or not 0 <= snapshot["compressed_bytes"] <= MAX_SNAPSHOT_COMPRESSED:
            raise ValueError("snapshot compressed size")
        if type(snapshot["uncompressed_bytes"]) is not int or not 0 <= snapshot["uncompressed_bytes"] <= MAX_SNAPSHOT_UNCOMPRESSED:
            raise ValueError("snapshot size")
        verification = state["verification"]
        if verification is not None:
            base_verification_keys = {
                "config_revision", "checked_at", "passed", "eligible_sources", "cursor",
                "checked_sources", "completed_sources", "failed_sources", "error_codes", "source_results",
                "task_results",
            }
            binding_keys = {"runner_repository", "billing_mode"}
            if not isinstance(verification, dict) or frozenset(verification) not in {frozenset(base_verification_keys), frozenset(base_verification_keys | binding_keys)}:
                raise ValueError("verification")
            if binding_keys.issubset(verification):
                runner_repository = verification["runner_repository"]
                if runner_repository is not None and (
                    not isinstance(runner_repository, str)
                    or re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", runner_repository) is None
                ):
                    raise ValueError("verification runner")
                if verification["billing_mode"] not in {"private", "public"}:
                    raise ValueError("verification billing mode")
                if verification["billing_mode"] == "public" and runner_repository is None:
                    raise ValueError("verification runner binding")
            if not _digest(verification["config_revision"]) or type(verification["passed"]) is not bool:
                raise ValueError("verification values")
            parse_time(verification["checked_at"])
            cursor_value = verification["cursor"]
            if not isinstance(cursor_value, str) or len(cursor_value) > 180 or (
                cursor_value and not (
                    re.fullmatch(r"d:[a-z0-9][a-z0-9_-]{0,63}", cursor_value)
                    or re.fullmatch(r"w:\d{1,16}", cursor_value)
                )
            ):
                raise ValueError("verification cursor")
            for key in ("eligible_sources", "checked_sources", "completed_sources", "failed_sources"):
                if type(verification[key]) is not int or not 0 <= verification[key] <= 100_000:
                    raise ValueError("verification counts")
            _error_codes(verification["error_codes"])
            _validate_source_results(verification["source_results"])
            _validate_verification_task_results(verification["task_results"])
        lease = state["lease"]
        if lease is not None:
            if not isinstance(lease, dict) or set(lease) != {"owner", "role", "generation", "expires_at"}:
                raise ValueError("lease")
            if not isinstance(lease["owner"], str) or not 1 <= len(lease["owner"]) <= 100:
                raise ValueError("lease owner")
            if lease["role"] not in {"windows", "hosted", "verification"}:
                raise ValueError("lease role")
            if type(lease["generation"]) is not int or lease["generation"] != state["generation"]:
                raise ValueError("lease generation")
            parse_time(lease["expires_at"])
        for key in ("windows_heartbeat", "hosted_last_attempt", "hosted_last_success"):
            if state[key] is not None:
                parse_time(state[key])
        cursor = state["hosted_cursor"]
        if not isinstance(cursor, dict) or set(cursor) != {"config_revision", "task_key", "updated_at"}:
            raise ValueError("cursor")
        if not _digest(cursor["config_revision"]) or not isinstance(cursor["task_key"], str) or len(cursor["task_key"]) > 180:
            raise ValueError("cursor values")
        if cursor["task_key"] and re.fullmatch(r"[dw]:[A-Za-z0-9_-]{1,160}", cursor["task_key"]) is None:
            raise ValueError("cursor task key")
        parse_time(cursor["updated_at"])
        selected = state["selected_source_ids"]
        if not isinstance(selected, list) or len(selected) > 200 or any(
            not isinstance(source_id, str) or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", source_id) is None
            for source_id in selected
        ) or len(set(selected)) != len(selected):
            raise ValueError("selected sources")
        _validate_source_results(state["source_results"])
        progress = state["progress"]
        if not isinstance(progress, dict) or set(progress) != {
            "eligible_sources", "checked_sources", "completed_sources", "failed_sources", "uncertain_alert_count", "error_codes",
        }:
            raise ValueError("progress")
        for key in ("eligible_sources", "checked_sources", "completed_sources", "failed_sources", "uncertain_alert_count"):
            if type(progress[key]) is not int or not 0 <= progress[key] <= 100_000:
                raise ValueError("progress counts")
        _error_codes(progress["error_codes"])
        budget = state["budget"]
        if not isinstance(budget, dict) or set(budget) != {"valid_until", "monthly_minutes_cap", "reserved_minutes", "blocked"}:
            raise ValueError("budget")
        if budget["valid_until"] is not None:
            parse_time(budget["valid_until"])
        for key in ("monthly_minutes_cap", "reserved_minutes"):
            if type(budget[key]) is not int or not 0 <= budget[key] <= 2_000:
                raise ValueError("budget count")
        if type(budget["blocked"]) is not bool:
            raise ValueError("budget blocked")
        for name in ("monthly_minutes", "monthly_runs", "run_ids"):
            mapping = state[name]
            if not isinstance(mapping, dict) or len(mapping) > MAX_MONTHS:
                raise ValueError(name)
            for month, count in mapping.items():
                if not isinstance(month, str) or re.fullmatch(r"\d{4}-\d{2}", month) is None:
                    raise ValueError("month")
                if name == "run_ids":
                    if not isinstance(count, list) or len(count) > MAX_RUN_IDS_PER_MONTH or any(not isinstance(item, str) or len(item) > 100 for item in count):
                        raise ValueError("run ids")
                elif type(count) is not int or not 0 <= count <= 100_000:
                    raise ValueError("monthly count")
        if type(state["uncertain_alert_count"]) is not int or not 0 <= state["uncertain_alert_count"] <= 100_000:
            raise ValueError("uncertain count")
        if type(state["status_revision"]) is not int or not 1 <= state["status_revision"] <= 2**63 - 1:
            raise ValueError("status revision")
        if state["last_error_code"] not in _ERROR_CODES:
            raise ValueError("error code")
        parse_time(state["updated_at"])
        # Exercise JSON serialization and bound the decoded envelope before write.
        raw = _json_bytes(state)
        if len(raw) > MAX_STATE_BYTES:
            raise ValueError("state size")
    except HostingError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        raise HostingError("Shared monitoring state is invalid; checks are paused.") from None


def _error_codes(value: object) -> None:
    if not isinstance(value, list) or len(value) > 100:
        raise ValueError("error codes")
    if any(not isinstance(item, str) or item not in _ERROR_CODES for item in value):
        raise ValueError("error codes")


def _validate_source_results(value: object) -> None:
    if not isinstance(value, list) or len(value) > 200:
        raise ValueError("source results")
    seen = set()
    for row in value:
        if not isinstance(row, dict) or set(row) != {
            "source_id", "passed", "checked_at", "coverage", "error_code", "market_context_id",
        }:
            raise ValueError("source result")
        source_id = row["source_id"]
        if not isinstance(source_id, str) or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", source_id) is None or source_id in seen:
            raise ValueError("source id")
        seen.add(source_id)
        if type(row["passed"]) is not bool:
            raise ValueError("source result values")
        coverage = row["coverage"]
        if not isinstance(coverage, dict) or set(coverage) != {
            "discovered_products", "discovered_variants", "watches_checked", "observations",
        }:
            raise ValueError("coverage")
        if any(type(count) is not int or not 0 <= count <= 100_000 for count in coverage.values()):
            raise ValueError("coverage counts")
        parse_time(row["checked_at"])
        if row["error_code"] not in _ERROR_CODES:
            raise ValueError("source error")
        context = row["market_context_id"]
        if context is not None and (not isinstance(context, str) or len(context) > 100):
            raise ValueError("market context")


def _validate_verification_task_results(value: object) -> None:
    """Validate compact, allow-listed task checkpoints used to resume verification."""
    if not isinstance(value, list) or len(value) > MAX_VERIFICATION_TASKS:
        raise ValueError("verification task results")
    seen: set[str] = set()
    for row in value:
        if not isinstance(row, dict) or set(row) != {
            "task_key", "source_id", "task_kind", "passed", "error_code", "coverage",
            "market_context_id", "checked_at",
        }:
            raise ValueError("verification task result")
        task_key = row["task_key"]
        source_id = row["source_id"]
        task_kind = row["task_kind"]
        if not isinstance(task_key, str) or not (
            re.fullmatch(r"d:[a-z0-9][a-z0-9_-]{0,63}", task_key)
            or re.fullmatch(r"w:\d{1,16}", task_key)
        ) or task_key in seen:
            raise ValueError("verification task key")
        if not isinstance(source_id, str) or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", source_id) is None:
            raise ValueError("verification task source")
        if task_kind not in {"discovery", "watch"}:
            raise ValueError("verification task kind")
        if (task_kind == "discovery") != task_key.startswith("d:"):
            raise ValueError("verification task identity")
        if task_kind == "discovery" and task_key != "d:" + source_id:
            raise ValueError("verification discovery key")
        if type(row["passed"]) is not bool or row["error_code"] not in _ERROR_CODES:
            raise ValueError("verification task status")
        if row["passed"] != (row["error_code"] == "none"):
            raise ValueError("verification task error")
        coverage = row["coverage"]
        if not isinstance(coverage, dict) or set(coverage) != {
            "discovered_products", "discovered_variants", "watches_checked", "observations",
        } or any(type(count) is not int or not 0 <= count <= 100_000 for count in coverage.values()):
            raise ValueError("verification task coverage")
        context = row["market_context_id"]
        if context is not None and (
            not isinstance(context, str) or not (context in {"unknown", "mixed"} or re.fullmatch(r"[0-9a-f]{16}", context))
        ):
            raise ValueError("verification task context")
        parse_time(row["checked_at"])
        seen.add(task_key)


class GitHubLedger:
    """GitHub Contents API ledger with strict paths and SHA compare-and-swap."""

    def __init__(
        self,
        repository: str,
        token: str,
        *,
        branch: str = BRANCH,
        opener=urlopen,
        require_private_repository: bool = False,
    ):
        if not isinstance(repository, str) or re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", repository) is None:
            raise HostingError("A valid GitHub repository is required.")
        if not isinstance(token, str) or not token or any(char.isspace() for char in token):
            raise HostingError("A GitHub access token is required.")
        if not isinstance(branch, str) or re.fullmatch(r"[A-Za-z0-9_.-]+", branch) is None:
            raise HostingError("The private state branch name is invalid.")
        self.repository, self.token, self.branch, self.opener = repository, token, branch, opener
        self.require_private_repository = bool(require_private_repository)

    @property
    def status_url(self) -> str:
        return f"https://github.com/{self.repository}/blob/{self.branch}/{STATUS_PATH}"

    def api(self, path: str, *, method: str = "GET", data: dict | None = None) -> dict:
        repository_path = f"/repos/{self.repository}"
        if (
            not isinstance(path, str)
            or (path != repository_path and not path.startswith(repository_path + "/"))
            or "\r" in path
            or "\n" in path
        ):
            raise HostingError("The GitHub API path is invalid.")
        body = None if data is None else _json_bytes(data)
        request = Request(
            "https://api.github.com" + path,
            data=body,
            method=method,
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "PremiumWatch/hosted-fallback",
                "Cache-Control": "no-cache",
            },
        )
        try:
            with self.opener(request, timeout=20) as response:
                raw = response.read(MAX_API_RESPONSE + 1)
            if len(raw) > MAX_API_RESPONSE:
                raise HostingError("GitHub returned an oversized response; monitoring is paused.")
            if not raw:
                return {}
            decoded = json.loads(raw)
            if not isinstance(decoded, dict):
                raise HostingError("GitHub returned an invalid response; monitoring is paused.")
            return decoded
        except HTTPError as exc:
            if exc.code in (409, 422):
                raise Conflict("The shared monitoring state changed; retrying safely.") from None
            if exc.code == 404:
                raise NotFound("The private monitoring file was not found.") from None
            if exc.code in (401, 403):
                raise HostingError("GitHub denied the required private repository permission.") from None
            raise HostingError(f"GitHub returned HTTP {exc.code}; monitoring is paused.") from None
        except (URLError, TimeoutError, OSError):
            raise HostingError("Cannot reach private monitoring state; alerts are paused to avoid overlap.") from None
        except (ValueError, UnicodeDecodeError):
            raise HostingError("GitHub returned an invalid response; monitoring is paused.") from None

    def verify_private_repository(self) -> dict:
        info = self.api(f"/repos/{self.repository}")
        if info.get("private") is not True or str(info.get("full_name", "")).casefold() != self.repository.casefold():
            raise HostingError("The configured state repository must be private.")
        return {"private": True, "full_name": self.repository, "default_branch": str(info.get("default_branch", ""))}

    def verify_public_repository(self) -> dict:
        info = self.api(f"/repos/{self.repository}")
        if (
            info.get("private") is not False
            or info.get("fork") is True
            or str(info.get("full_name", "")).casefold() != self.repository.casefold()
        ):
            raise HostingError("The runner repository must be public.")
        return {"private": False, "full_name": self.repository, "default_branch": str(info.get("default_branch", ""))}

    def dispatch_workflow(self, workflow_file: str, *, ref: str, mode: str) -> None:
        if not isinstance(workflow_file, str) or re.fullmatch(r"[A-Za-z0-9_.-]+\.yml", workflow_file) is None:
            raise HostingError("The runner workflow selection is invalid.")
        if not isinstance(ref, str) or re.fullmatch(r"[A-Za-z0-9_.-]+", ref) is None or mode not in {"verify", "scan"}:
            raise HostingError("The runner dispatch request is invalid.")
        self.api(
            f"/repos/{self.repository}/actions/workflows/{quote(workflow_file, safe='')}/dispatches",
            method="POST",
            data={"ref": ref, "inputs": {"mode": mode}},
        )

    def set_repository_secret(self, name: str, plaintext: str) -> None:
        if not isinstance(name, str) or re.fullmatch(r"[A-Z][A-Z0-9_]{1,99}", name) is None:
            raise HostingError("The runner secret name is invalid.")
        if not isinstance(plaintext, str) or not plaintext or len(plaintext) > 500 or "\x00" in plaintext:
            raise HostingError("The runner secret value is invalid.")
        try:
            from nacl.public import PublicKey, SealedBox

            public = self.api(f"/repos/{self.repository}/actions/secrets/public-key")
            key_id, encoded_key = public.get("key_id"), public.get("key")
            if not isinstance(key_id, str) or not isinstance(encoded_key, str):
                raise ValueError("key")
            key = PublicKey(base64.b64decode(encoded_key, validate=True))
            encrypted = base64.b64encode(SealedBox(key).encrypt(plaintext.encode("utf-8"))).decode("ascii")
        except HostingError:
            raise
        except Exception:
            raise HostingError("GitHub could not prepare the encrypted runner secret.") from None
        self.api(
            f"/repos/{self.repository}/actions/secrets/{quote(name, safe='')}",
            method="PUT",
            data={"encrypted_value": encrypted, "key_id": key_id},
        )

    def delete_repository_secret(self, name: str) -> None:
        if not isinstance(name, str) or re.fullmatch(r"[A-Z][A-Z0-9_]{1,99}", name) is None:
            raise HostingError("The runner secret name is invalid.")
        try:
            self.api(f"/repos/{self.repository}/actions/secrets/{quote(name, safe='')}", method="DELETE")
        except NotFound:
            return

    def ensure_state_branch(self) -> str:
        """Create the app's isolated state branch from the current default-branch tip."""
        info = self.verify_private_repository()
        try:
            result = self.api(
                f"/repos/{self.repository}/git/ref/heads/{quote(self.branch, safe='')}"
            )
            sha = result.get("object", {}).get("sha")
            if not isinstance(sha, str) or re.fullmatch(r"[0-9a-f]{40}", sha) is None:
                raise HostingError("GitHub returned an invalid private state branch reference.")
            return sha
        except NotFound:
            default_branch = info.get("default_branch")
            if not isinstance(default_branch, str) or re.fullmatch(r"[A-Za-z0-9_.-]+", default_branch) is None:
                raise HostingError("The private repository has no valid default branch.") from None
            base = self.api(
                f"/repos/{self.repository}/git/ref/heads/{quote(default_branch, safe='')}"
            )
            sha = base.get("object", {}).get("sha")
            if not isinstance(sha, str) or re.fullmatch(r"[0-9a-f]{40}", sha) is None:
                raise HostingError("GitHub returned an invalid default branch reference.")
            try:
                created = self.api(
                    f"/repos/{self.repository}/git/refs",
                    method="POST",
                    data={"ref": f"refs/heads/{self.branch}", "sha": sha},
                )
            except Conflict:
                # A concurrent setup may have created the branch after our GET.
                concurrent = self.api(
                    f"/repos/{self.repository}/git/ref/heads/{quote(self.branch, safe='')}"
                )
                sha = concurrent.get("object", {}).get("sha")
                if not isinstance(sha, str) or re.fullmatch(r"[0-9a-f]{40}", sha) is None:
                    raise HostingError("GitHub did not confirm the private state branch.") from None
                return sha
            result_sha = created.get("object", {}).get("sha")
            if not isinstance(result_sha, str) or result_sha != sha:
                raise HostingError("GitHub did not confirm the private state branch.")
            return result_sha

    def read(self) -> tuple[dict, str]:
        item = self.api(f"/repos/{self.repository}/contents/{STATE_PATH}?ref={quote(self.branch)}")
        try:
            encoded = item["content"]
            if not isinstance(encoded, str) or len(encoded) > MAX_STATE_BYTES * 2:
                raise ValueError("size")
            raw = base64.b64decode(re.sub(r"\s+", "", encoded), validate=True)
            if len(raw) > MAX_STATE_BYTES:
                raise ValueError("size")
            state = json.loads(raw, object_pairs_hook=_no_duplicate_keys)
            validate_state(state, expected_repository=self.repository)
            sha = item["sha"]
            if not isinstance(sha, str) or not sha:
                raise ValueError("sha")
            return state, sha
        except HostingError:
            raise
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, RecursionError):
            raise HostingError("Shared monitoring state is invalid; checks are paused.") from None

    def write(self, state: dict, sha: str | None) -> str:
        validate_state(state, expected_repository=self.repository)
        raw = _json_bytes(state)
        payload = {
            "branch": self.branch,
            "message": "Update Premium Watch private monitor state [skip ci]",
            "content": base64.b64encode(raw).decode("ascii"),
        }
        if sha:
            payload["sha"] = sha
        result = self.api(f"/repos/{self.repository}/contents/{STATE_PATH}", method="PUT", data=payload)
        try:
            new_sha = result["content"]["sha"]
            if not isinstance(new_sha, str) or not new_sha:
                raise ValueError("sha")
            return new_sha
        except (KeyError, TypeError, ValueError):
            raise HostingError("GitHub did not confirm the shared state update.") from None

    def initialize(self, state: dict) -> str:
        """Create the state file on the pre-created private state branch."""
        return self.write(state, None)

    def initialize_snapshot(self, snapshot: dict, *, budget: dict | None = None) -> tuple[dict, str]:
        """Create the private snapshot and then its small control pointer."""
        pointer = self.upload_snapshot(snapshot)
        state = initial_state(snapshot, snapshot_blob_sha=pointer["blob_sha"], budget=budget, repository=self.repository)
        state["snapshot"] = pointer
        validate_state(state, expected_repository=self.repository)
        state_sha = self.initialize(state)
        return state, state_sha

    def load_snapshot(self, state: dict) -> dict:
        """Fetch and verify the immutable snapshot blob named by a control record."""
        pointer = state.get("snapshot") or {}
        blob_sha = pointer.get("blob_sha")
        if not isinstance(blob_sha, str) or re.fullmatch(r"[0-9a-f]{40}", blob_sha) is None:
            raise HostingError("The private application snapshot has not been uploaded.")
        blob = self.api(f"/repos/{self.repository}/git/blobs/{blob_sha}")
        try:
            if blob.get("encoding") != "base64" or blob.get("sha") != blob_sha:
                raise ValueError("blob")
            encoded = blob["content"]
            if not isinstance(encoded, str) or len(encoded) > MAX_SNAPSHOT_COMPRESSED * 2:
                raise ValueError("size")
            packed = base64.b64decode(re.sub(r"\s+", "", encoded), validate=True)
            if (
                len(packed) != pointer["compressed_bytes"]
                or hashlib.sha256(packed).hexdigest() != pointer["compressed_sha256"]
            ):
                raise ValueError("hash")
            snapshot = unpack_snapshot(packed)
            if snapshot.get("schema_version") != 1 or snapshot.get("config_revision") != state["config_revision"]:
                raise ValueError("revision")
            if len(_json_bytes(snapshot)) != pointer["uncompressed_bytes"]:
                raise ValueError("uncompressed size")
            return snapshot
        except HostingError:
            raise
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, RecursionError):
            raise HostingError("The private application snapshot could not be validated.") from None

    def upload_snapshot(self, snapshot: dict, *, expected_blob_sha: str | None = None) -> dict:
        """Write a new allow-listed snapshot blob without duplicating it in heartbeats."""
        if self.require_private_repository:
            # Public runner jobs recheck visibility immediately before sensitive
            # snapshot writes, without adding a repository lookup to each lease fence.
            self.verify_private_repository()
        packed, uncompressed_bytes = pack_snapshot(snapshot)
        # For ordinary Contents updates, the supplied SHA is itself the CAS
        # precondition. Avoid a second path GET on every unit checkpoint.
        current_sha = expected_blob_sha if expected_blob_sha is not None else self._current_blob_sha(SNAPSHOT_PATH)
        if len(packed) <= 900_000:
            payload = {
                "branch": self.branch,
                "message": "Update Premium Watch allow-listed snapshot [skip ci]",
                "content": base64.b64encode(packed).decode("ascii"),
            }
            if current_sha:
                payload["sha"] = current_sha
            result = self.api(f"/repos/{self.repository}/contents/{SNAPSHOT_PATH}", method="PUT", data=payload)
            try:
                blob_sha = result["content"]["sha"]
            except (KeyError, TypeError):
                raise HostingError("GitHub did not confirm the private application snapshot.") from None
        else:
            blob_sha = self._write_large_blob(SNAPSHOT_PATH, packed, expected_blob_sha=current_sha)
        if not isinstance(blob_sha, str) or re.fullmatch(r"[0-9a-f]{40}", blob_sha) is None:
            raise HostingError("GitHub returned an invalid snapshot identifier.")
        return {
            "blob_sha": blob_sha,
            "config_revision": snapshot["config_revision"],
            "compressed_sha256": hashlib.sha256(packed).hexdigest(),
            "compressed_bytes": len(packed),
            "uncompressed_bytes": uncompressed_bytes,
        }

    def _current_blob_sha(self, path: str) -> str | None:
        try:
            result = self.api(f"/repos/{self.repository}/contents/{path}?ref={quote(self.branch)}")
            sha = result.get("sha")
            if not isinstance(sha, str) or re.fullmatch(r"[0-9a-f]{40}", sha) is None:
                raise HostingError("The private application snapshot reference is invalid.")
            return sha
        except NotFound:
            return None

    def _write_large_blob(self, path: str, packed: bytes, *, expected_blob_sha: str | None) -> str:
        """Use Git's blob/tree/commit API for compressed snapshots over Contents limits."""
        if self._current_blob_sha(path) != expected_blob_sha:
            raise Conflict("The private application snapshot changed; retrying safely.")
        blob = self.api(
            f"/repos/{self.repository}/git/blobs", method="POST",
            data={"content": base64.b64encode(packed).decode("ascii"), "encoding": "base64"},
        )
        blob_sha = blob.get("sha")
        if not isinstance(blob_sha, str) or re.fullmatch(r"[0-9a-f]{40}", blob_sha) is None:
            raise HostingError("GitHub did not confirm the compressed snapshot blob.")
        ref = self.api(f"/repos/{self.repository}/git/ref/heads/{quote(self.branch, safe='')}")
        head_sha = (ref.get("object") or {}).get("sha")
        if not isinstance(head_sha, str) or re.fullmatch(r"[0-9a-f]{40}", head_sha) is None:
            raise HostingError("GitHub did not return the private state branch head.")
        commit = self.api(f"/repos/{self.repository}/git/commits/{head_sha}")
        base_tree = (commit.get("tree") or {}).get("sha")
        if not isinstance(base_tree, str) or re.fullmatch(r"[0-9a-f]{40}", base_tree) is None:
            raise HostingError("GitHub did not return the private state branch tree.")
        tree = self.api(
            f"/repos/{self.repository}/git/trees", method="POST",
            data={"base_tree": base_tree, "tree": [{"path": path, "mode": "100644", "type": "blob", "sha": blob_sha}]},
        )
        tree_sha = tree.get("sha")
        if not isinstance(tree_sha, str) or re.fullmatch(r"[0-9a-f]{40}", tree_sha) is None:
            raise HostingError("GitHub did not confirm the private state tree.")
        new_commit = self.api(
            f"/repos/{self.repository}/git/commits", method="POST",
            data={"message": "Update Premium Watch allow-listed snapshot [skip ci]", "tree": tree_sha, "parents": [head_sha]},
        )
        new_commit_sha = new_commit.get("sha")
        if not isinstance(new_commit_sha, str) or re.fullmatch(r"[0-9a-f]{40}", new_commit_sha) is None:
            raise HostingError("GitHub did not confirm the private snapshot commit.")
        self.api(
            f"/repos/{self.repository}/git/refs/heads/{quote(self.branch, safe='')}", method="PATCH",
            data={"sha": new_commit_sha, "force": False},
        )
        return blob_sha

    def change(self, mutate, *, attempts: int = 5, initial: tuple[dict, str] | None = None) -> tuple[object, dict]:
        for attempt in range(max(1, min(10, attempts))):
            if attempt == 0 and initial is not None:
                state, sha = initial
            else:
                state, sha = self.read()
            before = _json_bytes(state)
            result = mutate(state)
            if _json_bytes(state) == before:
                return result, state
            try:
                self.write(state, sha)
                return result, state
            except Conflict:
                continue
        raise HostingError("Shared monitoring state is busy; this check will retry later.")

    def publish_status(self, *, force: bool = False) -> bool:
        """Write a redacted phone page without allowing an older snapshot to win."""
        path = f"/repos/{self.repository}/contents/{STATUS_PATH}"
        for _ in range(5):
            state, _ = self.read()
            try:
                current = self.api(path + "?ref=" + quote(self.branch))
                current_sha = current.get("sha")
                existing = _decode_content(current.get("content", ""))
            except NotFound:
                current_sha, existing = None, ""
            current_revision = _status_revision(existing)
            if current_revision > state["status_revision"]:
                continue
            if current_revision == state["status_revision"] and not force:
                return True
            content = render_status(state, self.repository).encode("utf-8")
            if existing == content.decode("utf-8"):
                return True
            payload = {
                "branch": self.branch,
                "message": "Refresh Premium Watch phone status [skip ci]",
                "content": base64.b64encode(content).decode("ascii"),
            }
            if current_sha:
                payload["sha"] = current_sha
            try:
                self.api(path, method="PUT", data=payload)
                return True
            except Conflict:
                continue
        return False


def _decode_content(value: object) -> str:
    if not isinstance(value, str) or len(value) > 300_000:
        return ""
    try:
        raw = base64.b64decode(re.sub(r"\s+", "", value), validate=True)
        return raw.decode("utf-8")[:100_000]
    except (ValueError, UnicodeDecodeError):
        return ""


def _status_revision(body: str) -> int:
    match = re.search(r"<!-- premiumwatch-status-revision:(\d{1,20}) -->", body)
    return int(match.group(1)) if match else 0


def _display_time(value: object) -> str:
    if not value:
        return "Not reported"
    try:
        return parse_time(value).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, TypeError, OverflowError):
        return "Unknown"


def render_status(state: dict, repository: str | None = None, *, now: datetime | None = None) -> str:
    """Render status fields only; never include product-level data or URLs."""
    validate_state(state)
    repository = repository or state["repository"]
    moment = now or now_utc()
    progress = state["progress"]
    lease = state.get("lease") or {}
    pc_time = state.get("windows_heartbeat")
    pc_state = "Reporting recently" if recent(pc_time, OFFLINE_SECONDS, now=moment) else "No recent report"
    hosted_time = state.get("hosted_last_success")
    hosted_state = "Complete" if hosted_time else "Not completed yet"
    if state["last_error_code"] != "none":
        hosted_state = "Partial or needs attention"
    verification = state.get("verification") or {}
    verification_text = "Passed" if verification.get("passed") and verification.get("config_revision") == state["config_revision"] else "Not passed"
    budget = state["budget"]
    month = moment.astimezone(timezone.utc).strftime("%Y-%m")
    month_used = int(state["monthly_minutes"].get(month, 0))
    billing_mode = verification.get("billing_mode")
    if billing_mode == "public":
        budget_state = "Public standard runner; private Actions minute pool is not charged"
    elif billing_mode == "private":
        budget_state = (
            "Blocked" if budget["blocked"] or budget["monthly_minutes_cap"] < 2
            else "Monthly limit reached" if month_used >= budget["monthly_minutes_cap"]
            else f"$0 Stop guard active; {month_used}/{budget['monthly_minutes_cap']} reserved minutes this month"
        )
    else:
        budget_state = "Runner billing mode not verified; check the local hosting panel"
    uncertain = max(state["uncertain_alert_count"], progress["uncertain_alert_count"])
    errors = list(dict.fromkeys(progress["error_codes"] + [row["error_code"] for row in state["source_results"] if row["error_code"] != "none"]))
    error_codes = ", ".join(errors) if errors else "None"
    lease_state = "Held" if lease and _lease_active(lease, moment) else "Free"
    failed_sources = int(verification.get("failed_sources", progress["failed_sources"])) if verification else progress["failed_sources"]
    lines = [
        "# Premium Watch status",
        "",
        "Private monitoring status. This page omits product names, product links, and credentials.",
        "",
        f"<!-- premiumwatch-status-revision:{state['status_revision']} -->",
        f"- Updated: {_display_time(state['updated_at'])}",
        f"- Monitoring: {'Paused by owner' if state['paused'] else 'Armed' if state['armed'] else 'Not armed'}",
        f"- PC report: {pc_state} ({_display_time(pc_time)})",
        f"- Hosted check: {hosted_state} (last attempt {_display_time(state['hosted_last_attempt'])}; last complete {_display_time(hosted_time)})",
        f"- Cloud source verification: {verification_text} ({_display_time(verification.get('checked_at'))})",
        f"- Coverage: {progress['checked_sources']}/{progress['eligible_sources']} selected sources checked; {progress['completed_sources']} passed; {progress['failed_sources']} failed; unfinished work resumes later",
        f"- Cloud selection: {len(state['selected_source_ids'])} selected; {failed_sources} failed and remaining shops stay local-only",
        f"- Source error codes: {error_codes}",
        f"- Exclusive lease: {lease_state}",
        f"- Alert deliveries needing review: {uncertain}",
        f"- Actions budget: {budget_state}",
        f"- Last safe error code: {state['last_error_code']}",
        "",
        f"Phone view: https://github.com/{repository}/blob/{BRANCH}/{STATUS_PATH}",
        "",
    ]
    return "\n".join(lines)


def _lease_active(lease: dict, now: datetime) -> bool:
    try:
        return parse_time(lease["expires_at"]) > now.astimezone(timezone.utc)
    except (KeyError, TypeError, ValueError, OverflowError):
        return True


def _change_status(state: dict, code: str | None = None) -> None:
    state["status_revision"] += 1
    state["updated_at"] = timestamp()
    if code is not None:
        if code not in _ERROR_CODES:
            raise HostingError("The monitoring status code is not allow-listed.")
        state["last_error_code"] = code


class SharedMonitor:
    """Fenced Windows/hosted lease with an exclusive generation per owner."""

    def __init__(self, ledger: GitHubLedger, role: str, *, owner: str | None = None, clock=now_utc):
        if role not in {"windows", "hosted", "verification"}:
            raise ValueError("role")
        self.ledger, self.role, self.clock = ledger, role, clock
        self.owner = (owner or f"{role}-{os.urandom(12).hex()}")[:100]
        self.generation: int | None = None
        self.last_reason = "lease_conflict"

    def owned(self, state: dict) -> bool:
        lease = state.get("lease") or {}
        return bool(
            self.generation is not None
            and not state.get("paused")
            and lease.get("owner") == self.owner
            and lease.get("role") == self.role
            and lease.get("generation") == self.generation
            and _lease_active(lease, self.clock())
        )

    def fenced(self, _phase: str | None = None) -> bool:
        """Fresh remote ownership check for each scan checkpoint and delivery."""
        try:
            state, _ = self.ledger.read()
        except HostingError:
            return False
        return self.owned(state)

    def acquire(self) -> tuple[bool, dict]:
        now = self.clock().astimezone(timezone.utc)
        acquired = {"ok": False, "generation": None, "reason": "lease_conflict"}

        def claim(state: dict) -> None:
            # The CAS coordinator may invoke this closure more than once after
            # a competing writer wins. Never carry an earlier tentative claim
            # into a retry against the new state.
            acquired.update(ok=False, generation=None, reason="lease_conflict")
            if state["paused"]:
                acquired["reason"] = "paused"
                return
            if self.role in {"hosted", "verification"}:
                if self.role == "hosted" and recent(state["windows_heartbeat"], OFFLINE_SECONDS, now=now):
                    acquired["reason"] = "pc_online"
                    return
                if self.role == "hosted":
                    verification = state.get("verification") or {}
                    if not state["armed"] or not verification.get("passed") or verification.get("config_revision") != state["config_revision"]:
                        acquired["reason"] = "verification_required"
                        return
                elif state["armed"]:
                    acquired["reason"] = "verification_required"
                    return
            lease = state.get("lease") or {}
            verification_yields_local = (
                self.role == "verification"
                and lease.get("role") == "windows"
                and not state["armed"]
            )
            if lease and _lease_active(lease, now) and lease.get("owner") != self.owner and not verification_yields_local:
                acquired["reason"] = "lease_conflict"
                return
            if lease and _lease_active(lease, now) and lease.get("owner") == self.owner:
                generation = lease["generation"]
            else:
                state["generation"] += 1
                generation = state["generation"]
            state["lease"] = {
                "owner": self.owner,
                "role": self.role,
                "generation": generation,
                "expires_at": timestamp(now + timedelta(seconds=LEASE_SECONDS)),
            }
            if self.role == "windows":
                state["windows_heartbeat"] = timestamp(now)
            if self.role in {"hosted", "verification"}:
                state["hosted_last_attempt"] = timestamp(now)
            acquired.update(ok=True, generation=generation, reason="none")
            _change_status(state, "none")

        _, state = self.ledger.change(claim)
        self.generation = acquired["generation"] if acquired["ok"] else None
        self.last_reason = str(acquired["reason"])
        return bool(acquired["ok"]), state

    def renew(self) -> bool:
        now = self.clock().astimezone(timezone.utc)
        renewed = False

        def update(state: dict) -> None:
            nonlocal renewed
            if not self.owned(state):
                return
            state["lease"]["expires_at"] = timestamp(now + timedelta(seconds=LEASE_SECONDS))
            if self.role == "windows":
                state["windows_heartbeat"] = timestamp(now)
            _change_status(state)
            renewed = True

        _, state = self.ledger.change(update)
        accepted = renewed and self.owned(state)
        if not accepted:
            self.generation = None
        return accepted

    def checkpoint(
        self,
        *,
        snapshot: dict | None = None,
        hosted_cursor: dict | None = None,
        progress: dict | None = None,
        error_code: str | None = None,
        complete: bool = False,
        uncertain_alert_count: int | None = None,
    ) -> dict:
        """Persist one scan unit only while the caller's fenced lease is current."""
        current, current_sha = self.ledger.read()
        if not self.owned(current):
            raise HostingError("This monitor lost its shared lease; the checkpoint was rejected.")
        snapshot_pointer = None
        if snapshot is not None:
            if not isinstance(snapshot, dict) or snapshot.get("config_revision") != current["config_revision"]:
                raise HostingError("The application configuration changed; the cloud checkpoint was rejected.")
            snapshot_pointer = self.ledger.upload_snapshot(
                snapshot,
                expected_blob_sha=(current.get("snapshot") or {}).get("blob_sha") or None,
            )
        accepted = {"ok": False}

        def save(state: dict) -> None:
            if not self.owned(state):
                raise HostingError("This monitor lost its shared lease; the checkpoint was rejected.")
            if snapshot is not None:
                if snapshot_pointer is None or snapshot_pointer["config_revision"] != state["config_revision"]:
                    raise HostingError("The application configuration changed; the cloud checkpoint was rejected.")
                state["snapshot"] = snapshot_pointer
            if hosted_cursor is not None:
                state["hosted_cursor"] = hosted_cursor
            if progress is not None:
                state["progress"] = progress
            if uncertain_alert_count is not None:
                state["uncertain_alert_count"] = uncertain_alert_count
                state["progress"]["uncertain_alert_count"] = uncertain_alert_count
            if error_code is not None:
                state["last_error_code"] = error_code
            if complete:
                state["hosted_last_success"] = timestamp(self.clock())
            state["lease"]["expires_at"] = timestamp(self.clock() + timedelta(seconds=LEASE_SECONDS))
            _change_status(state, error_code)
            accepted["ok"] = True

        _, saved = self.ledger.change(save, initial=(current, current_sha))
        if not accepted["ok"]:
            raise HostingError("The monitoring checkpoint was rejected.")
        return saved

    def record_verification_task(
        self, *, config_revision: str, task_result: dict, source_result: dict | None = None,
        runner_repository: str | None = None, billing_mode: str = "private",
    ) -> dict:
        """Durably checkpoint one safe task result before continuing verification."""
        _validate_verification_task_results([task_result])
        if source_result is not None:
            _validate_source_results([source_result])
            if source_result["source_id"] != task_result["source_id"]:
                raise HostingError("A verification source checkpoint did not match its task.")
        if billing_mode not in {"private", "public"} or (
            runner_repository is not None
            and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", runner_repository) is None
        ) or (billing_mode == "public" and runner_repository is None):
            raise HostingError("The verification runner binding is invalid.")
        accepted = {"ok": False}

        def save(state: dict) -> None:
            if self.role != "verification" or not self.owned(state):
                raise HostingError("Verification lost its shared lease; the task result was rejected.")
            if state["config_revision"] != config_revision:
                raise HostingError("The application configuration changed during cloud verification.")
            if task_result["source_id"] not in state["selected_source_ids"]:
                raise HostingError("The verification task is outside the selected source set.")
            verification = state.get("verification")
            same_binding = (
                isinstance(verification, dict)
                and verification.get("runner_repository") == runner_repository
                and verification.get("billing_mode", "private") == billing_mode
            )
            if not isinstance(verification, dict) or verification.get("config_revision") != config_revision or not same_binding:
                verification = {
                    "config_revision": config_revision,
                    "checked_at": task_result["checked_at"],
                    "passed": False,
                    "eligible_sources": len(state["selected_source_ids"]),
                    "cursor": "",
                    "checked_sources": 0,
                    "completed_sources": 0,
                    "failed_sources": 0,
                    "error_codes": [],
                    "source_results": [],
                    "task_results": [],
                    "runner_repository": runner_repository,
                    "billing_mode": billing_mode,
                }
            task_map = {row["task_key"]: row for row in verification["task_results"]}
            task_map[task_result["task_key"]] = task_result
            task_rows = [task_map[key] for key in sorted(task_map)]
            _validate_verification_task_results(task_rows)
            result_map = {row["source_id"]: row for row in verification["source_results"]}
            if source_result is not None:
                result_map[source_result["source_id"]] = source_result
            selected = set(state["selected_source_ids"])
            source_rows = [result_map[key] for key in sorted(result_map) if key in selected]
            checked_source_ids = {row["source_id"] for row in task_rows if row["source_id"] in selected}
            completed = sum(row["passed"] for row in source_rows)
            failed = sum(not row["passed"] for row in source_rows if row["source_id"] in checked_source_ids)
            codes = sorted({
                row["error_code"] for row in task_rows
                if row["source_id"] in selected and row["error_code"] != "none"
            } | {
                row["error_code"] for row in source_rows if row["error_code"] != "none"
            })
            verification.update({
                "checked_at": task_result["checked_at"],
                "passed": False,
                "eligible_sources": len(selected),
                "cursor": task_result["task_key"],
                "checked_sources": len(checked_source_ids),
                "completed_sources": completed,
                "failed_sources": failed,
                "error_codes": codes,
                "source_results": source_rows,
                "task_results": task_rows,
            })
            state["verification"] = verification
            state["source_results"] = source_rows
            state["progress"] = {
                "eligible_sources": len(selected),
                "checked_sources": len(checked_source_ids),
                "completed_sources": completed,
                "failed_sources": failed,
                "uncertain_alert_count": state["uncertain_alert_count"],
                "error_codes": codes,
            }
            state["hosted_last_attempt"] = task_result["checked_at"]
            _change_status(state, "hosted_partial" if codes else "none")
            accepted["ok"] = True

        _, saved = self.ledger.change(save)
        if not accepted["ok"]:
            raise HostingError("The verification task result was not accepted.")
        return saved

    def record_verification(
        self, *, config_revision: str, checked_at: str, source_results: list[dict],
        task_results: list[dict] | None = None, cursor: str = "",
        runner_repository: str | None = None, billing_mode: str = "private",
    ) -> dict:
        """Merge current-revision task/source results and report truthful coverage."""
        _validate_source_results(source_results)
        if task_results is not None:
            _validate_verification_task_results(task_results)
        if cursor and not (
            re.fullmatch(r"d:[a-z0-9][a-z0-9_-]{0,63}", cursor)
            or re.fullmatch(r"w:\d{1,16}", cursor)
        ):
            raise HostingError("The cloud verification cursor is invalid.")
        if billing_mode not in {"private", "public"} or (
            runner_repository is not None
            and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", runner_repository) is None
        ) or (billing_mode == "public" and runner_repository is None):
            raise HostingError("The verification runner binding is invalid.")
        accepted = {"ok": False}

        def save(state: dict) -> None:
            if self.role != "verification" or not self.owned(state):
                raise HostingError("Verification lost its shared lease; results were rejected.")
            if state["config_revision"] != config_revision:
                raise HostingError("The application configuration changed during cloud verification.")
            checked_time = timestamp(parse_time(checked_at))
            previous = state.get("verification") or {}
            same_binding = (
                previous.get("runner_repository") == runner_repository
                and previous.get("billing_mode", "private") == billing_mode
            )
            task_map = {
                row["task_key"]: row for row in (
                    previous.get("task_results", [])
                    if previous.get("config_revision") == config_revision and same_binding else []
                )
            }
            for row in task_results or []:
                task_map[row["task_key"]] = row
            merged_tasks = [task_map[key] for key in sorted(task_map)]
            _validate_verification_task_results(merged_tasks)
            result_map = {
                row["source_id"]: row for row in (
                    previous.get("source_results", [])
                    if previous.get("config_revision") == config_revision and same_binding else []
                )
            }
            result_map.update({row["source_id"]: row for row in source_results})
            selected = state["selected_source_ids"]
            checked_task_ids = {row["source_id"] for row in merged_tasks if row["source_id"] in selected}
            selected_rows = [result_map.get(source_id) for source_id in selected]
            source_rows = [row for row in selected_rows if row is not None and row["source_id"] in checked_task_ids]
            checked = len(checked_task_ids)
            completed = sum(row["passed"] for row in source_rows)
            failed = sum(not row["passed"] for row in source_rows)
            passed = bool(selected) and checked == len(selected) and completed == len(selected)
            codes = sorted({
                row["error_code"] for row in merged_tasks
                if row["source_id"] in selected and row["error_code"] != "none"
            } | {row["error_code"] for row in source_rows if row["error_code"] != "none"})
            if checked < len(selected) and not codes:
                codes = ["source_incomplete"]
            final_cursor = cursor or (previous.get("cursor", "") if previous.get("config_revision") == config_revision else "")
            state["source_results"] = source_rows
            state["verification"] = {
                "config_revision": config_revision,
                "checked_at": checked_time,
                "passed": passed,
                "eligible_sources": len(selected),
                "cursor": final_cursor,
                "checked_sources": checked,
                "completed_sources": completed,
                "failed_sources": failed,
                "error_codes": codes,
                "source_results": source_rows,
                "task_results": merged_tasks,
                "runner_repository": runner_repository,
                "billing_mode": billing_mode,
            }
            state["progress"] = {
                "eligible_sources": len(selected),
                "checked_sources": checked,
                "completed_sources": completed,
                "failed_sources": failed,
                "uncertain_alert_count": state["uncertain_alert_count"],
                "error_codes": codes,
            }
            state["hosted_last_attempt"] = checked_time
            _change_status(state, "none" if passed else "hosted_partial")
            accepted["ok"] = True

        _, saved = self.ledger.change(save)
        if not accepted["ok"]:
            raise HostingError("Cloud verification was not accepted.")
        return saved

    def set_source_selection(self, source_ids: list[str]) -> dict:
        """Set the explicitly cloud-verified subset and invalidate old verification."""
        if not isinstance(source_ids, list) or len(source_ids) > 200:
            raise HostingError("The cloud source selection is invalid.")
        normalized = sorted(set(source_ids))
        if any(not isinstance(item, str) or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", item) is None for item in normalized):
            raise HostingError("The cloud source selection contains an invalid source.")
        current, _ = self.ledger.read()
        snapshot = self.ledger.load_snapshot(current)
        available = set(_candidate_ids(snapshot))
        if not set(normalized).issubset(available):
            raise HostingError("The cloud selection includes an unsupported source.")
        expected_revision = current["config_revision"]

        def update(state: dict) -> None:
            if state["config_revision"] != expected_revision:
                raise HostingError("The application configuration changed while saving the cloud selection.")
            if state["selected_source_ids"] != normalized:
                state["selected_source_ids"] = normalized
                verification = state.get("verification")
                if verification and verification.get("config_revision") == expected_revision:
                    selected_set = set(normalized)
                    task_rows = [row for row in verification.get("task_results", []) if row["source_id"] in selected_set]
                    by_id = {row["source_id"]: row for row in state["source_results"] if row["source_id"] in selected_set}
                    selected_results = [by_id.get(source_id) for source_id in normalized]
                    checked_ids = {row["source_id"] for row in task_rows}
                    checked = len(checked_ids)
                    completed = sum(row is not None and row["passed"] for row in selected_results)
                    failed = sum(row is not None and not row["passed"] for row in selected_results)
                    passed = bool(normalized) and checked == len(normalized) and completed == len(normalized)
                    verification["passed"] = passed
                    verification["eligible_sources"] = len(normalized)
                    verification["checked_sources"] = checked
                    verification["completed_sources"] = completed
                    verification["failed_sources"] = failed
                    verification["cursor"] = ""
                    verification["task_results"] = task_rows
                    verification["error_codes"] = sorted({row["error_code"] for row in selected_results if row and row["error_code"] != "none"})
                    verification["source_results"] = [row for row in selected_results if row is not None]
                    state["source_results"] = verification["source_results"]
                    state["progress"].update({
                        "eligible_sources": len(normalized),
                        "checked_sources": checked,
                        "completed_sources": completed,
                        "failed_sources": failed,
                        "error_codes": verification["error_codes"],
                    })
                else:
                    state["verification"] = None
                state["armed"] = False
                state["hosted_cursor"] = {"config_revision": state["config_revision"], "task_key": "", "updated_at": timestamp(self.clock())}
                _change_status(state, "config_changed")

        _, saved = self.ledger.change(update)
        return saved

    def sync_snapshot(self, snapshot: dict) -> dict:
        """Upload local durable state; a config revision change disarms hosted checks."""
        if not isinstance(snapshot, dict) or snapshot.get("schema_version") != 1 or not _digest(snapshot.get("config_revision")):
            raise HostingError("The application snapshot has no valid configuration fingerprint.")
        current, current_sha = self.ledger.read()
        if not self.owned(current):
            raise HostingError("This monitor lost its shared lease; the snapshot was rejected.")
        pointer = self.ledger.upload_snapshot(
            snapshot,
            expected_blob_sha=(current.get("snapshot") or {}).get("blob_sha") or None,
        )

        def update(state: dict) -> None:
            if not self.owned(state):
                raise HostingError("This monitor lost its shared lease; the snapshot pointer was rejected.")
            new_revision = snapshot["config_revision"]
            if new_revision != state["config_revision"]:
                state["config_revision"] = new_revision
                state["snapshot"] = pointer
                state["selected_source_ids"] = [item for item in state["selected_source_ids"] if item in set(_candidate_ids(snapshot))]
                state["verification"] = None
                state["armed"] = False
                state["hosted_cursor"] = {"config_revision": new_revision, "task_key": "", "updated_at": timestamp(self.clock())}
                state["source_results"] = []
                _change_status(state, "config_changed")
            else:
                state["snapshot"] = pointer
                _change_status(state)

        _, saved = self.ledger.change(update, initial=(current, current_sha))
        return saved

    def heartbeat(self) -> bool:
        if self.role != "windows":
            return False
        if self.generation is None:
            ok, _ = self.acquire()
            return ok
        return self.renew()

    def release(self) -> bool:
        released = False

        def clear(state: dict) -> None:
            nonlocal released
            if self.owned(state):
                state["lease"] = None
                _change_status(state)
                released = True

        _, _ = self.ledger.change(clear)
        self.generation = None
        return released

    def pause_all(self) -> dict:
        """Set the explicit global pause and fence every currently running worker."""
        self.generation = None

        def pause(state: dict) -> None:
            state["paused"] = True
            state["lease"] = None
            state["generation"] += 1
            _change_status(state)

        _, saved = self.ledger.change(pause)
        return saved

    def resume_all(self) -> dict:
        """Clear the explicit global pause; local ownership must still be claimed."""
        self.generation = None

        def resume(state: dict) -> None:
            if state["paused"]:
                state["paused"] = False
                state["lease"] = None
                state["generation"] += 1
                _change_status(state, "none")

        _, saved = self.ledger.change(resume)
        return saved

    def unarm(self) -> dict:
        """Disable hosted takeover and invalidate any in-flight cloud generation."""
        self.generation = None

        def disarm(state: dict) -> None:
            state["armed"] = False
            state["verification"] = None
            state["lease"] = None
            state["generation"] += 1
            _change_status(state)

        _, saved = self.ledger.change(disarm)
        return saved


def recent_budget_block(state: dict, *, now: datetime | None = None) -> bool:
    """Fail closed when the durable account guard or minimum reserve is unavailable."""
    budget = state["budget"]
    # A null valid_until means the owner verified the account guard at setup or
    # activation and approved a fixed monthly allocation. Fresh proof is needed
    # for those local actions, not every week while the cloud runner is unattended.
    return bool(budget["blocked"] or budget["monthly_minutes_cap"] < 2)


def reserve_run_minutes(state: dict, *, month: str, run_key: str, worst_case_minutes: int, now: datetime | None = None) -> bool:
    """Reserve a whole job timeout before starting source work, including verification."""
    if not re.fullmatch(r"\d{4}-\d{2}", month) or not isinstance(run_key, str) or not run_key or len(run_key) > 100:
        return False
    if type(worst_case_minutes) is not int or not 1 <= worst_case_minutes <= 10:
        return False
    ids = state["run_ids"].get(month, [])
    if run_key in ids:
        return True
    state["budget"]["reserved_minutes"] = state["monthly_minutes"].get(month, 0)
    if recent_budget_block(state, now=now):
        state["budget"]["blocked"] = True
        state["last_error_code"] = "budget_blocked"
        _change_status(state, "budget_blocked")
        return False
    if state["budget"]["reserved_minutes"] + worst_case_minutes > state["budget"]["monthly_minutes_cap"]:
        # This is a true allocation exhaustion. Eligibility-only denials are
        # handled by the runner's smaller reserve and must not set this flag.
        state["budget"]["blocked"] = True
        state["last_error_code"] = "budget_blocked"
        _change_status(state, "budget_blocked")
        return False
    if len(ids) >= MAX_RUN_IDS_PER_MONTH:
        state["budget"]["blocked"] = True
        state["last_error_code"] = "budget_blocked"
        _change_status(state, "budget_blocked")
        return False
    state["run_ids"].setdefault(month, []).append(run_key)
    state["monthly_minutes"][month] = state["monthly_minutes"].get(month, 0) + worst_case_minutes
    state["monthly_runs"][month] = state["monthly_runs"].get(month, 0) + 1
    state["budget"]["reserved_minutes"] += worst_case_minutes
    for mapping in (state["monthly_minutes"], state["monthly_runs"], state["run_ids"]):
        for old_month in sorted(mapping)[:-MAX_MONTHS]:
            mapping.pop(old_month, None)
    _change_status(state)
    return True
