"""Finite, manually dispatched GitHub Actions entry points for Premium Watch."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .hosting import (
    BRANCH,
    REPOSITORY,
    OFFLINE_SECONDS,
    HostingError,
    GitHubLedger,
    SharedMonitor,
    _ERROR_CODES,
    _lease_active,
    _change_status,
    now_utc,
    parse_time,
    recent,
    reserve_run_minutes,
    timestamp,
    _validate_verification_task_results,
)


REPOSITORY_ENV = "PRIVATE_STATE_REPOSITORY"
TOKEN_ENV = "PREMIUM_STATE_TOKEN"
LEGACY_REPOSITORY_ENV = "PREMIUM_WATCH_HOSTED_REPOSITORY"
LEGACY_TOKEN_ENV = "PREMIUM_WATCH_GITHUB_TOKEN"
PUBLIC_RUNNER_ENV = "PREMIUM_WATCH_PUBLIC_RUNNER"
BILLING_MODE_ENV = "PREMIUM_WATCH_BILLING_MODE"
RUNNER_GITHUB_TOKEN_ENV = "GITHUB_TOKEN"
WEBHOOK_ENV = "PREMIUM_WATCH_DISCORD_WEBHOOK"
RESERVATION_TIMEOUT_MINUTES = 2
PROVIDER_JOB_TIMEOUT_MINUTES = 4
VERIFY_TIMEOUT_MINUTES = RESERVATION_TIMEOUT_MINUTES + PROVIDER_JOB_TIMEOUT_MINUTES
RUN_TIMEOUT_MINUTES = RESERVATION_TIMEOUT_MINUTES + PROVIDER_JOB_TIMEOUT_MINUTES
SOFT_VERIFY_SECONDS = 600
SOFT_SCAN_SECONDS = 600
MAX_HOSTED_CHECKS = 100
FINAL_STATE_PUBLISH_RESERVE_SECONDS = 90
JOB_DEADLINE_ENV = "PREMIUM_WATCH_PROVIDER_JOB_DEADLINE_EPOCH"
HOSTED_EXECUTION_CONTEXT = "premium-watch/public-runner/v1"


class RunnerError(RuntimeError):
    """A finite hosted check was safely skipped or could not be completed."""


def _ledger(repository: str | None = None, token: str | None = None) -> GitHubLedger:
    repository = (repository or os.environ.get(REPOSITORY_ENV, "") or os.environ.get(LEGACY_REPOSITORY_ENV, "")).strip()
    token = (token or os.environ.get(TOKEN_ENV, "") or os.environ.get(LEGACY_TOKEN_ENV, "")).strip()
    if not repository or not token:
        raise RunnerError("Hosted private state access is not configured.")
    return GitHubLedger(
        repository,
        token,
        require_private_repository=_public_runner_mode(),
    )


def _public_runner_mode() -> bool:
    return os.environ.get(BILLING_MODE_ENV, "").strip().casefold() == "public"


def _verify_private_state_repository(ledger) -> None:
    """Verify state remains private before any public-job state access."""
    if not _public_runner_mode():
        return
    verify = getattr(ledger, "verify_private_repository", None)
    try:
        info = verify() if callable(verify) else None
    except Exception:
        raise RunnerError("The private state repository could not be verified safely.") from None
    repository = getattr(ledger, "repository", "")
    if (
        not isinstance(info, dict)
        or info.get("private") is not True
        or not isinstance(repository, str)
        or str(info.get("full_name", "")).casefold() != repository.casefold()
    ):
        raise RunnerError("The configured cloud state repository must be private.")


def validate_public_runner_environment(*, opener=urlopen) -> None:
    """Fail closed unless this is the intended public GitHub-hosted Linux runner."""
    repository = os.environ.get("GITHUB_REPOSITORY", "").strip()
    token = os.environ.get(RUNNER_GITHUB_TOKEN_ENV, "").strip()
    if (
        os.environ.get(PUBLIC_RUNNER_ENV, "").casefold() != "true"
        or not repository
        or re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", repository) is None
        or not token
        or os.environ.get("RUNNER_OS", "") != "Linux"
        or os.environ.get("RUNNER_ENVIRONMENT", "") != "github-hosted"
        or not os.environ.get("ImageOS", "").casefold().startswith("ubuntu")
    ):
        raise RunnerError("The public hosted runner environment is not eligible.")
    request = Request(
        f"https://api.github.com/repos/{repository}",
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "PremiumWatch/public-runner",
        },
    )
    try:
        with opener(request, timeout=15) as response:
            raw = response.read(500_001)
        if len(raw) > 500_000:
            raise ValueError("response size")
        info = json.loads(raw) if raw else {}
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, UnicodeDecodeError):
        raise RunnerError("The public runner repository could not be verified safely.") from None
    if (
        not isinstance(info, dict)
        or info.get("private") is not False
        or info.get("fork") is True
        or str(info.get("full_name", "")).casefold() != repository.casefold()
    ):
        raise RunnerError("The public runner repository is not eligible.")


def _append_step_summary(title: str, lines: list[str]) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "").strip()
    if summary_path:
        with open(summary_path, "a", encoding="utf-8", newline="\n") as output:
            output.write("\n## " + title + "\n\n")
            output.write("\n".join(lines).rstrip() + "\n")


def _set_output(name: str, value: str) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT", "").strip()
    if output_path and re.fullmatch(r"[a-z_]+", name):
        with open(output_path, "a", encoding="utf-8", newline="\n") as output:
            output.write(f"{name}={value}\n")


def _month(now: datetime | None = None) -> str:
    return (now or now_utc()).astimezone(timezone.utc).strftime("%Y-%m")


def _provider_budget_seconds(soft_limit: int) -> float:
    """Subtract checkout/setup time and keep a final state-publish reserve."""
    value = os.environ.get(JOB_DEADLINE_ENV, "").strip()
    if not value:
        return float(soft_limit)
    try:
        deadline_epoch = float(value)
    except ValueError:
        return 0.0
    if not deadline_epoch > 0:
        return 0.0
    return max(0.0, min(float(soft_limit), deadline_epoch - time.time() - FINAL_STATE_PUBLISH_RESERVE_SECONDS))


def _run_key() -> str:
    run_id = os.environ.get("GITHUB_RUN_ID", "manual").strip() or "manual"
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1").strip() or "1"
    return f"{run_id}:{attempt}"[:100]


def _gate_reason(
    state: dict, mode: str, *, now: datetime | None = None, already_reserved: bool = False,
    public_runner: bool = False, runner_repository: str | None = None,
) -> str | None:
    moment = now or now_utc()
    if state["paused"]:
        return "Monitoring is paused by the owner."
    if mode == "run" and recent(state["windows_heartbeat"], OFFLINE_SECONDS, now=moment):
        return "The PC reported within the ten-minute ownership window."
    lease = state.get("lease") or {}
    verify_can_quiesce_pc = mode == "verify" and lease.get("role") == "windows" and not state["armed"]
    if lease and _lease_active(lease, moment) and not verify_can_quiesce_pc:
        return "Another monitor still owns the exclusive check lease."
    budget = state["budget"]
    if budget["blocked"] and not public_runner:
        return "The durable account-wide Actions budget guard is blocked."
    if not public_runner:
        month = _month(moment)
        used = int(state["monthly_minutes"].get(month, 0))
        timeout = VERIFY_TIMEOUT_MINUTES if mode == "verify" else RUN_TIMEOUT_MINUTES
        if used + (0 if already_reserved else timeout) > budget["monthly_minutes_cap"]:
            return "The conservative monthly Actions minute cap has been reached."
    if mode == "verify":
        if state["armed"]:
            return "Cloud verification is available only while hosted monitoring is unarmed."
        if not state["selected_source_ids"]:
            return "Choose at least one public source before starting cloud verification."
        return None
    if mode != "run":
        return "The hosted check mode is invalid."
    verification = state.get("verification") or {}
    if (
        not state["armed"]
        or not verification.get("passed")
        or verification.get("config_revision") != state["config_revision"]
        or not state["selected_source_ids"]
    ):
        return "Hosted monitoring is not armed for the current verified source selection."
    if public_runner and (
        verification.get("billing_mode") != "public"
        or verification.get("runner_repository", "").casefold() != str(runner_repository or "").casefold()
    ):
        return "The public runner has not passed verification for the current configuration."
    verified_ids = {row["source_id"] for row in verification.get("source_results", []) if row["passed"]}
    if not set(state["selected_source_ids"]).issubset(verified_ids):
        return "A selected cloud source has not passed current verification."
    return None


def preflight(mode: str = "run", *, ledger: GitHubLedger | None = None) -> bool:
    """Read-only guard before dependency installation; never scans a retailer."""
    if mode not in {"verify", "run"}:
        raise RunnerError("The preflight mode is invalid.")
    remote = ledger or _ledger()
    state, _ = remote.read()
    reserved = _run_key() in state.get("run_ids", {}).get(_month(), [])
    reason = _gate_reason(state, mode, already_reserved=reserved)
    should_run = reason is None
    _set_output("should_run", "true" if should_run else "false")
    _append_step_summary("Premium Watch preflight", [reason or "The private state is eligible for one bounded hosted operation."])
    return should_run


def reserve_budget(mode: str = "verify", *, ledger: GitHubLedger | None = None) -> bool:
    """Reserve worst-case workflow minutes before read-only prep or dependency install."""
    if mode not in {"verify", "run"}:
        raise RunnerError("The budget reservation mode is invalid.")
    remote = ledger or _ledger()
    moment = now_utc()
    month = _month(moment)
    run_key = _run_key()
    result = {"allowed": False, "reason": "The hosted dispatch was safely blocked."}

    def reserve(state: dict) -> None:
        existing = run_key in state.get("run_ids", {}).get(month, [])
        reason = _gate_reason(state, mode, now=moment, already_reserved=existing)
        if existing:
            result["allowed"] = reason is None
            result["reason"] = reason or "The hosted dispatch already has a full worst-case reservation."
            return
        # An eligible dispatch reserves both hard job timeouts. If a pause,
        # active PC lease, or other preflight rule blocks the provider job, only
        # the reservation job runs and is charged. This leaves the remaining
        # monthly allocation available for a later eligible attempt.
        worst_case = VERIFY_TIMEOUT_MINUTES if reason is None else RESERVATION_TIMEOUT_MINUTES
        if reserve_run_minutes(
                state,
                month=month,
                run_key=run_key,
                worst_case_minutes=worst_case,
                now=moment,
        ):
            result["allowed"] = reason is None
            result["reason"] = reason or "The bounded hosted dispatch is reserved."
            return
        state["last_error_code"] = "budget_blocked"
        _change_status(state, "budget_blocked")
        result["allowed"] = False
        result["reason"] = reason or "The safe monthly Actions allowance is exhausted."

    _, state = remote.change(reserve)
    _set_output("should_run", "true" if result["allowed"] else "false")
    _append_step_summary("Premium Watch budget reservation", [str(result["reason"])[:220]])
    return bool(result["allowed"])


def _reserve_job(ledger: GitHubLedger, mode: str, *, now: datetime | None = None) -> tuple[SharedMonitor | None, dict, str | None]:
    """Reserve the whole hard-timeout cost before any provider request."""
    moment = now or now_utc()
    public_runner = _public_runner_mode()
    runner_repository = os.environ.get("GITHUB_REPOSITORY", "").strip() if public_runner else None
    if public_runner:
        state, _ = ledger.read()
        reason = _gate_reason(
            state, mode, now=moment, public_runner=True, runner_repository=runner_repository,
        )
        if reason:
            return None, state, reason
    else:
        state = None
    decision: dict[str, object] = {"allowed": False, "reason": None}
    if public_runner:
        decision["allowed"] = True
    else:
        minutes = VERIFY_TIMEOUT_MINUTES if mode == "verify" else RUN_TIMEOUT_MINUTES

        def reserve(current: dict) -> None:
            reserved = reserve_run_minutes(
                current,
                month=_month(moment),
                run_key=_run_key(),
                worst_case_minutes=minutes,
                now=moment,
            )
            if not reserved:
                decision["reason"] = "The conservative monthly Actions minute cap is exhausted."
                decision["allowed"] = False
                return
            reason = _gate_reason(current, mode, now=moment, already_reserved=True)
            if reason:
                current["last_error_code"] = _error_code(reason)
                _change_status(current, current["last_error_code"])
                decision["reason"] = reason
                decision["allowed"] = False
            else:
                decision["allowed"] = True
                decision["reason"] = None

        _, state = ledger.change(reserve)
    if not decision["allowed"]:
        return None, state, str(decision["reason"] or "The hosted operation was safely skipped.")
    role = "verification" if mode == "verify" else "hosted"
    monitor = SharedMonitor(ledger, role)
    acquired, state = monitor.acquire()
    if not acquired:
        reason = {
            "pc_online": "The PC reported recently; the hosted operation was skipped.",
            "paused": "Monitoring is paused by the owner.",
            "verification_required": "Hosted monitoring is not armed and verified for the current configuration.",
        }.get(monitor.last_reason, "Another monitor owns the exclusive check lease.")
        return None, state, reason
    return monitor, state, None


def _error_code(value: object) -> str:
    if isinstance(value, str) and value in _ERROR_CODES:
        return value
    label = str(value or "").casefold()
    if label in {"budget_exhausted", "partial_run", "budget_exhausted_stop"}:
        return "source_incomplete"
    if "pc reported" in label or "pc online" in label:
        return "pc_online"
    if "verification" in label or "verified source" in label:
        return "verification_required"
    if "budget" in label or "allowance" in label or "minutes" in label:
        return "budget_blocked"
    if "lease" in label or "ownership" in label or "another monitor" in label:
        return "lease_conflict"
    if "market" in label or "region" in label or "currency" in label or "context" in label:
        return "market_context_mismatch"
    if "timeout" in label or "timed out" in label:
        return "source_timeout"
    if "block" in label or "challenge" in label or "403" in label:
        return "source_blocked"
    if "incomplete" in label or "partial" in label or "limit" in label:
        return "source_incomplete"
    return "provider_unavailable"


def _service_for(snapshot: dict, monitor: SharedMonitor, data_dir: Path):
    from .service import PremiumService

    seed_sources = Path(data_dir).parent / "empty-sources.json"
    seed_sources.parent.mkdir(parents=True, exist_ok=True)
    seed_sources.write_text("[]", encoding="utf-8")
    service = PremiumService(
        data_dir=data_dir,
        sources_file=seed_sources,
        execution_context_id=HOSTED_EXECUTION_CONTEXT,
    )
    imported = service.import_hosted_snapshot(
        snapshot,
        expected_config_revision=snapshot["config_revision"],
        hosted=True,
        ownership_check=lambda _phase: monitor.fenced(),
    )
    if not isinstance(imported, dict) or imported.get("status") not in {"complete", "imported", "ok"}:
        raise RunnerError("The allow-listed application snapshot could not be imported safely.")
    service.set_ownership_check(monitor.fenced)
    return service


def _source_result(row: dict) -> dict:
    """Reduce provider output to source ID, coverage counts, and safe code only."""
    source_id = str(row.get("source_id") or "")
    if re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", source_id) is None:
        raise RunnerError("The source verifier returned an invalid source identifier.")
    raw_coverage = row.get("coverage") or {}
    if not isinstance(raw_coverage, dict):
        raw_coverage = {}
    coverage = {}
    for key in ("discovered_products", "discovered_variants", "watches_checked", "observations"):
        value = raw_coverage.get(key, 0)
        coverage[key] = max(0, min(int(value), 100_000)) if type(value) in (int, float) else 0
    context = row.get("market_context_id")
    if context is not None:
        context = str(context)[:100]
    return {
        "source_id": source_id,
        "passed": row.get("passed") is True,
        "checked_at": str(row.get("checked_at") or timestamp()),
        "coverage": coverage,
        "error_code": "none" if row.get("passed") is True else _error_code(row.get("error_code")),
        "market_context_id": context,
    }


def _verification_task_result(row: dict) -> dict:
    """Keep only the bounded safe IDs, counters, status, and context digest."""
    if not isinstance(row, dict):
        raise RunnerError("The source verifier returned an invalid task checkpoint.")
    task_key = _task_key(row.get("task_key"))
    source_id = str(row.get("source_id") or "")
    if re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", source_id) is None:
        raise RunnerError("The source verifier returned an invalid task source identifier.")
    kind = row.get("task_kind")
    if kind not in {"discovery", "watch"}:
        raise RunnerError("The source verifier returned an invalid task kind.")
    passed = row.get("passed") is True
    error_code = "none" if passed else _error_code(row.get("error_code"))
    raw_coverage = row.get("coverage") or {}
    if not isinstance(raw_coverage, dict):
        raw_coverage = {}
    coverage = {
        key: max(0, min(int(raw_coverage.get(key, 0)), 100_000))
        if type(raw_coverage.get(key, 0)) in (int, float) else 0
        for key in ("discovered_products", "discovered_variants", "watches_checked", "observations")
    }
    context = row.get("market_context_id")
    if context is not None and (
        not isinstance(context, str)
        or (context not in {"unknown", "mixed"} and re.fullmatch(r"[0-9a-f]{16}", context) is None)
    ):
        context = "unknown"
    checked_at = str(row.get("checked_at") or timestamp())
    try:
        checked_at = timestamp(parse_time(checked_at))
    except (TypeError, ValueError, OverflowError):
        raise RunnerError("The source verifier returned an invalid task timestamp.") from None
    safe = {
        "task_key": task_key,
        "source_id": source_id,
        "task_kind": kind,
        "passed": passed,
        "error_code": error_code,
        "coverage": coverage,
        "market_context_id": context,
        "checked_at": checked_at,
    }
    _validate_verification_task_results([safe])
    return safe


def _scan_progress(selected_source_ids: list[str], source_results: list[dict], *, uncertain_alert_count: int) -> dict:
    """Count only sources on which the current hosted slice started a unit."""
    selected = set(selected_source_ids)
    checked_rows = [
        row for row in source_results
        if isinstance(row, dict)
        and row.get("source_id") in selected
        and type(row.get("attempted_tasks")) is int
        and row["attempted_tasks"] > 0
    ]
    checked_ids = {row["source_id"] for row in checked_rows}
    completed_ids = {
        row["source_id"] for row in checked_rows
        if row.get("status") in {"complete", "healthy", "success"}
    }
    error_codes = sorted({
        _error_code(row.get("error_code")) for row in checked_rows
        if row.get("error_code") and row.get("error_code") != "none"
    })
    return {
        "eligible_sources": len(selected),
        "checked_sources": len(checked_ids),
        "completed_sources": len(completed_ids),
        "failed_sources": len(checked_ids - completed_ids),
        "uncertain_alert_count": max(0, min(int(uncertain_alert_count), 100_000)),
        "error_codes": error_codes,
    }


def _scan_task_progress(
    selected_source_ids: list[str], attempted_source_ids: set[str], source_id: object,
    *, uncertain_alert_count: int,
) -> dict:
    selected = set(selected_source_ids)
    if isinstance(source_id, str) and source_id in selected:
        attempted_source_ids.add(source_id)
    return {
        "eligible_sources": len(selected),
        "checked_sources": len(attempted_source_ids & selected),
        "completed_sources": 0,
        "failed_sources": 0,
        "uncertain_alert_count": max(0, min(int(uncertain_alert_count), 100_000)),
        "error_codes": [],
    }


def verify_sources(*, ledger: GitHubLedger | None = None) -> dict:
    """Check the selected public-source set in Linux without persisting data or sending Discord."""
    remote = ledger or _ledger()
    _verify_private_state_repository(remote)
    monitor, state, reason = _reserve_job(remote, "verify")
    if monitor is None:
        _append_step_summary("Cloud source verification", [reason or "Verification was safely skipped."])
        return {"status": "paused", "reason": reason}

    scratch = None
    try:
        public_runner = _public_runner_mode()
        runner_repository = os.environ.get("GITHUB_REPOSITORY", "").strip() if public_runner else None
        billing_mode = "public" if public_runner else "private"
        snapshot = remote.load_snapshot(state)
        selected = list(state["selected_source_ids"])
        if not selected:
            raise RunnerError("Choose at least one public source before starting cloud verification.")
        scratch = tempfile.TemporaryDirectory(prefix="premium-watch-verify-")
        service = _service_for(snapshot, monitor, Path(scratch.name) / "data")

        max_seconds = _provider_budget_seconds(SOFT_VERIFY_SECONDS)
        if max_seconds < 10:
            raise RunnerError("The provider job has too little time left for a safe verification request.")

        previous_verification = state.get("verification") or {}
        can_resume = (
            previous_verification.get("config_revision") == state["config_revision"]
            and previous_verification.get("billing_mode", "private") == billing_mode
            and previous_verification.get("runner_repository") == runner_repository
        )
        def checkpoint(metadata: dict) -> bool:
            if not monitor.fenced():
                return False
            task = _verification_task_result(metadata.get("task_result"))
            source_row = metadata.get("source_result")
            safe_source = _source_result(source_row) if isinstance(source_row, dict) else None
            latest = monitor.record_verification_task(
                config_revision=state["config_revision"], task_result=task, source_result=safe_source,
                runner_repository=runner_repository, billing_mode=billing_mode,
            )
            remote.publish_status()
            return monitor.fenced() and latest["config_revision"] == state["config_revision"]

        result = service.verify_hosted_sources(
            selected,
            max_seconds=max_seconds,
            max_checks=MAX_HOSTED_CHECKS,
            cursor=previous_verification.get("cursor") if can_resume else None,
            completed_task_results=previous_verification.get("task_results", []) if can_resume else [],
            checkpoint_callback=checkpoint,
        )
        if not monitor.fenced():
            raise RunnerError("Verification lost its shared lease before saving the result.")
        rows = [_source_result(row) for row in result.get("sources", []) if isinstance(row, dict)]
        task_rows = [
            _verification_task_result(row)
            for row in result.get("task_results", []) if isinstance(row, dict)
        ]
        checked_at = str(result.get("checked_at") or timestamp())
        state = monitor.record_verification(
            config_revision=state["config_revision"],
            checked_at=checked_at,
            source_results=rows,
            task_results=task_rows,
            cursor=_task_key(result.get("cursor") or ""),
            runner_repository=runner_repository,
            billing_mode=billing_mode,
        )
        passed = bool((state.get("verification") or {}).get("passed"))
        selected_count = len(state["selected_source_ids"])
        checked = int((state.get("verification") or {}).get("checked_sources", 0))
        completed = int((state.get("verification") or {}).get("completed_sources", 0))
        failed = int((state.get("verification") or {}).get("failed_sources", 0))
        _append_step_summary(
            "Cloud source verification",
            [
                f"Coverage: {checked}/{selected_count} selected public sources checked; {completed} passed; {failed} failed.",
                "No local database was changed and no Discord message was sent.",
                "Failed or unselected sources remain available to the local Windows monitor.",
            ],
        )
        monitor.release()
        remote.publish_status(force=True)
        if result.get("status") != "complete" or not passed:
            return {"status": "partial", "checked": checked, "completed": completed, "failed": failed}
        return {"status": "complete", "checked": checked, "completed": completed, "failed": failed}
    except Exception as exc:
        try:
            def save_failure(current: dict) -> None:
                if monitor.owned(current):
                    current["last_error_code"] = "hosted_failed"
                    current["hosted_last_attempt"] = timestamp()
                    _change_status(current, "hosted_failed")

            remote.change(save_failure)
        except Exception:
            pass
        monitor.release()
        try:
            remote.publish_status(force=True)
        except Exception:
            pass
        if isinstance(exc, RunnerError) and "too little time left" in str(exc):
            raise RunnerError("The provider job has too little time left for a safe verification request.") from None
        code = _error_code(exc)
        _append_step_summary("Cloud source verification", [f"Verification stopped safely ({code}).", "No Discord message was sent."])
        raise RunnerError(f"Verification stopped safely ({code}).") from None
    finally:
        if scratch is not None:
            scratch.cleanup()


def _task_key(value: object) -> str:
    if isinstance(value, str) and len(value) <= 180 and (not value or re.fullmatch(r"[dw]:[A-Za-z0-9_-]{1,160}", value)):
        return value
    raise RunnerError("The hosted scan returned an invalid resumable cursor.")


def run_hosted_scan(*, ledger: GitHubLedger | None = None) -> dict:
    """Run one small due-work slice through the shared fenced lease."""
    remote = ledger or _ledger()
    _verify_private_state_repository(remote)
    monitor, state, reason = _reserve_job(remote, "run")
    if monitor is None:
        _append_step_summary("Hosted check", [reason or "The hosted check was safely skipped."])
        return {"status": "paused", "reason": reason}
    scratch = None
    try:
        webhook = os.environ.get(WEBHOOK_ENV, "").strip()
        if not webhook:
            raise RunnerError("The hosted Discord secret is missing.")
        snapshot = remote.load_snapshot(state)
        service_cursor = state["hosted_cursor"].get("task_key") or None
        selected = list(state["selected_source_ids"])
        if not selected:
            raise RunnerError("No verified cloud sources are selected.")
        scratch = tempfile.TemporaryDirectory(prefix="premium-watch-run-")
        service = _service_for(snapshot, monitor, Path(scratch.name) / "data")
        service.set_hosted_webhook(webhook)
        max_seconds = _provider_budget_seconds(SOFT_SCAN_SECONDS)
        if max_seconds < 10:
            # Fail closed after dependency/setup time has consumed the safe
            # provider window. Persist a truthful timeout status while this
            # invocation still owns the lease; no shop or cart request starts.
            monitor.checkpoint(error_code="source_timeout")
            remote.publish_status()
            raise RunnerError("The provider job has too little time left for a safe hosted check.")
        attempted_source_ids: set[str] = set()

        def checkpoint(metadata: dict) -> bool:
            if not monitor.fenced():
                return False
            fresh = service.export_hosted_snapshot()
            if fresh.get("config_revision") != state["config_revision"]:
                return False
            cursor_key = _task_key(metadata.get("cursor", ""))
            progress = _scan_task_progress(
                selected, attempted_source_ids, metadata.get("source_id"),
                uncertain_alert_count=state["uncertain_alert_count"],
            )
            latest = monitor.checkpoint(
                snapshot=fresh,
                hosted_cursor={"config_revision": state["config_revision"], "task_key": cursor_key, "updated_at": timestamp()},
                progress=progress,
            )
            # Durable sending/delivered state has been written before this callback returns.
            return monitor.fenced() and latest["config_revision"] == fresh["config_revision"]

        result = service.run_once(
            source_ids=selected,
            max_seconds=max_seconds,
            max_checks=MAX_HOSTED_CHECKS,
            cursor=service_cursor,
            deliver=True,
            checkpoint_callback=checkpoint,
        )
        if not monitor.fenced():
            raise RunnerError("The hosted check lost its shared lease before its final checkpoint.")
        latest_snapshot = service.export_hosted_snapshot()
        task_key = _task_key(result.get("cursor", service_cursor or ""))
        complete = result.get("status") == "complete"
        source_rows = result.get("source_results") or []
        progress = _scan_progress(
            selected, source_rows,
            uncertain_alert_count=result.get("uncertain_alert_count", state["uncertain_alert_count"]),
        )
        failure_count = progress["failed_sources"]
        final = monitor.checkpoint(
            snapshot=latest_snapshot,
            hosted_cursor={"config_revision": state["config_revision"], "task_key": task_key, "updated_at": timestamp()},
            progress=progress,
            error_code="none" if complete and not failure_count else "hosted_partial" if not complete else "hosted_failed",
            complete=complete and not failure_count,
            uncertain_alert_count=progress["uncertain_alert_count"],
        )
        processed = int(result.get("processed", 0))
        delivered = int(result.get("delivered", 0))
        _append_step_summary(
            "Hosted check",
            [
                f"Status: {'complete' if complete and not failure_count else 'partial or needs attention'}; {processed} bounded work items processed.",
                f"Discord deliveries accepted: {delivered}; uncertain alerts needing review: {final['uncertain_alert_count']}.",
                "The scan resumes from a private checkpoint if another slice is needed.",
            ],
        )
        monitor.release()
        remote.publish_status(force=True)
        return {"status": "complete" if complete and not failure_count else "partial", "processed": processed, "delivered": delivered, "cursor": task_key}
    except Exception as exc:
        monitor.release()
        try:
            remote.publish_status(force=True)
        except Exception:
            pass
        if isinstance(exc, RunnerError) and "too little time left" in str(exc):
            raise RunnerError("The provider job has too little time left for a safe hosted check.") from None
        code = _error_code(exc)
        _append_step_summary("Hosted check", [f"The scan stopped safely ({code}).", "The private checkpoint remains available for a later run."])
        raise RunnerError(f"The scan stopped safely ({code}).") from None
    finally:
        if scratch is not None:
            scratch.cleanup()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Premium Watch hosted runner")
    parser.add_argument("mode", choices=("reserve", "preflight", "verify", "run", "scan"))
    parser.add_argument("--preflight-mode", choices=("verify", "run"), default="run")
    args = parser.parse_args(argv)
    try:
        public_runner = _public_runner_mode()
        if public_runner:
            if args.mode not in {"verify", "scan"}:
                raise RunnerError("The public runner accepts only verification or scan modes.")
            validate_public_runner_environment()
        if args.mode == "reserve":
            reserve_budget(args.preflight_mode)
            return 0
        if args.mode == "preflight":
            preflight(args.preflight_mode)
            return 0
        if args.mode == "verify":
            result = verify_sources()
            return 0 if result.get("status") == "complete" else 1
        if args.mode == "scan":
            result = run_hosted_scan()
            return 0 if result.get("status") in {"complete", "paused"} else 1
        result = run_hosted_scan()
        return 0 if result.get("status") in {"complete", "paused"} else 1
    except (HostingError, RunnerError) as exc:
        print(f"Hosted operation stopped safely ({_error_code(exc)}).", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
