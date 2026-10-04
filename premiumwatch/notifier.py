from __future__ import annotations

import json
import re
import ssl
from http.client import HTTPSConnection
from typing import Any
from urllib.parse import urlsplit

from .security import validate_webhook_url


class WebhookDeliveryError(RuntimeError):
    def __init__(
        self, message: str, retry_after: float | None = None, *,
        retryable: bool = True, uncertain: bool = False,
    ):
        super().__init__(message)
        self.retry_after = retry_after
        self.retryable = retryable
        self.uncertain = uncertain


def _retry_after(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return max(1.0, min(float(value), 3600.0))
    except (TypeError, ValueError):
        return None


def build_payload(
    event: dict[str, Any], *, mention_user_id: str = "", mention_role_id: str = ""
) -> dict[str, Any]:
    title = " ".join(str(event.get("title") or "Premium Watch alert").split())[:256]
    summary = " ".join(str(event.get("summary") or "").split())[:4000]
    url = str(event.get("url") or "")
    details = event.get("details") or {}
    fields: list[dict[str, Any]] = []
    for name, label in (
        ("store_name", "Store"), ("variant_title", "Edition"), ("availability", "Availability"),
        ("old_price", "Previous price"), ("new_price", "Current price"),
        ("historical_low", "Tracked low"), ("tracking_started_at", "Tracking began"),
        ("quantity", "Reported quantity"), ("detail", "Details"),
    ):
        value = details.get(name)
        if value not in (None, ""):
            fields.append({"name": label, "value": str(value)[:1024], "inline": name != "detail"})
    for name, label in (
        ("old_accepted_quantity", "Previously accepted in cart probe"),
        ("new_accepted_quantity", "Now accepted in cart probe"),
        ("requested_quantity", "Cart probe request"),
    ):
        value = details.get(name)
        if value not in (None, ""):
            fields.append({"name": label, "value": str(value)[:1024], "inline": True})
    outcome = details.get("outcome")
    if outcome:
        fields.append({"name": "Cart probe result", "value": str(outcome).replace("_", " ")[:1024], "inline": True})
    if details.get("currency") and any(
        field["name"] in {"Previous price", "Current price", "Tracked low"} for field in fields
    ):
        currency = str(details["currency"]).upper()
        for field in fields:
            if field["name"] in {"Previous price", "Current price", "Tracked low"} and not field["value"].upper().endswith(currency):
                field["value"] = f"{field['value']} {currency}"
    if details.get("new_low"):
        fields.append({"name": "Tracking note", "value": "Lowest observed since tracking began", "inline": False})
    if details.get("topic_id"):
        fields.append({"name": "Topic ID", "value": str(details["topic_id"])[:100], "inline": True})
    embed: dict[str, Any] = {"title": title, "description": summary, "fields": fields[:20]}
    if url:
        embed["url"] = url
    if event.get("created_at"):
        embed["timestamp"] = str(event["created_at"])
    mentions: dict[str, list[str]] = {}
    if re.fullmatch(r"[0-9]{17,20}", str(mention_user_id or "")):
        mentions["users"] = [str(mention_user_id)]
    if re.fullmatch(r"[0-9]{17,20}", str(mention_role_id or "")):
        mentions["roles"] = [str(mention_role_id)]
    content_parts = []
    if "users" in mentions:
        content_parts.append(f"<@{mentions['users'][0]}>")
    if "roles" in mentions:
        content_parts.append(f"<@&{mentions['roles'][0]}>")
    return {
        "content": " ".join(content_parts)[:2000] or None,
        "embeds": [embed],
        "allowed_mentions": {"parse": [], **mentions},
    }


def post_webhook(webhook_url: str, payload: dict[str, Any], timeout: float = 12.0) -> None:
    """Send one webhook message without following redirects or logging its URL."""
    url = validate_webhook_url(webhook_url)
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(body) > 900_000:
        raise ValueError("Discord alert is too large.")
    parts = urlsplit(url)
    path = parts.path + "?wait=true"
    connection = HTTPSConnection(parts.hostname, parts.port or 443, timeout=timeout, context=ssl.create_default_context())
    try:
        connection.request(
            "POST", path, body=body,
            headers={"Content-Type": "application/json", "User-Agent": "PremiumWatch/0.1"},
        )
        response = connection.getresponse()
        response.read(64_000)
        if 200 <= response.status < 300:
            return
        if response.status == 429:
            raise WebhookDeliveryError("Discord asked Premium Watch to slow down.", _retry_after(response.getheader("Retry-After")))
        if response.status in {400, 401, 403, 404}:
            raise WebhookDeliveryError(f"Discord rejected the alert (HTTP {response.status}).", retryable=False)
        raise WebhookDeliveryError(
            f"Discord returned HTTP {response.status}.", retryable=False,
            uncertain=response.status >= 500,
        )
    except WebhookDeliveryError:
        raise
    except (OSError, TimeoutError, ssl.SSLError):
        raise WebhookDeliveryError(
            "Could not confirm Discord delivery. The alert will not be retried automatically.",
            retryable=False, uncertain=True,
        ) from None
    finally:
        connection.close()
