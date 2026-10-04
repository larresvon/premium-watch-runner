from __future__ import annotations

import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

from .security import validate_public_http_url


STATUSES = {"announced", "preorder", "in_stock", "sold_out", "unknown"}
QUANTITY_KINDS = {"exact", "threshold", "availability", "unknown"}
_CART_PROBE_STATUSES = {"waiting", "confirmed", "stale", "error"}
_CART_PROBE_OUTCOMES = {"availability_cap", "accepted_floor", "order_limit"}
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_SAFE_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_]{0,79}$")


class PremiumWatchError(RuntimeError):
    """A safe error suitable for returning to the local dashboard."""


class ProviderError(PremiumWatchError):
    """A provider could not complete a trustworthy check."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def normalize_time(value: Any, *, default_now: bool = True) -> str:
    if value in (None, "") and default_now:
        return utc_now()
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError("Observation time must be ISO date/time text.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Observation time must include a time zone.")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds")


def normalize_price(value: Any) -> str | None:
    if value is None or value == "":
        return None
    try:
        amount = Decimal(str(value).strip())
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("Price must be a decimal number.") from exc
    if not amount.is_finite() or amount < 0:
        raise ValueError("Price must be a finite, non-negative decimal.")
    return format(amount.normalize(), "f")


def normalize_currency(value: Any, price: str | None) -> str | None:
    currency = str(value or "").strip().upper()
    if not currency:
        if price is not None:
            raise ValueError("A native ISO currency is required when a price is present.")
        return None
    if not _CURRENCY.fullmatch(currency):
        raise ValueError("Currency must be a three-letter ISO code.")
    return currency


def _clean_text(value: Any, name: str, *, required: bool = False, limit: int = 500) -> str:
    text = " ".join(str(value or "").split())
    if required and not text:
        raise ValueError(f"{name} is required.")
    if len(text) > limit:
        raise ValueError(f"{name} is too long.")
    return text


def normalize_observation(raw: dict[str, Any], *, source: dict[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("Provider returned an invalid observation.")
    product_id = _clean_text(raw.get("product_id"), "Product ID", required=True, limit=240)
    variant_id = _clean_text(raw.get("variant_id"), "Variant ID", limit=240)
    title = _clean_text(raw.get("product_title"), "Product title", required=True, limit=300)
    variant_title = _clean_text(raw.get("variant_title"), "Variant title", limit=240)
    url = validate_public_http_url(raw.get("url") or "")
    available = raw.get("available")
    if available is not None and not isinstance(available, bool):
        raise ValueError("Availability must be true, false, or unknown.")
    status = str(raw.get("status") or "unknown").strip().lower()
    if status not in STATUSES:
        raise ValueError("Provider returned an unsupported availability status.")
    quantity = raw.get("quantity")
    if quantity is not None:
        if isinstance(quantity, bool) or not isinstance(quantity, int) or quantity < 0:
            raise ValueError("Quantity must be a non-negative integer or unknown.")
    quantity_kind = str(raw.get("quantity_kind") or "unknown").strip().lower()
    if quantity_kind not in QUANTITY_KINDS:
        raise ValueError("Provider returned an unsupported quantity kind.")
    if quantity is None:
        quantity_kind = "unknown" if quantity_kind != "availability" else "availability"
    elif quantity_kind not in {"exact", "threshold"}:
        raise ValueError("A numeric quantity must be exact or a threshold.")
    price = normalize_price(raw.get("price"))
    # Zero-value deposits or unselected options are not a usable item price.
    if price is not None and Decimal(price) == 0:
        price = None
    currency = normalize_currency(raw.get("currency"), price)
    compare_at_price = normalize_price(raw.get("compare_at_price"))
    if compare_at_price is not None and Decimal(compare_at_price) == 0:
        compare_at_price = None
    detail = _clean_text(raw.get("detail"), "Observation detail", limit=800)
    image = str(raw.get("image_url") or "").strip()
    image_url = validate_public_http_url(image) if image else ""
    market_context = _normalize_market_context(
        raw.get("market_context", source.get("market_context") if source else None)
    )
    result = {
        "product_id": product_id,
        "variant_id": variant_id,
        "product_title": title,
        "variant_title": variant_title,
        "url": url,
        "available": available,
        "status": status,
        "quantity": quantity,
        "quantity_kind": quantity_kind,
        "price": price,
        "currency": currency,
        "compare_at_price": compare_at_price,
        "image_url": image_url,
        "detail": detail,
        "observed_at": normalize_time(raw.get("observed_at")),
    }
    if market_context is not None:
        result["market_context"] = market_context
    return result


def _normalize_market_context(value: Any) -> str | dict[str, str] | None:
    """Keep only explicit retailer market context supplied by a provider or config."""
    if value in (None, ""):
        return None
    if isinstance(value, str):
        text = " ".join(value.split())
        if not text or len(text) > 120 or "\x00" in text:
            raise ValueError("Market context must be short plain text.")
        return text
    fields = {"market", "country", "region", "locale", "shipping_country", "storefront"}
    if not isinstance(value, dict) or set(value) - fields or len(value) > len(fields):
        raise ValueError("Market context contains unsupported fields.")
    result = {}
    for key, item in value.items():
        if item in (None, ""):
            continue
        if not isinstance(item, str) or len(item) > 80 or "\x00" in item:
            raise ValueError("Market context values must be short plain text.")
        result[key] = " ".join(item.split())
    return dict(sorted(result.items())) or None


def normalize_cart_probe(raw: Any) -> dict[str, Any]:
    """Validate cart/order-limit evidence independently from public stock quantity."""
    if not isinstance(raw, dict):
        raise ValueError("Cart probe evidence must be an object.")
    status = str(raw.get("status") or "").strip().lower()
    if status not in _CART_PROBE_STATUSES:
        raise ValueError("Cart probe returned an unsupported status.")
    outcome = raw.get("outcome")
    if outcome is not None:
        outcome = str(outcome).strip().lower()
        if outcome not in _CART_PROBE_OUTCOMES:
            raise ValueError("Cart probe returned an unsupported outcome.")
    accepted = raw.get("accepted_quantity")
    if accepted is not None and (
        isinstance(accepted, bool) or not isinstance(accepted, int) or accepted < 1
    ):
        raise ValueError("Cart accepted quantity must be a positive integer or unknown.")
    requested = raw.get("requested_quantity", 10)
    if isinstance(requested, bool) or not isinstance(requested, int) or requested != 10:
        raise ValueError("Cart probe request quantity must be 10.")
    confirmed_at = raw.get("confirmed_at")
    if confirmed_at not in (None, ""):
        confirmed_at = normalize_time(confirmed_at, default_now=False)
    else:
        confirmed_at = None
    last_attempt_at = raw.get("last_attempt_at")
    if last_attempt_at not in (None, ""):
        last_attempt_at = normalize_time(last_attempt_at, default_now=False)
    else:
        last_attempt_at = None
    error = str(raw.get("error") or "").strip().lower()
    if error and not _SAFE_ERROR_CODE.fullmatch(error):
        raise ValueError("Cart probe error must be a safe error code.")
    if status == "confirmed":
        if outcome is None or accepted is None or confirmed_at is None:
            raise ValueError("Confirmed cart evidence requires a quantity, outcome, and timestamp.")
        if accepted > requested:
            raise ValueError("Cart accepted quantity cannot exceed the request.")
        if outcome == "availability_cap" and accepted >= requested:
            raise ValueError("An availability cap must be below the request quantity.")
        if outcome == "accepted_floor" and accepted != requested:
            raise ValueError("A full cart acceptance must match the request quantity.")
        if error:
            raise ValueError("Confirmed cart evidence cannot include an error.")
    elif status == "stale":
        if outcome is None or accepted is None or confirmed_at is None:
            raise ValueError("Stale cart evidence must retain a confirmed quantity and time.")
    elif status in {"waiting", "error"}:
        if accepted is not None or outcome is not None or confirmed_at is not None:
            raise ValueError("Unconfirmed cart evidence cannot include confirmed values.")
    result = {
        "status": status,
        "outcome": outcome,
        "accepted_quantity": accepted,
        "requested_quantity": requested,
        "confirmed_at": confirmed_at,
        "last_attempt_at": last_attempt_at,
        "error": error or None,
    }
    market_context = _normalize_market_context(raw.get("market_context"))
    if market_context is not None:
        result["market_context"] = market_context
    return result


def normalize_product(raw: dict[str, Any], *, source: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not isinstance(raw, dict):
        raise ValueError("Provider returned an invalid discovered product.")
    product_id = _clean_text(raw.get("product_id"), "Product ID", required=True, limit=240)
    title = _clean_text(raw.get("title"), "Product title", required=True, limit=300)
    url = validate_public_http_url(raw.get("url"))
    image = str(raw.get("image_url") or "").strip()
    image_url = validate_public_http_url(image) if image else ""
    variants_raw = raw.get("variants", [])
    if not isinstance(variants_raw, list):
        raise ValueError("Discovered product variants must be a list.")
    variants: list[dict[str, Any]] = []
    seen_variants: set[str] = set()
    for item in variants_raw:
        observation = dict(item) if isinstance(item, dict) else item
        if not isinstance(observation, dict):
            raise ValueError("Provider returned an invalid product variant.")
        observation.setdefault("product_id", product_id)
        observation.setdefault("product_title", title)
        observation.setdefault("url", url)
        observation.setdefault("image_url", image_url)
        normalized = normalize_observation(observation, source=source)
        if normalized["product_id"] != product_id:
            raise ValueError("Variant product ID does not match its discovered product.")
        variant_key = normalized["variant_id"]
        if variant_key in seen_variants:
            raise ValueError("Provider returned duplicate variants for one product.")
        seen_variants.add(variant_key)
        variants.append(normalized)
    product = {"product_id": product_id, "title": title, "url": url, "image_url": image_url}
    return product, variants
