from __future__ import annotations

from decimal import Decimal
from typing import Any

from .storage import dedup_key


def has_signal(observation: dict[str, Any]) -> bool:
    return (
        observation.get("available") is not None
        or observation.get("status") != "unknown"
        or observation.get("quantity") is not None
        or observation.get("price") is not None
    )


def listing_event(source: dict[str, Any], product: dict[str, Any], observed_at: str) -> dict[str, Any]:
    forum_topic = str(source.get("platform", "")).lower() in {"invision", "mediapsychos"}
    title = product["title"]
    event_title = f"New group-buy topic: {title}" if forum_topic else f"New listing: {title}"
    kind_text = "group-buy topic" if forum_topic else "listing"
    return {
        "dedup_key": dedup_key(["new_listing", source.get("id"), product["product_id"]]),
        "kind": "new_listing",
        "source_id": source["id"],
        "product_id": product["product_id"],
        "variant_id": "",
        "created_at": observed_at,
        "title": event_title,
        "summary": f"Previously unseen {kind_text} found at {source.get('name') or source['id']}.",
        "url": product["url"],
        "details": {
            "store_name": source.get("name") or source["id"],
            "image_url": product.get("image_url", ""),
            "topic_id": product["product_id"] if forum_topic else "",
        },
    }


def variant_event(source: dict[str, Any], observation: dict[str, Any]) -> dict[str, Any]:
    status = observation.get("status") or "unknown"
    available = observation.get("available")
    if status == "announced":
        orderability = "Announced; orders are not marked open"
    elif available is True or status in {"preorder", "in_stock"}:
        orderability = "Orders appear open"
    elif available is False or status == "sold_out":
        orderability = "Currently marked sold out"
    else:
        orderability = "Unknown; the source did not expose orderability"
    title = observation.get("product_title") or "Product"
    edition = observation.get("variant_title") or "New edition"
    return {
        "dedup_key": dedup_key(["new_variant", source.get("id"), observation["product_id"], observation.get("variant_id", "")]),
        "kind": "new_variant",
        "source_id": source["id"],
        "product_id": observation["product_id"],
        "variant_id": observation.get("variant_id", ""),
        "created_at": observation["observed_at"],
        "title": f"New edition: {title}",
        "summary": f"A new edition ({edition}) was found. {orderability}.",
        "url": observation["url"],
        "details": {
            "store_name": source.get("name") or source["id"],
            "variant_title": edition,
            "availability": orderability,
            "status": status,
            "available": available,
            "quantity": observation.get("quantity"),
            "quantity_kind": observation.get("quantity_kind"),
        },
    }


def observation_events(
    source: dict[str, Any],
    previous: dict[str, Any] | None,
    current: dict[str, Any],
    *,
    previous_low: str | None,
    tracking_started_at: str = "",
    notify_price_increases: bool,
) -> list[tuple[dict[str, Any], bool]]:
    """Return (event, should_notify) pairs for one exact variant transition."""
    if previous is None:
        return []
    previous_context = previous.get("comparison_context")
    current_context = current.get("comparison_context")
    if (previous_context is not None or current_context is not None) and previous_context != current_context:
        return []
    source_id = source["id"]
    product_id = current["product_id"]
    variant_id = current.get("variant_id", "")
    previous_at = previous.get("observed_at", "")
    current_at = current.get("observed_at", "")
    variant_title = current.get("variant_title") or previous.get("variant_title") or ""
    url = current.get("url") or previous.get("url") or ""
    display_title = current.get("product_title") or previous.get("product_title") or "Product"
    result: list[tuple[dict[str, Any], bool]] = []

    old_status = previous.get("status") or "unknown"
    new_status = current.get("status") or "unknown"
    old_available = previous.get("available")
    new_available = current.get("available")

    availability_kind = ""
    if new_status == "preorder" and (old_status in {"announced", "sold_out"} or old_available is False):
        availability_kind = "orders_opened"
    elif new_status == "in_stock" and old_status == "announced":
        availability_kind = "orders_opened"
    elif new_status == "in_stock" and (old_status == "sold_out" or old_available is False):
        availability_kind = "restock"
    elif old_available is False and new_available is True:
        availability_kind = "restock"
    elif new_status == "sold_out" and (old_status != "sold_out" or old_available is not False):
        availability_kind = "availability_change"
    elif old_available is True and new_available is False:
        availability_kind = "availability_change"

    if availability_kind:
        if availability_kind == "orders_opened":
            title = f"Orders opened: {display_title}"
            summary = "Preorders or orders are now marked open."
        elif availability_kind == "restock":
            title = f"Restock: {display_title}"
            summary = "This edition changed from unavailable to available."
        else:
            title = f"Availability changed: {display_title}"
            summary = f"Availability is now {new_status.replace('_', ' ')}."
        details = {
            "store_name": source.get("name") or source["id"],
            "variant_title": variant_title,
            "availability": f"{old_status.replace('_', ' ')} → {new_status.replace('_', ' ')}",
            "old_available": old_available,
            "new_available": new_available,
            "previous_observed_at": previous_at,
        }
        event = _event(
            availability_kind, source_id, product_id, variant_id, current_at,
            title, summary, url, details,
            ["availability", old_status, new_status, old_available, new_available, previous_at, current_at],
        )
        result.append((event, True))

    old_qty = previous.get("quantity")
    new_qty = current.get("quantity")
    quantity_kind = current.get("quantity_kind")
    if (
        old_qty is not None and new_qty is not None and old_qty != new_qty
        and quantity_kind in {"exact", "threshold"}
        and previous.get("quantity_kind") == quantity_kind
    ):
        qualifier = "at least " if quantity_kind == "threshold" else ""
        details = {
            "store_name": source.get("name") or source["id"],
            "variant_title": variant_title,
            "quantity": f"{qualifier}{old_qty} → {qualifier}{new_qty}",
            "old_quantity": old_qty,
            "new_quantity": new_qty,
            "quantity_kind": quantity_kind,
            "detail": "A reported quantity changed; this does not measure sales.",
            "previous_observed_at": previous_at,
        }
        event = _event(
            "quantity_change", source_id, product_id, variant_id, current_at,
            f"Reported quantity changed: {display_title}",
            "The publicly reported quantity changed. It is not a measure of sales.",
            url, details, ["quantity", quantity_kind, old_qty, new_qty, previous_at, current_at],
        )
        result.append((event, True))

    old_cart = previous.get("cart_probe")
    new_cart = current.get("cart_probe")
    cart_context_matches = (
        isinstance(old_cart, dict) and isinstance(new_cart, dict)
        and old_cart.get("market_context") == new_cart.get("market_context")
    )
    if cart_context_matches:
        old_cart_qty = old_cart.get("accepted_quantity")
        new_cart_qty = new_cart.get("accepted_quantity")
        old_cart_outcome = old_cart.get("outcome")
        cart_outcome = new_cart.get("outcome")
        comparable_cart_outcomes = {"availability_cap", "order_limit"}
        comparable_bounds = (
            old_cart_outcome == cart_outcome and cart_outcome in comparable_cart_outcomes
        ) or {old_cart_outcome, cart_outcome} == {"availability_cap", "accepted_floor"}
        if (
            old_cart.get("confirmed_at")
            and new_cart.get("status") == "confirmed"
            and new_cart.get("confirmed_at")
            and comparable_bounds
            and old_cart.get("requested_quantity") == new_cart.get("requested_quantity") == 10
            and isinstance(old_cart_qty, int) and not isinstance(old_cart_qty, bool)
            and isinstance(new_cart_qty, int) and not isinstance(new_cart_qty, bool)
            and old_cart_qty != new_cart_qty
        ):
            def cart_quantity_label(outcome: str, quantity: int) -> str:
                if outcome == "accepted_floor":
                    return f"at least {quantity}"
                if outcome == "order_limit":
                    return f"{quantity} (published per-order limit)"
                return f"{quantity} of 10 requested (availability-limited)"

            old_label = cart_quantity_label(str(old_cart_outcome), old_cart_qty)
            new_label = cart_quantity_label(str(cart_outcome), new_cart_qty)
            details = {
                "store_name": source.get("name") or source["id"],
                "variant_title": variant_title,
                "old_accepted_quantity": old_cart_qty,
                "new_accepted_quantity": new_cart_qty,
                "requested_quantity": 10,
                "old_outcome": old_cart_outcome,
                "new_outcome": cart_outcome,
                "outcome": cart_outcome,
                "previous_observed_at": old_cart.get("confirmed_at"),
                "detail": (
                    f"The previous probe accepted {old_label}; the latest accepted {new_label}. "
                    "This is cart/order-limit evidence, not exact warehouse stock or a measure of sales."
                ),
            }
            event = _event(
                "cart_change", source_id, product_id, variant_id, str(new_cart["confirmed_at"]),
                f"Cart acceptance changed: {display_title}",
                (
                    f"A verified anonymous 10-item cart probe accepted {old_label} before and "
                    f"{new_label} now. This describes cart acceptance, not exact warehouse stock or sales."
                ),
                url, details,
                [
                    "cart_probe", old_cart_outcome, cart_outcome, 10, old_cart_qty, new_cart_qty,
                    old_cart.get("confirmed_at"), new_cart.get("confirmed_at"),
                ],
            )
            result.append((event, True))

    old_price = previous.get("price")
    new_price = current.get("price")
    currency = current.get("currency")
    if old_price is not None and new_price is not None and currency and previous.get("currency") == currency:
        old_amount = Decimal(str(old_price))
        new_amount = Decimal(str(new_price))
        if old_amount != new_amount:
            direction = "decrease" if new_amount < old_amount else "increase"
            historical_low_before = Decimal(str(previous_low)) if previous_low is not None else old_amount
            tracked_low = min(historical_low_before, new_amount)
            is_new_low = new_amount < historical_low_before
            details = {
                "store_name": source.get("name") or source["id"],
                "variant_title": variant_title,
                "old_price": str(old_price),
                "new_price": str(new_price),
                "currency": currency,
                "direction": direction,
                "new_low": is_new_low,
                "historical_low": format(tracked_low.normalize(), "f"),
                "tracking_started_at": tracking_started_at,
                "previous_observed_at": previous_at,
                "tracking_note": "Lowest observed since tracking began" if is_new_low else "",
            }
            suffix = " (new observed low)" if is_new_low else ""
            event = _event(
                "price_change", source_id, product_id, variant_id, current_at,
                f"Price {direction}d{suffix}: {display_title}",
                f"Price changed from {old_price} {currency} to {new_price} {currency}.",
                url, details, ["price", currency, old_price, new_price, previous_at, current_at],
            )
            result.append((event, direction == "decrease" or notify_price_increases))
    return result


def merge_comparison_state(previous: dict[str, Any] | None, current: dict[str, Any]) -> dict[str, Any]:
    """Retain the last known value of each signal when a scan reports it as unknown."""
    if previous is None:
        return dict(current)
    merged = dict(previous)
    for key in (
        "product_id", "product_title", "variant_id", "variant_title", "url", "image_url",
        "market_context", "observer_context", "comparison_context",
    ):
        if current.get(key):
            merged[key] = current[key]
    if current.get("status") and current["status"] != "unknown":
        merged["status"] = current["status"]
        merged["status_observed_at"] = current.get("observed_at", "")
    if current.get("available") is not None:
        merged["available"] = current["available"]
        merged["availability_observed_at"] = current.get("observed_at", "")
    if current.get("quantity") is not None and current.get("quantity_kind") in {"exact", "threshold"}:
        merged["quantity"] = current["quantity"]
        merged["quantity_kind"] = current["quantity_kind"]
        merged["quantity_observed_at"] = current.get("observed_at", "")
    current_cart = current.get("cart_probe")
    if isinstance(current_cart, dict):
        merged_cart = dict(current_cart)
        previous_cart = previous.get("cart_probe")
        if isinstance(previous_cart, dict) and current_cart.get("status") in {"stale", "error"}:
            if previous_cart.get("confirmed_at"):
                for key in ("outcome", "accepted_quantity", "requested_quantity", "confirmed_at"):
                    if previous_cart.get(key) is not None:
                        merged_cart[key] = previous_cart[key]
                merged_cart["status"] = "stale"
            else:
                merged_cart["status"] = "error"
        merged["cart_probe"] = merged_cart
    if current.get("price") is not None and current.get("currency"):
        merged["price"] = current["price"]
        merged["currency"] = current["currency"]
        merged["compare_at_price"] = current.get("compare_at_price")
        merged["price_observed_at"] = current.get("observed_at", "")
    if current.get("detail"):
        merged["detail"] = current["detail"]
    # This timestamp marks the latest usable comparison checkpoint; raw current
    # data, including unknown fields, is stored separately for honest display.
    merged["observed_at"] = current.get("observed_at", merged.get("observed_at", ""))
    return merged


def _event(
    kind: str, source_id: str, product_id: str, variant_id: str, created_at: str,
    title: str, summary: str, url: str, details: dict[str, Any], fingerprint: list[Any],
) -> dict[str, Any]:
    return {
        "dedup_key": dedup_key([kind, source_id, product_id, variant_id, *fingerprint]),
        "kind": kind,
        "source_id": source_id,
        "product_id": product_id,
        "variant_id": variant_id,
        "created_at": created_at,
        "title": title[:256],
        "summary": summary[:1500],
        "url": url,
        "details": details,
    }
