"""Bounded, anonymous Shopify cart-availability probe for an exact watched variant.

This helper makes one small add request and never enters checkout. Its result
describes what the current anonymous cart could accept, not global inventory.
"""

from __future__ import annotations

import json
import re
import socket
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

import requests

from .base import ProviderError, _REDIRECT_CODES, _check_dns_public, validate_public_url


_MAX_REQUESTED_QUANTITY = 10
_MAX_REDIRECTS = 5
_AVAILABILITY_PARTIAL_RE = re.compile(
    r"^Only\s+(?P<quantity>\d+)\s+items?\s+(?:was|were)\s+added\s+to\s+your\s+cart\s+due\s+to\s+availability\.?$",
    re.IGNORECASE,
)
_PRODUCT_PATH_RE = re.compile(
    r"^(?P<prefix>(?:/[a-z]{2}(?:-[a-z]{2})?)?)/products/(?P<handle>[^/]+?)(?:\.js)?/?$",
    re.IGNORECASE,
)


class CartProbeError(ProviderError):
    """Safe, machine-readable failure from an isolated Shopify cart probe."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ShopifyCartProbe:
    """Use one bounded add request in a fresh, anonymous Shopify session.

    The shared policy HTTP object supplies timeouts, response limits, per-host
    pacing and its DNS cache. Its cookie jar and authorization headers are
    never copied into the probe session.
    """

    def __init__(self, shared_policy_http: Any) -> None:
        self.http = shared_policy_http

    def probe(
        self,
        source: dict[str, Any],
        product_url: str,
        variant_id: str,
        requested_quantity: int = 10,
    ) -> dict[str, Any]:
        retailer_url = str(source.get("url") or "")
        if str(source.get("platform") or "").casefold() != "shopify":
            raise CartProbeError("unsupported_platform", "Cart quantity checks are only supported for Shopify sources.")
        if (
            isinstance(requested_quantity, bool)
            or not isinstance(requested_quantity, int)
            or requested_quantity < 1
            or requested_quantity > _MAX_REQUESTED_QUANTITY
        ):
            raise CartProbeError(
                "invalid_probe_quantity",
                f"The cart quantity request must be between 1 and {_MAX_REQUESTED_QUANTITY}.",
            )
        if not re.fullmatch(r"\d{1,32}", str(variant_id or "")):
            raise CartProbeError("invalid_variant_id", "A numeric Shopify variant ID is required.")

        try:
            validate_public_url(retailer_url)
            validate_public_url(product_url, retailer_url)
        except ProviderError as exc:
            raise CartProbeError("invalid_product_url", "The product URL is not an approved public retailer URL.") from exc

        session = self._new_anonymous_session()
        add_attempted = False
        result: dict[str, Any] | None = None
        primary_error: CartProbeError | None = None
        cleanup_error: CartProbeError | None = None

        try:
            page = self._request(
                session,
                "GET",
                product_url,
                retailer_url,
                follow_get_redirects=True,
            )
            if page.status_code != 200:
                self._close(page)
                raise CartProbeError("product_page_unavailable", "The public product page could not be read.")
            final_product_url = page.url
            page_origin = self._origin(final_product_url)
            self._close(page)

            product_json_url, locale_prefix = self._product_json_url(final_product_url)
            product_response = self._request(
                session,
                "GET",
                product_json_url,
                retailer_url,
                same_origin=page_origin,
                follow_get_redirects=True,
            )
            if product_response.status_code != 200 or self._origin(product_response.url) != page_origin:
                self._close(product_response)
                raise CartProbeError("product_json_unavailable", "The public Shopify product data could not be read.")
            try:
                product_data = self._json_body(product_response)
            finally:
                self._close(product_response)

            raw_variant = self._exact_variant(product_data, str(variant_id))
            if raw_variant.get("available") is False:
                raise CartProbeError("variant_unavailable", "Shopify reports this variant unavailable.")
            if raw_variant.get("available") is not True:
                raise CartProbeError("availability_unknown", "Shopify did not confirm that this variant is available.")
            product_rule = self._optional_rule(raw_variant.get("quantity_rule"), required=False)

            cart_base = f"{self._origin_url(page_origin)}{locale_prefix}/cart"
            add_url = f"{cart_base}/add.js"
            add_attempted = True
            add_response = self._request(
                session,
                "POST",
                add_url,
                retailer_url,
                same_origin=page_origin,
                json_body={
                    "items": [
                        {
                            "id": int(variant_id),
                            "quantity": requested_quantity,
                        }
                    ]
                },
            )
            add_status = add_response.status_code
            try:
                add_data = self._json_body(add_response)
            finally:
                self._close(add_response)
            if add_status not in {200, 422}:
                raise CartProbeError("cart_add_rejected", "Shopify did not accept the cart quantity request.")

            cart_response = self._request(
                session,
                "GET",
                f"{cart_base}.js",
                retailer_url,
                same_origin=page_origin,
            )
            if cart_response.status_code != 200:
                self._close(cart_response)
                raise CartProbeError("cart_state_unavailable", "The temporary cart state could not be confirmed.")
            try:
                cart_data = self._json_body(cart_response)
            finally:
                self._close(cart_response)

            accepted_quantity, cart_rule = self._cart_quantity(cart_data, str(variant_id))
            if accepted_quantity < 1:
                raise CartProbeError("cart_quantity_missing", "The cart did not confirm an accepted quantity.")
            if product_rule is not None and cart_rule is not None and product_rule != cart_rule:
                raise CartProbeError("quantity_rule_mismatch", "Shopify returned inconsistent quantity rules.")
            rule = cart_rule or product_rule
            if rule is None:
                raise CartProbeError("quantity_rule_missing", "Shopify did not expose a clear variant quantity rule.")
            outcome = self._classify(
                add_status=add_status,
                add_data=add_data,
                accepted_quantity=accepted_quantity,
                requested_quantity=requested_quantity,
                rule=rule,
            )
            result = {
                "outcome": outcome,
                "accepted_quantity": accepted_quantity,
                "requested_quantity": requested_quantity,
            }
        except CartProbeError as exc:
            primary_error = exc
        except ProviderError as exc:
            primary_error = CartProbeError("public_request_blocked", "A public retailer request failed its safety checks.")
            primary_error.__cause__ = exc
        except (requests.RequestException, socket.gaierror, TimeoutError) as exc:
            primary_error = CartProbeError("request_failed", "A public retailer request failed.")
            primary_error.__cause__ = exc
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            primary_error = CartProbeError("malformed_response", "Shopify returned incomplete or malformed public data.")
            primary_error.__cause__ = exc
        finally:
            if add_attempted:
                try:
                    self._clear_and_verify(session, retailer_url, page_origin, locale_prefix)
                except CartProbeError as exc:
                    cleanup_error = exc
            session.cookies.clear()
            session.close()

        if cleanup_error is not None:
            raise cleanup_error
        if primary_error is not None:
            raise primary_error
        if result is None:
            raise CartProbeError("no_measurement", "The Shopify cart probe did not produce a confirmed quantity.")
        result["observed_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        return result

    def _new_anonymous_session(self) -> requests.Session:
        session = requests.Session()
        session.trust_env = False
        # Copy only harmless public request headers. Never copy cookies,
        # Authorization, or proxy credentials from the shared client.
        shared_headers = getattr(getattr(self.http, "session", None), "headers", {})
        for key in ("User-Agent", "Accept"):
            if key in shared_headers:
                session.headers[key] = shared_headers[key]
        session.headers.setdefault("User-Agent", "PremiumWatch/0.1 public Shopify cart probe")
        session.headers.setdefault("Accept", "text/html,application/json;q=0.9,*/*;q=0.5")
        session.headers["Cache-Control"] = "no-store"
        return session

    def _request(
        self,
        session: requests.Session,
        method: str,
        url: str,
        retailer_url: str,
        *,
        same_origin: tuple[str, str, int] | None = None,
        follow_get_redirects: bool = False,
        json_body: dict[str, Any] | None = None,
    ) -> requests.Response:
        current = url
        seen: set[str] = set()
        for redirect_count in range(_MAX_REDIRECTS + 1):
            host = self._validate_request_url(current, retailer_url, same_origin)
            if current in seen:
                raise CartProbeError("redirect_loop", "Shopify returned a redirect loop.")
            seen.add(current)
            if host not in self.http._dns_checked:
                try:
                    _check_dns_public(host)
                except ProviderError as exc:
                    raise CartProbeError(
                        "public_dns_rejected",
                        "The retailer host did not resolve to public addresses.",
                    ) from exc
                self.http._dns_checked.add(host)

            self._pace_host(host)
            request_headers = {
                "Accept": "application/json" if method == "POST" or ".js" in urlparse(current).path else "text/html,*/*;q=0.5"
            }
            try:
                response = session.request(
                    method,
                    current,
                    timeout=self.http.timeout,
                    allow_redirects=False,
                    stream=True,
                    json=json_body,
                    headers=request_headers,
                )
            except requests.RequestException as exc:
                raise CartProbeError("request_failed", "A public Shopify request failed.") from exc

            if response.status_code in _REDIRECT_CODES:
                location = response.headers.get("Location")
                self._close(response)
                if not follow_get_redirects or method != "GET" or not location:
                    raise CartProbeError("redirect_blocked", "Shopify redirected a cart request unexpectedly.")
                if redirect_count >= _MAX_REDIRECTS:
                    raise CartProbeError("redirect_limit", "Shopify exceeded the safe redirect limit.")
                current = urljoin(current, location)
                continue
            if response.status_code in {401, 403, 429}:
                self._close(response)
                raise CartProbeError("retailer_blocked", "Shopify blocked or rate-limited the public request.")
            self._read_limited(response)
            response.url = current
            return response
        raise CartProbeError("redirect_limit", "Shopify exceeded the safe redirect limit.")

    def _validate_request_url(
        self,
        url: str,
        retailer_url: str,
        same_origin: tuple[str, str, int] | None,
    ) -> str:
        try:
            host = validate_public_url(url, retailer_url)
        except ProviderError as exc:
            raise CartProbeError("public_url_rejected", "The Shopify request URL failed public host checks.") from exc
        if same_origin is not None and self._origin(url) != same_origin:
            raise CartProbeError("origin_changed", "Shopify changed origin during the isolated cart request.")
        return host

    def _pace_host(self, host: str) -> None:
        now = time.monotonic()
        last = self.http._last_by_host.get(host, 0.0)
        delay = float(self.http.min_host_interval) - (now - last)
        if delay > 0:
            time.sleep(delay)
        self.http._last_by_host[host] = time.monotonic()

    def _read_limited(self, response: requests.Response) -> None:
        limit = int(self.http.max_response_bytes)
        chunks: list[bytes] = []
        size = 0
        try:
            for chunk in response.iter_content(64 * 1024):
                if not chunk:
                    continue
                size += len(chunk)
                if size > limit:
                    self._close(response)
                    raise CartProbeError(
                        "response_too_large",
                        "Shopify returned a response above the configured size limit.",
                    )
                chunks.append(chunk)
        except requests.RequestException as exc:
            self._close(response)
            raise CartProbeError("response_read_failed", "Shopify's public response ended early.") from exc
        response._content = b"".join(chunks)
        response._content_consumed = True

    @staticmethod
    def _json_body(response: requests.Response) -> dict[str, Any]:
        try:
            payload = response.json()
        except (json.JSONDecodeError, ValueError) as exc:
            raise CartProbeError("malformed_json", "Shopify returned malformed JSON.") from exc
        if not isinstance(payload, dict):
            raise CartProbeError("malformed_json", "Shopify returned malformed JSON.")
        return payload

    @staticmethod
    def _exact_variant(product_data: dict[str, Any], variant_id: str) -> dict[str, Any]:
        variants = product_data.get("variants")
        if not isinstance(variants, list):
            raise CartProbeError("malformed_product", "Shopify product data did not include a variants list.")
        matches = [
            item
            for item in variants
            if isinstance(item, dict) and str(item.get("id") or "") == variant_id
        ]
        if len(matches) != 1:
            raise CartProbeError(
                "variant_not_found",
                "The watched variant was missing or ambiguous in Shopify product data.",
            )
        return matches[0]

    @classmethod
    def _optional_rule(cls, raw: Any, *, required: bool) -> dict[str, int | None] | None:
        if raw is None:
            if required:
                raise CartProbeError("quantity_rule_missing", "Shopify did not expose a clear variant quantity rule.")
            return None
        if not isinstance(raw, dict) or "max" not in raw:
            raise CartProbeError("quantity_rule_invalid", "Shopify returned an incomplete variant quantity rule.")

        parsed: dict[str, int | None] = {"max": None}
        for field in ("min", "increment"):
            if field in raw:
                value = raw[field]
                if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                    raise CartProbeError("quantity_rule_invalid", "Shopify returned an invalid variant quantity rule.")
                parsed[field] = value
        if "min" not in parsed or "increment" not in parsed:
            raise CartProbeError("quantity_rule_invalid", "Shopify returned an incomplete variant quantity rule.")

        maximum = raw["max"]
        if maximum is not None and (
            isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 1
        ):
            raise CartProbeError("quantity_rule_invalid", "Shopify returned an invalid variant quantity rule.")
        parsed["max"] = maximum
        if maximum is not None:
            if maximum < parsed["min"] or maximum % parsed["increment"] != 0:
                raise CartProbeError("quantity_rule_invalid", "Shopify returned an inconsistent variant quantity rule.")
        if parsed["min"] % parsed["increment"] != 0:
            raise CartProbeError("quantity_rule_invalid", "Shopify returned an inconsistent variant quantity rule.")
        return parsed

    @classmethod
    def _cart_quantity(
        cls,
        cart_data: dict[str, Any],
        variant_id: str,
    ) -> tuple[int, dict[str, int | None] | None]:
        items = cart_data.get("items")
        item_count = cart_data.get("item_count")
        if not isinstance(items, list) or isinstance(item_count, bool) or not isinstance(item_count, int) or item_count < 0:
            raise CartProbeError("malformed_cart", "Shopify returned an incomplete cart state.")

        all_quantities: list[int] = []
        matching: list[dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                raise CartProbeError("malformed_cart", "Shopify returned an incomplete cart state.")
            item_quantity = item.get("quantity")
            if isinstance(item_quantity, bool) or not isinstance(item_quantity, int) or item_quantity < 0:
                raise CartProbeError("malformed_cart", "Shopify returned an invalid cart quantity.")
            all_quantities.append(item_quantity)
            item_variant_id = str(item.get("variant_id") or item.get("id") or "")
            if item_variant_id == variant_id:
                matching.append(item)
        if sum(all_quantities) != item_count:
            raise CartProbeError("malformed_cart", "Shopify returned inconsistent cart totals.")
        if len(matching) != 1:
            raise CartProbeError(
                "cart_quantity_ambiguous",
                "Shopify did not return exactly one matching cart line.",
            )
        rule = cls._optional_rule(matching[0].get("quantity_rule"), required=False)
        return int(matching[0]["quantity"]), rule

    @classmethod
    def _classify(
        cls,
        *,
        add_status: int,
        add_data: dict[str, Any],
        accepted_quantity: int,
        requested_quantity: int,
        rule: dict[str, int | None],
    ) -> str:
        maximum = rule["max"]
        if add_status == 200:
            if accepted_quantity != requested_quantity:
                raise CartProbeError("cart_result_mismatch", "Shopify's add response and cart state did not agree.")
            if maximum is not None and accepted_quantity > maximum:
                raise CartProbeError("quantity_rule_mismatch", "Shopify accepted more than its published quantity rule.")
            if maximum is not None and accepted_quantity == maximum:
                return "order_limit"
            return "accepted_floor"

        if add_status != 422 or accepted_quantity >= requested_quantity:
            raise CartProbeError("cart_add_response_ambiguous", "Shopify's cart response did not identify a partial add.")
        if maximum is not None and accepted_quantity == maximum:
            return "order_limit"
        reported_quantity = cls._availability_partial_quantity(add_data)
        if reported_quantity is None or reported_quantity != accepted_quantity:
            raise CartProbeError("cart_result_mismatch", "Shopify's partial-add message and cart state did not agree.")
        if maximum is None and 0 < accepted_quantity < requested_quantity:
            return "availability_cap"
        raise CartProbeError(
            "quantity_result_ambiguous",
            "The cart quantity could not be separated from the variant order rule.",
        )

    @staticmethod
    def _availability_partial_quantity(add_data: dict[str, Any]) -> int | None:
        candidates = [add_data.get("message"), add_data.get("description")]
        for candidate in candidates:
            if not isinstance(candidate, str):
                continue
            match = _AVAILABILITY_PARTIAL_RE.fullmatch(candidate.strip())
            if match:
                return int(match.group("quantity"))
        return None

    def _clear_and_verify(
        self,
        session: requests.Session,
        retailer_url: str,
        origin: tuple[str, str, int],
        locale_prefix: str,
    ) -> None:
        cart_base = f"{self._origin_url(origin)}{locale_prefix}/cart"
        try:
            clear = self._request(
                session,
                "POST",
                f"{cart_base}/clear.js",
                retailer_url,
                same_origin=origin,
                json_body={},
            )
            if clear.status_code != 200:
                self._close(clear)
                raise CartProbeError("cleanup_failed", "The temporary Shopify cart could not be cleared.")
            try:
                clear_data = self._json_body(clear)
            finally:
                self._close(clear)
            if clear_data.get("item_count") != 0 or clear_data.get("items") != []:
                raise CartProbeError("cleanup_failed", "The temporary Shopify cart was not empty after clearing.")

            verify = self._request(
                session,
                "GET",
                f"{cart_base}.js",
                retailer_url,
                same_origin=origin,
            )
            if verify.status_code != 200:
                self._close(verify)
                raise CartProbeError("cleanup_failed", "Shopify's empty cart state could not be verified.")
            try:
                verify_data = self._json_body(verify)
            finally:
                self._close(verify)
            if verify_data.get("item_count") != 0 or verify_data.get("items") != []:
                raise CartProbeError("cleanup_failed", "Shopify's temporary cart did not verify as empty.")
        except CartProbeError as exc:
            if exc.code == "cleanup_failed":
                raise
            raise CartProbeError(
                "cleanup_failed",
                "The temporary Shopify cart could not be cleared and verified.",
            ) from exc

    @staticmethod
    def _product_json_url(product_url: str) -> tuple[str, str]:
        parsed = urlparse(product_url)
        path = parsed.path.rstrip("/")
        match = _PRODUCT_PATH_RE.fullmatch(path)
        if not match:
            raise CartProbeError("invalid_product_path", "The Shopify watch URL must identify one public product.")
        handle = match.group("handle")
        if handle.endswith(".js"):
            js_path = f"{match.group('prefix')}/products/{handle}"
        else:
            js_path = f"{match.group('prefix')}/products/{handle}.js"
        ajax_url = urlunparse(parsed._replace(path=js_path, query="", fragment=""))
        return ajax_url, match.group("prefix")

    @staticmethod
    def _origin(url: str) -> tuple[str, str, int]:
        parsed = urlparse(url)
        return parsed.scheme.lower(), (parsed.hostname or "").rstrip(".").lower(), parsed.port or 443

    @staticmethod
    def _origin_url(origin: tuple[str, str, int]) -> str:
        scheme, host, port = origin
        authority = host if port == 443 else f"{host}:{port}"
        return f"{scheme}://{authority}"

    @staticmethod
    def _close(response: Any) -> None:
        try:
            response.close()
        except Exception:
            pass
