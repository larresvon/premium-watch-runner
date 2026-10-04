"""Shared, bounded HTTP and observation helpers for public store pages."""

from __future__ import annotations

import ipaddress
import json
import math
import re
import socket
import time
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from html import unescape
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup


class ProviderError(RuntimeError):
    """A source could not be checked reliably."""


class ProviderBlocked(ProviderError):
    """A source requires access or rejected a public read request."""


class ProviderDeadlineExceeded(ProviderError):
    """A cooperative hosted scan deadline elapsed before more public work."""


class IncompleteDiscovery(ProviderError):
    """A catalog scan stopped before its requested listing was complete."""


_REDIRECT_CODES = {301, 302, 303, 307, 308}
_DEFAULT_TIMEOUT = 12
_MAX_RESPONSE_BYTES = 5 * 1024 * 1024
_PRICE_RE = re.compile(
    r"(?<![\w])(?:(USD|US|EUR|GBP|KRW|JPY|CAD|AUD|HKD|TWD|CNY|PHP)\s*)?"
    r"([$€£₩¥])\s*([0-9][0-9,]*(?:\.[0-9]{1,3})?)",
    re.IGNORECASE,
)
_SUFFIX_CURRENCY_RE = re.compile(r"\s*(USD|EUR|GBP|KRW|JPY|CAD|AUD|HKD|TWD|CNY|PHP)\b", re.I)
_CODED_PRICE_RE = re.compile(r"(?<![\w])([0-9][0-9,]*(?:\.[0-9]{1,3})?)\s+(USD|EUR|GBP|KRW|JPY|CAD|AUD|HKD|TWD|CNY|PHP)\b", re.I)
_QTY_PATTERNS = (
    re.compile(r"\bonly\s+(\d+)\s+(?:left|remaining|in\s+stock)\b", re.I),
    re.compile(r"\b(\d+)\s+(?:left|remaining)\s+in\s+stock\b", re.I),
    re.compile(r"\b(?:stock|quantity|qty)\s*[:：]\s*(\d+)\b", re.I),
    re.compile(r"재고(?:수량)?\s*[:：]?\s*(\d+)\s*개", re.I),
)
_SOLD_OUT_RE = re.compile(r"\b(?:sold\s*out|out\s*of\s*stock|unavailable)\b|품절", re.I)
_IN_STOCK_RE = re.compile(r"\b(?:in\s*stock|available)\b|재고\s*있음", re.I)
_PREORDER_RE = re.compile(r"\bpre[ -]?order\b|예약\s*(?:판매|상품|주문)|예판", re.I)
_ANNOUNCED_RE = re.compile(r"\bcoming\s*soon\b|\bwill\s+be\s+released\s+on\b|출시\s*예정", re.I)
_PLACEHOLDER_RE = re.compile(
    r"^\s*(?:select|choose|please\s+select|please\s+select\s+an?\s+option|select\s+an?\s+option|select\s+option|choose\s+an?\s+option|choose\s+option|옵션\s*선택|선택하세요|선택)(?:\s*\.{0,3})?\s*$",
    re.I,
)
_DEPOSIT_RE = re.compile(r"\bdeposit\b|예약금|계약금", re.I)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    return unescape(str(value)).strip()


def clean_html(value: Any) -> str:
    return BeautifulSoup(safe_text(value), "html.parser").get_text(" ", strip=True)


def normalized_host(host: str) -> str:
    return host.rstrip(".").encode("idna").decode("ascii").lower()


def domain_root(host: str) -> str:
    """Return a conservative retailer root for the public domains used here."""
    labels = normalized_host(host).split(".")
    if len(labels) >= 3 and labels[-1] in {"uk", "au", "nz", "kr", "vn", "jp", "sg", "hk"} and labels[-2] in {
        "co", "com", "org", "net", "ac", "gov"
    }:
        return ".".join(labels[-3:])
    if len(labels) < 2:
        return ".".join(labels)
    return ".".join(labels[-2:])


def validate_public_url(url: str, retailer_url: str | None = None) -> str:
    parsed = urlparse(str(url or ""))
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ProviderError("Only public HTTPS retailer URLs are supported.")
    if parsed.port not in (None, 443):
        raise ProviderError("Non-standard retailer ports are not allowed.")
    host = normalized_host(parsed.hostname)
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".test")):
        raise ProviderError("Local and reserved hosts are not allowed.")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        if not address.is_global:
            raise ProviderError("Private or reserved IP addresses are not allowed.")
    elif "." not in host:
        raise ProviderError("A public fully qualified retailer host is required.")

    if retailer_url:
        retailer = urlparse(retailer_url)
        if not retailer.hostname:
            raise ProviderError("The configured source URL has no public host.")
        if domain_root(host) != domain_root(retailer.hostname):
            raise ProviderError("The product URL must stay on the configured retailer domain.")
    return host


def _check_dns_public(host: str) -> None:
    """Reject a host that resolves to any private, loopback, link-local or reserved address."""
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ProviderError(f"Could not resolve public retailer host {host}.") from exc
    addresses = {item[4][0].split("%", 1)[0] for item in infos}
    if not addresses:
        raise ProviderError(f"Could not resolve public retailer host {host}.")
    for raw in addresses:
        try:
            if not ipaddress.ip_address(raw).is_global:
                raise ProviderError(f"Retailer host {host} resolved to a non-public address.")
        except ValueError as exc:
            raise ProviderError(f"Retailer host {host} returned an invalid address.") from exc


class PublicHttp:
    """Paced HTTPS GET transport with redirect, DNS, timeout and body limits."""

    def __init__(
        self,
        session_dir: Path,
        *,
        timeout: int = _DEFAULT_TIMEOUT,
        min_host_interval: float = 0.8,
        max_response_bytes: int = _MAX_RESPONSE_BYTES,
    ) -> None:
        self.session_dir = Path(session_dir)
        self.timeout = timeout
        self.min_host_interval = min_host_interval
        self.max_response_bytes = max_response_bytes
        self._last_by_host: dict[str, float] = {}
        self._dns_checked: set[str] = set()
        self._deadline: ContextVar[float | None] = ContextVar(
            f"premiumwatch_public_http_deadline_{id(self)}", default=None,
        )
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "PremiumWatch/0.1 (+public listing monitor; contact: local user)",
                "Accept": "text/html,application/json,application/xhtml+xml;q=0.9,*/*;q=0.5",
            }
        )

    @contextmanager
    def deadline_scope(self, deadline: float | None):
        """Apply a monotonic absolute deadline to public HTTP only.

        Nested scopes keep the earlier deadline. Resetting the context token in
        ``finally`` restores any previous scope, including after exceptions.
        Cart probing deliberately does not enter this scope so cleanup requests
        can finish safely after the ordinary scan budget is consumed.
        """
        if deadline is not None:
            if isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline):
                raise ValueError("Provider deadline must be a finite monotonic timestamp.")
            previous = self._deadline.get()
            deadline = min(float(deadline), previous) if previous is not None else float(deadline)
        token = self._deadline.set(deadline if deadline is not None else self._deadline.get())
        try:
            yield self
        finally:
            self._deadline.reset(token)

    def _remaining(self) -> float | None:
        deadline = self._deadline.get()
        return None if deadline is None else deadline - time.monotonic()

    def _check_deadline(self) -> float | None:
        remaining = self._remaining()
        if remaining is not None and remaining <= 0:
            raise ProviderDeadlineExceeded("The public provider scan reached its time limit.")
        return remaining

    def get(self, url: str, retailer_url: str) -> requests.Response:
        current = url
        seen: set[str] = set()
        for _ in range(6):
            self._check_deadline()
            host = validate_public_url(current, retailer_url)
            if current in seen:
                raise ProviderError("Retailer returned a redirect loop.")
            seen.add(current)
            if host not in self._dns_checked:
                _check_dns_public(host)
                self._dns_checked.add(host)
                self._check_deadline()
            delay = self.min_host_interval - (time.monotonic() - self._last_by_host.get(host, 0.0))
            if delay > 0:
                remaining = self._check_deadline()
                if remaining is not None and delay >= remaining:
                    raise ProviderDeadlineExceeded("The public provider scan reached its time limit while pacing requests.")
                time.sleep(delay)
                self._check_deadline()
            self._last_by_host[host] = time.monotonic()
            remaining = self._check_deadline()
            request_timeout = self.timeout if remaining is None else min(float(self.timeout), remaining)
            if request_timeout <= 0:
                raise ProviderDeadlineExceeded("The public provider scan reached its time limit before a request.")
            try:
                response = self.session.get(
                    current,
                    timeout=request_timeout,
                    allow_redirects=False,
                    stream=True,
                )
            except requests.RequestException as exc:
                safe_location = urlunparse((*urlparse(current)[:4], "", ""))
                raise ProviderError(f"GET {safe_location} failed: {type(exc).__name__}.") from exc

            try:
                self._check_deadline()
            except ProviderDeadlineExceeded:
                response.close()
                raise

            if response.status_code in _REDIRECT_CODES:
                location = response.headers.get("Location")
                response.close()
                if not location:
                    raise ProviderError("Retailer returned a redirect without a destination.")
                current = urljoin(current, location)
                # Validate redirect targets against the configured retailer before following.
                validate_public_url(current, retailer_url)
                self._check_deadline()
                continue
            if response.status_code in {401, 403, 429}:
                response.close()
                raise ProviderBlocked(
                    f"Retailer returned HTTP {response.status_code}; this source is gated or rate-limited."
                )
            if response.status_code >= 400:
                status = response.status_code
                response.close()
                raise ProviderError(f"Retailer returned HTTP {status}.")
            chunks: list[bytes] = []
            size = 0
            try:
                iterator = iter(response.iter_content(64 * 1024))
                while True:
                    self._check_deadline()
                    try:
                        chunk = next(iterator)
                    except StopIteration:
                        break
                    self._check_deadline()
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > self.max_response_bytes:
                        response.close()
                        raise ProviderError("Retailer response exceeded the configured size limit.")
                    chunks.append(chunk)
            except ProviderDeadlineExceeded:
                response.close()
                raise
            except requests.RequestException as exc:
                response.close()
                raise ProviderError(f"Retailer response ended early: {type(exc).__name__}.") from exc
            response._content = b"".join(chunks)
            response._content_consumed = True
            response.url = current
            return response
        raise ProviderError("Retailer exceeded the redirect limit.")


def response_soup(response: requests.Response) -> BeautifulSoup:
    return BeautifulSoup(response.text, "html.parser")


def iso_currency(value: Any) -> str | None:
    candidate = safe_text(value).upper()
    if re.fullmatch(r"[A-Z]{3}", candidate):
        return candidate
    return None


_ZERO_MINOR = {"BIF", "CLP", "DJF", "GNF", "ISK", "JPY", "KMF", "KRW", "PYG", "RWF", "UGX", "VND", "VUV", "XAF", "XOF", "XPF"}
_THREE_MINOR = {"BHD", "IQD", "JOD", "KWD", "LYD", "OMR", "TND"}


def decimal_string(value: Any, currency: str | None, *, integer_minor_units: bool = False) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        amount = Decimal(str(value).replace(",", "").strip())
    except (InvalidOperation, ValueError):
        return None
    if not amount.is_finite() or amount <= 0:
        return None
    code = iso_currency(currency)
    exponent = 0 if code in _ZERO_MINOR else (3 if code in _THREE_MINOR else 2)
    if integer_minor_units and amount == amount.to_integral_value():
        amount /= Decimal(10) ** exponent
    quant = Decimal(1) if exponent == 0 else Decimal(1).scaleb(-exponent)
    try:
        amount = amount.quantize(quant)
    except InvalidOperation:
        return None
    return format(amount, f".{exponent}f")


def currency_from_html(soup: BeautifulSoup, html: str = "", hint: Any = None) -> str | None:
    if hint and iso_currency(hint):
        # A source hint is a fallback only; explicit page currency always wins.
        fallback = iso_currency(hint)
    else:
        fallback = None
    for meta in soup.select("meta[property='product:price:currency'], meta[itemprop='priceCurrency'], meta[name='currency']"):
        value = meta.get("content") or meta.get("value")
        if iso_currency(value):
            return iso_currency(value)
    for script in soup.select("script[type='application/ld+json']"):
        try:
            data = json.loads(script.string or script.get_text())
        except (json.JSONDecodeError, TypeError):
            continue
        for node in _walk_json(data):
            code = iso_currency(node.get("priceCurrency"))
            if code:
                return code
    probes = [html]
    probes.extend(script.get_text(" ", strip=True) for script in soup.select("script:not([src])"))
    patterns = (
        r"(?:currency(?:_code|Code|\.active)?|shopCurrency)\s*['\"]?\s*[:=]\s*['\"]([A-Z]{3})['\"]",
        r"\"currency\"\s*:\s*\"([A-Z]{3})\"",
    )
    for probe in probes:
        for pattern in patterns:
            match = re.search(pattern, probe, re.I)
            if match and iso_currency(match.group(1)):
                return iso_currency(match.group(1))
    return fallback


def _walk_json(data: Any) -> Iterable[dict[str, Any]]:
    if isinstance(data, dict):
        yield data
        for value in data.values():
            yield from _walk_json(value)
    elif isinstance(data, list):
        for value in data:
            yield from _walk_json(value)


def price_from_text(text: str, currency_hint: str | None = None) -> tuple[str | None, str | None]:
    source = safe_text(text)
    match = _PRICE_RE.search(source)
    if not match:
        coded = _CODED_PRICE_RE.search(source)
        if coded:
            code = iso_currency(coded.group(2))
            return decimal_string(coded.group(1), code), code
        return None, iso_currency(currency_hint)
    explicit_code, symbol, raw = match.groups()
    symbol_currency = {
        "$": None,
        "€": "EUR",
        "£": "GBP",
        "₩": "KRW",
        "¥": None,
    }.get(symbol)
    suffix = _SUFFIX_CURRENCY_RE.match(source[match.end():])
    code = explicit_code or (suffix.group(1) if suffix else None)
    normalized_code = "USD" if code and code.upper() == "US" else code
    currency = iso_currency(normalized_code) or symbol_currency or iso_currency(currency_hint)
    if symbol == "$" and not (explicit_code or suffix or currency_hint):
        currency = None
    if symbol == "¥" and not (explicit_code or suffix or currency_hint):
        currency = None
    amount = decimal_string(raw, currency)
    return amount, currency


def stock_from_text(text: str) -> tuple[bool | None, str, int | None, str, str | None]:
    clean = re.sub(r"\s+", " ", safe_text(text))
    if _SOLD_OUT_RE.search(clean):
        return False, "sold_out", None, "availability", "Retailer labels this item sold out."
    for pattern in _QTY_PATTERNS:
        match = pattern.search(clean)
        if match:
            quantity = int(match.group(1))
            if quantity == 0:
                return False, "sold_out", 0, "exact", "Public listing shows an exact quantity of zero."
            return True, "in_stock", quantity, "exact", f"Public listing says {quantity} left."
    if _PREORDER_RE.search(clean):
        return True, "preorder", None, "availability", "Retailer labels this item as a preorder."
    if _ANNOUNCED_RE.search(clean):
        return None, "announced", None, "unknown", "Retailer labels this item as coming soon."
    if _IN_STOCK_RE.search(clean):
        return True, "in_stock", None, "availability", "Retailer labels this item in stock."
    return None, "unknown", None, "unknown", None


def is_placeholder(value: Any) -> bool:
    text = safe_text(value).strip()
    if not text:
        return True
    return bool(_PLACEHOLDER_RE.match(text)) or text.casefold() in {"select", "choose", "-- select --", "- select -"}


def should_suppress_price(product_title: str, variant_title: str, body: str, price: str | None) -> tuple[str | None, str | None]:
    combined = " ".join((product_title, variant_title, body))
    if price is None:
        return None, None
    if _DEPOSIT_RE.search(combined):
        return None, "Deposit amount is excluded from price tracking."
    try:
        if Decimal(price) <= 0:
            return None, "Zero or placeholder price is excluded from price tracking."
    except InvalidOperation:
        return None, None
    return price, None


def base_observation(
    *,
    product_id: str,
    variant_id: str,
    product_title: str,
    variant_title: str,
    url: str,
    available: bool | None,
    status: str,
    quantity: int | None = None,
    quantity_kind: str = "unknown",
    price: str | None = None,
    currency: str | None = None,
    compare_at_price: str | None = None,
    image_url: str | None = None,
    detail: str | None = None,
) -> dict[str, Any]:
    return {
        "product_id": str(product_id),
        "variant_id": str(variant_id),
        "product_title": safe_text(product_title),
        "variant_title": safe_text(variant_title),
        "url": url,
        "available": available,
        "status": status,
        "quantity": quantity,
        "quantity_kind": quantity_kind,
        "price": price,
        "currency": iso_currency(currency),
        "compare_at_price": compare_at_price,
        "image_url": image_url,
        "detail": detail,
        "observed_at": utc_now(),
    }


def absolute_url(page_url: str, target: str | None) -> str | None:
    if not target:
        return None
    url = urljoin(page_url, safe_text(target).replace("&amp;", "&"))
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return url


def set_query(url: str, **updates: Any) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    for key, value in updates.items():
        query[key] = [str(value)]
    encoded = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=encoded))


def query_int(url: str, names: tuple[str, ...], default: int = 1) -> int:
    query = parse_qs(urlparse(url).query)
    for name in names:
        values = query.get(name)
        if values:
            try:
                return max(1, int(values[0]))
            except (TypeError, ValueError):
                pass
    return default


def parse_jsonld_products(soup: BeautifulSoup) -> list[dict[str, Any]]:
    products: list[dict[str, Any]] = []
    for script in soup.select("script[type='application/ld+json']"):
        try:
            raw = json.loads(script.string or script.get_text())
        except (json.JSONDecodeError, TypeError):
            continue
        for node in _walk_json(raw):
            types = node.get("@type", [])
            if isinstance(types, str):
                types = [types]
            if "Product" in types or "ProductGroup" in types:
                products.append(node)
    return products


def jsonld_offer(product: dict[str, Any]) -> dict[str, Any] | None:
    offers = product.get("offers")
    if isinstance(offers, list):
        offers = next((item for item in offers if isinstance(item, dict)), None)
    return offers if isinstance(offers, dict) else None


def normalized_product_title(value: Any) -> str:
    text = clean_html(value)
    text = re.sub(r"^(?:sold out\s*)", "", text, flags=re.I)
    text = re.sub(r"^(?:product\s+name|product)\s*:\s*", "", text, flags=re.I)
    return re.sub(r"\s+", " ", text).strip()
