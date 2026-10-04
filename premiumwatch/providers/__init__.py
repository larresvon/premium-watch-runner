"""Provider registry and public contracts for Premium Watch."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .base import (
    IncompleteDiscovery, ProviderBlocked, ProviderDeadlineExceeded, ProviderError,
    PublicHttp, iso_currency, safe_text, validate_public_url,
)
from .html_catalog import HtmlCatalogProvider
from .shopify import ShopifyProvider
from .shopify_cart import CartProbeError, ShopifyCartProbe


def _load_optional_forum_components():
    try:
        from .forum import InvisionProvider
        from .forum_session import ForumLogin
    except ModuleNotFoundError as exc:
        if exc.name not in {f"{__package__}.forum", f"{__package__}.forum_session"}:
            raise
        return None, None
    return InvisionProvider, ForumLogin


def _forum_unavailable() -> dict[str, Any]:
    return {
        "ok": False,
        "status": "unavailable",
        "message": "Forum sign-in is unavailable in this build.",
    }


InvisionProvider, ForumLogin = _load_optional_forum_components()


class ProviderRegistry:
    """Routes source records to supported read-only public listing providers."""

    supported_platforms = ("shopify", "youngcart", "kimchidvd", "cafe24", "invision")
    _statuses = {"announced", "preorder", "in_stock", "sold_out", "unknown"}
    _quantity_kinds = {"exact", "threshold", "availability", "unknown"}

    def __init__(self, session_dir: Path) -> None:
        self.session_dir = Path(session_dir)
        self.http = PublicHttp(self.session_dir)
        self._forum_login = (
            ForumLogin(self.session_dir, self.http.session, http_client=self.http)
            if ForumLogin is not None else None
        )
        self._providers = {
            "shopify": ShopifyProvider(self.http),
            "cafe24": HtmlCatalogProvider(self.http, "cafe24"),
            "youngcart": HtmlCatalogProvider(self.http, "youngcart"),
            "kimchidvd": HtmlCatalogProvider(self.http, "kimchidvd"),
        }
        self.supported_platforms = tuple(
            platform for platform in type(self).supported_platforms
            if platform != "invision" or InvisionProvider is not None
        )
        if InvisionProvider is not None:
            self._providers["invision"] = InvisionProvider(self.http)
        self._shopify_cart_probe = ShopifyCartProbe(self.http)

    def begin_forum_login(self) -> dict[str, Any]:
        """Open a visible, isolated sign-in window only after an explicit user action."""
        if self._forum_login is None:
            return _forum_unavailable()
        return self._forum_login.begin()

    def finish_forum_login(self) -> dict[str, Any]:
        """Verify the user's interactive sign-in and protect the resulting forum cookies."""
        if self._forum_login is None:
            return _forum_unavailable()
        return self._forum_login.finish()

    def forum_login_status(self) -> dict[str, Any]:
        if self._forum_login is None:
            return _forum_unavailable()
        return self._forum_login.status()

    def close(self) -> None:
        """Close an explicitly started login browser, if one is still open."""
        if self._forum_login is not None:
            self._forum_login.close()

    def deadline_scope(self, deadline: float | None):
        """Scope the next discovery/check HTTP work to a monotonic deadline."""
        return self.http.deadline_scope(deadline)

    def discover(self, source: dict[str, Any]) -> list[dict[str, Any]]:
        provider = self._provider(source)
        try:
            products = provider.discover(source)
        except Exception as exc:
            self._record_forum_result(source, exc)
            raise
        self._record_forum_result(source, None)
        if not isinstance(products, list):
            raise ProviderError("Provider returned an invalid discovery result.")
        validated: list[dict[str, Any]] = []
        seen: set[str] = set()
        for product in products:
            self._validate_product(source, product)
            if product["product_id"] in seen:
                raise IncompleteDiscovery("Provider returned a duplicate product ID in a complete scan.")
            seen.add(product["product_id"])
            validated.append(product)
        return validated

    def check(self, source: dict[str, Any], product_url: str, variant_id: str = "") -> list[dict[str, Any]]:
        provider = self._provider(source)
        try:
            observations = provider.check(source, product_url, variant_id)
        except Exception as exc:
            self._record_forum_result(source, exc)
            raise
        self._record_forum_result(source, None)
        if not isinstance(observations, list) or not observations:
            raise ProviderError("Provider returned no observations; the check is incomplete.")
        validated: list[dict[str, Any]] = []
        seen: set[str] = set()
        for observation in observations:
            self._validate_observation(source, observation)
            key = observation["variant_id"]
            if key in seen:
                raise ProviderError("Provider returned duplicate variant IDs for one product check.")
            seen.add(key)
            validated.append(observation)
        if variant_id and all(item["variant_id"] != str(variant_id) for item in validated):
            raise ProviderError(f"Requested variant {variant_id} is not available in this public check.")
        return validated

    def probe_cart(
        self, source: dict[str, Any], product_url: str, variant_id: str,
        requested_quantity: int = 10,
    ) -> dict[str, Any]:
        """Return one isolated anonymous cart result for an opted-in Shopify watch."""
        if not isinstance(source, dict) or safe_text(source.get("platform")).lower() != "shopify":
            raise CartProbeError("unsupported_platform", "Cart quantity checks are only supported for Shopify sources.")
        validate_public_url(product_url, str(source.get("url") or ""))
        return self._shopify_cart_probe.probe(
            source, product_url, str(variant_id), requested_quantity=requested_quantity,
        )

    def _record_forum_result(self, source: dict[str, Any], error: Exception | None) -> None:
        if safe_text(source.get("platform")).lower() != "invision":
            return
        state = "accessible"
        if source.get("enabled") is False:
            state = "disabled"
        elif isinstance(error, ProviderBlocked):
            state = "gated"
        elif isinstance(error, IncompleteDiscovery):
            state = "incomplete"
        elif error is not None:
            state = "error"
        self._forum_login.record_section_access(safe_text(source.get("id")), state)

    def _provider(self, source: dict[str, Any]):
        if not isinstance(source, dict):
            raise ProviderError("Source configuration must be an object.")
        platform = safe_text(source.get("platform")).lower()
        if platform not in self._providers:
            raise ProviderError(f"Unsupported provider platform: {platform or '(empty)' }.")
        validate_public_url(str(source.get("url") or ""))
        return self._providers[platform]

    def _validate_product(self, source: dict[str, Any], product: Any) -> None:
        if not isinstance(product, dict):
            raise ProviderError("Provider returned a malformed product record.")
        for key in ("product_id", "title", "url"):
            if not safe_text(product.get(key)):
                raise ProviderError(f"Provider product is missing {key}.")
        validate_public_url(str(product["url"]), str(source["url"]))
        if not isinstance(product.get("variants", []), list):
            raise ProviderError("Provider product variants must be a list.")
        for observation in product.get("variants", []):
            self._validate_observation(source, observation)
        image = product.get("image_url")
        if image:
            parsed = urlparse(str(image))
            if parsed.scheme != "https" or not parsed.hostname:
                raise ProviderError("Provider product image URL must be public HTTPS.")

    def _validate_observation(self, source: dict[str, Any], observation: Any) -> None:
        if not isinstance(observation, dict):
            raise ProviderError("Provider returned a malformed observation.")
        required = (
            "product_id", "variant_id", "product_title", "variant_title", "url", "available",
            "status", "quantity", "quantity_kind", "price", "currency", "compare_at_price",
            "image_url", "detail", "observed_at",
        )
        missing = [key for key in required if key not in observation]
        if missing:
            raise ProviderError(f"Provider observation is missing fields: {', '.join(missing)}.")
        if not safe_text(observation.get("product_id")):
            raise ProviderError("Provider observation is missing a stable product ID.")
        if observation.get("variant_id") is None:
            raise ProviderError("Provider variant ID must be a string, including when blank for product-level stock.")
        if observation.get("available") not in (True, False, None):
            raise ProviderError("Provider availability must be true, false or unknown.")
        if observation.get("status") not in self._statuses:
            raise ProviderError("Provider returned an invalid stock status.")
        if observation.get("quantity_kind") not in self._quantity_kinds:
            raise ProviderError("Provider returned an invalid quantity kind.")
        quantity = observation.get("quantity")
        if quantity is not None and (not isinstance(quantity, int) or isinstance(quantity, bool) or quantity < 0):
            raise ProviderError("Provider quantity must be a non-negative public integer or unknown.")
        if quantity is not None and observation.get("quantity_kind") not in {"exact", "threshold"}:
            raise ProviderError("A reported quantity must declare exact or threshold quality.")
        price = observation.get("price")
        currency = iso_currency(observation.get("currency"))
        if price is not None:
            try:
                if Decimal(str(price)) <= 0:
                    raise ProviderError("Provider price must be a positive decimal or unknown.")
            except InvalidOperation as exc:
                raise ProviderError("Provider price must be a decimal string or unknown.") from exc
            if not currency:
                raise ProviderError("Provider may not report a price without a native ISO currency.")
        elif observation.get("currency") is not None and not currency:
            raise ProviderError("Provider currency must be a native three-letter ISO code.")
        validate_public_url(str(observation["url"]), str(source["url"]))


__all__ = [
    "IncompleteDiscovery",
    "CartProbeError",
    "ProviderBlocked",
    "ProviderDeadlineExceeded",
    "ProviderError",
    "ProviderRegistry",
]
