"""Read-only Shopify public catalog and Ajax product provider."""

from __future__ import annotations

import json
import re
from decimal import Decimal, InvalidOperation
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .base import (
    IncompleteDiscovery,
    ProviderBlocked,
    ProviderError,
    PublicHttp,
    base_observation,
    clean_html,
    currency_from_html,
    decimal_string,
    is_placeholder,
    iso_currency,
    jsonld_offer,
    parse_jsonld_products,
    response_soup,
    safe_text,
    should_suppress_price,
    utc_now,
    validate_public_url,
)


_PAGE_SIZE = 250
_MAX_PAGES = 20
_PREORDER = re.compile(r"\bpre[ -]?order\b|preorder|예약\s*(?:판매|상품)|예판", re.I)
_COMING_SOON = re.compile(
    r"\bcoming\s*soon\b|\binvitation[\s-]+only\b|\binvite[\s-]+only\b|출시\s*예정",
    re.I,
)


class ShopifyProvider:
    def __init__(self, http: PublicHttp) -> None:
        self.http = http

    def _listing_url(self, source_url: str, page: int) -> str:
        parsed = urlparse(source_url)
        path = parsed.path.rstrip("/") or "/"
        if path.endswith(".json"):
            api_path = path
        elif "/collections/" in path:
            api_path = f"{path}/products.json"
        else:
            api_path = f"{path}/products.json" if path != "/" else "/products.json"
        existing = parse_qs(parsed.query, keep_blank_values=True)
        existing.pop("page", None)
        existing.pop("limit", None)
        existing["limit"] = [str(_PAGE_SIZE)]
        existing["page"] = [str(page)]
        return urlunparse(parsed._replace(path=api_path, query=urlencode(existing, doseq=True), fragment=""))

    def _api_json(self, url: str, source_url: str) -> dict[str, Any]:
        response = self.http.get(url, source_url)
        content_type = response.headers.get("Content-Type", "").lower()
        try:
            payload = response.json()
        except (json.JSONDecodeError, ValueError) as exc:
            if re.search(r"attention required|checking your browser|verify you are human|captcha|access denied", response.text[:12000], re.I):
                raise ProviderBlocked("Shopify public catalog endpoint returned a site challenge or access gate.") from exc
            raise ProviderError("Shopify public catalog endpoint did not return JSON.") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("products"), list):
            raise ProviderError("Shopify public catalog response did not include a products list.")
        if content_type and "json" not in content_type and not response.text.lstrip().startswith("{"):
            raise ProviderError("Shopify public catalog endpoint returned an unexpected content type.")
        return payload

    def discover(self, source: dict[str, Any]) -> list[dict[str, Any]]:
        source_url = str(source.get("url") or "")
        validate_public_url(source_url)
        currency = iso_currency(source.get("currency_hint"))
        # The page may expose its native currency even though Shopify's public product JSON does not.
        try:
            page_response = self.http.get(source_url, source_url)
            page_soup = response_soup(page_response)
            currency = currency_from_html(page_soup, page_response.text, currency) or currency
        except ProviderError:
            # Catalog completeness is decided by the product JSON scan. Missing currency only suppresses prices.
            pass

        by_id: dict[str, dict[str, Any]] = {}
        previous_fingerprint: tuple[str, ...] | None = None
        for page in range(1, _MAX_PAGES + 1):
            endpoint = self._listing_url(source_url, page)
            try:
                products = self._api_json(endpoint, source_url)["products"]
            except ProviderError as exc:
                if page > 1:
                    raise IncompleteDiscovery(f"Shopify scan stopped on page {page}: {exc}") from exc
                raise
            if not products:
                break
            valid_items: list[dict[str, Any]] = []
            for raw in products:
                if not isinstance(raw, dict) or not raw.get("id") or not raw.get("handle") or not raw.get("title"):
                    raise IncompleteDiscovery(f"Shopify page {page} contained an incomplete product record.")
                valid_items.append(raw)
            fingerprint = tuple(str(item.get("id")) for item in valid_items)
            if fingerprint == previous_fingerprint:
                raise IncompleteDiscovery(f"Shopify repeated page {page}; pagination may be ignored by the store.")
            previous_fingerprint = fingerprint
            for raw in valid_items:
                product = self._product_from_catalog(raw, source_url, currency)
                by_id[product["product_id"]] = product
            if len(valid_items) < _PAGE_SIZE:
                break
            if page == _MAX_PAGES:
                raise IncompleteDiscovery(
                    f"Shopify catalog exceeds the {_MAX_PAGES}-page discovery cap; baseline was not accepted."
                )

        products = list(by_id.values())
        return self._filter(products, source)

    def _product_from_catalog(self, raw: dict[str, Any], source_url: str, currency: str | None) -> dict[str, Any]:
        host = urlparse(source_url).hostname or "shopify-store"
        product_id = f"shopify:{host.lower()}:{raw['id']}"
        title = clean_html(raw.get("title"))
        handle = safe_text(raw.get("handle"))
        url_path = safe_text(raw.get("url")) or f"/products/{handle}"
        if not url_path.startswith("/"):
            url_path = f"/products/{handle}"
        source_path = urlparse(source_url).path
        locale_match = re.match(r"^/([a-z]{2}(?:-[A-Z]{2})?)/", source_path)
        locale = f"/{locale_match.group(1)}" if locale_match else ""
        if url_path.startswith("/products/") and locale and not url_path.startswith(f"{locale}/"):
            url_path = f"{locale}{url_path}"
        product_url = urlunparse(urlparse(source_url)._replace(path=url_path, query="", fragment=""))
        image = raw.get("featured_image") or raw.get("image")
        if isinstance(image, dict):
            image = image.get("src") or image.get("url")
        if not image and raw.get("images"):
            first = raw["images"][0]
            image = first.get("src") if isinstance(first, dict) else first
        if isinstance(image, str) and image.startswith("//"):
            image = f"https:{image}"
        tags = raw.get("tags", [])
        tag_text = ",".join(tags) if isinstance(tags, list) else safe_text(tags)
        product_text = " ".join((title, tag_text, clean_html(raw.get("body_html"))))
        variants = [
            self._variant_observation(raw, variant, product_id, title, product_url, currency, product_text, image)
            for variant in raw.get("variants", [])
            if isinstance(variant, dict)
        ]
        variants = [item for item in variants if item is not None]
        return {
            "product_id": product_id,
            "title": title,
            "url": product_url,
            "image_url": image,
            "variants": variants,
        }

    def _variant_observation(
        self,
        product: dict[str, Any],
        raw: dict[str, Any],
        product_id: str,
        title: str,
        product_url: str,
        currency: str | None,
        product_text: str,
        image: str | None,
    ) -> dict[str, Any] | None:
        variant_id = str(raw.get("id") or "")
        if not variant_id:
            return None
        variant_title = safe_text(raw.get("title")) or "Default Title"
        if is_placeholder(variant_title):
            return None
        effective_currency = iso_currency(raw.get("currency") or product.get("currency")) or currency
        raw_price = raw.get("price")
        # The public catalog feed uses decimal strings; Ajax product JSON uses integer minor units.
        price = decimal_string(raw_price, effective_currency, integer_minor_units=isinstance(raw_price, int))
        raw_compare = raw.get("compare_at_price")
        compare = decimal_string(raw_compare, effective_currency, integer_minor_units=isinstance(raw_compare, int))
        price, suppressed = should_suppress_price(title, variant_title, product_text, price)
        if not effective_currency:
            price = None
            compare = None
        status_text = " ".join((product_text, variant_title))
        available_value = raw.get("available")
        available = available_value if isinstance(available_value, bool) else None
        if available is False:
            status = "sold_out"
            detail = "Shopify public product data reports this variant unavailable."
        elif _COMING_SOON.search(status_text):
            status = "announced"
            available = None
            detail = "Retailer labels this product coming soon."
        elif _PREORDER.search(status_text):
            status = "preorder"
            detail = (
                "Retailer labels this product as a preorder and public product data reports it available."
                if available is True
                else "Retailer labels this product as a preorder, but public product data does not confirm that orders are being accepted."
            )
        elif available is True:
            status = "in_stock"
            detail = "Shopify public product data reports this variant available."
        else:
            status = "unknown"
            detail = "Shopify public product data did not expose this variant's availability."
        quantity = raw.get("inventory_quantity")
        if not isinstance(quantity, int) or isinstance(quantity, bool) or quantity < 0:
            quantity = None
        quantity_kind = "exact" if quantity is not None else ("availability" if available is not None else "unknown")
        if suppressed:
            detail = f"{detail} {suppressed}".strip()
        return base_observation(
            product_id=product_id,
            variant_id=variant_id,
            product_title=title,
            variant_title=variant_title,
            url=product_url,
            available=available,
            status=status,
            quantity=quantity,
            quantity_kind=quantity_kind,
            price=price,
            currency=effective_currency,
            compare_at_price=compare,
            image_url=image,
            detail=detail,
        )

    def check(self, source: dict[str, Any], product_url: str, variant_id: str = "") -> list[dict[str, Any]]:
        source_url = str(source.get("url") or "")
        validate_public_url(product_url, source_url)
        parsed = urlparse(product_url)
        path = parsed.path
        if not re.search(r"/products/[^/]+(?:\.js|\.json)?/?$", path):
            raise ProviderError("Shopify watch URL must be a public product page.")
        if path.endswith(".json"):
            path = path[:-5] + ".js"
        elif not path.endswith(".js"):
            path = path.rstrip("/") + ".js"
        endpoint = urlunparse(parsed._replace(path=path, query="", fragment=""))
        # Load the public product page first so any market cookie it sets is
        # shared by the following Ajax JSON request in this same session.
        try:
            html_response = self.http.get(product_url, source_url)
            html_soup = response_soup(html_response)
            page_currency = currency_from_html(html_soup, html_response.text, None)
            page_price, page_price_currency = self._html_price_evidence(html_soup, page_currency)
        except ProviderError:
            html_soup = None
            page_currency = None
            page_price = None
            page_price_currency = None
        response = self.http.get(endpoint, source_url)
        try:
            product = response.json()
        except (json.JSONDecodeError, ValueError) as exc:
            if re.search(r"attention required|checking your browser|verify you are human|captcha|access denied", response.text[:12000], re.I):
                raise ProviderBlocked("Shopify public product endpoint returned a site challenge or access gate.") from exc
            raise ProviderError("Shopify public product endpoint did not return JSON.") from exc
        if not isinstance(product, dict) or not isinstance(product.get("variants"), list):
            raise ProviderError("Shopify public product response did not include variants.")
        html_currency = currency_from_html(html_soup, html_response.text, None) if html_soup is not None else None
        api_currency = iso_currency(product.get("currency") or product.get("priceCurrency"))
        currency = html_currency or iso_currency(source.get("currency_hint")) or api_currency
        explicit_currency_conflict = bool(html_currency and api_currency and html_currency != api_currency)
        product_id = f"shopify:{urlparse(product_url).hostname}:{product.get('id') or product.get('handle') or path}"
        title = clean_html(product.get("title")) or clean_html(product.get("product_title"))
        image = product.get("featured_image")
        if isinstance(image, str) and image.startswith("//"):
            image = f"https:{image}"
        product_text = " ".join((title, clean_html(product.get("description")), safe_text(product.get("tags"))))
        observations: list[dict[str, Any]] = []
        for raw in product["variants"]:
            if not isinstance(raw, dict):
                continue
            observation = self._variant_observation(product, raw, product_id, title, product_url, currency, product_text, image)
            if observation is not None:
                observations.append(observation)
        if not observations:
            raise ProviderError("Shopify product exposed no selectable variants.")
        if explicit_currency_conflict:
            self._withhold_prices(observations, "Shopify page and product JSON report different currencies; prices are withheld.")
        elif len(product["variants"]) == 1 and page_price is not None:
            observation = observations[0]
            if observation["price"] is not None:
                try:
                    prices_match = Decimal(observation["price"]) == Decimal(page_price)
                except (InvalidOperation, TypeError):
                    prices_match = False
                if not prices_match or (page_price_currency and observation["currency"] != page_price_currency):
                    self._withhold_prices(
                        observations,
                        "The public product page price does not match its single Shopify Ajax variant; amount withheld.",
                    )
        if variant_id:
            matches = [item for item in observations if item["variant_id"] == str(variant_id)]
            if not matches:
                raise ProviderError(f"Shopify variant {variant_id} is not present on the public product page.")
            return matches
        return observations

    @staticmethod
    def _html_price_evidence(soup, currency: str | None) -> tuple[str | None, str | None]:
        for selector in (
            "meta[property='product:price:amount']",
            "meta[itemprop='price']",
            "meta[property='og:price:amount']",
        ):
            node = soup.select_one(selector)
            raw = safe_text(node.get("content") or node.get("value")) if node else ""
            if raw and currency:
                amount = decimal_string(raw, currency)
                if amount:
                    return amount, currency
        return None, None

    @staticmethod
    def _withhold_prices(observations: list[dict[str, Any]], message: str) -> None:
        for observation in observations:
            observation["price"] = None
            observation["compare_at_price"] = None
            observation["detail"] = f"{observation['detail']} {message}".strip()

    @staticmethod
    def _filter(products: list[dict[str, Any]], source: dict[str, Any]) -> list[dict[str, Any]]:
        includes = [safe_text(value).casefold() for value in source.get("include_keywords", []) if safe_text(value)]
        excludes = [safe_text(value).casefold() for value in source.get("exclude_keywords", []) if safe_text(value)]
        output: list[dict[str, Any]] = []
        for product in products:
            title = safe_text(product.get("title")).casefold()
            if includes and not any(term in title for term in includes):
                continue
            if any(term in title for term in excludes):
                continue
            output.append(product)
        return output
