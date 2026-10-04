"""HTML-backed providers for Cafe24, YoungCart and KimchiDVD listings."""

from __future__ import annotations

import json
import re
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urlparse, urlunparse

from bs4 import BeautifulSoup, Tag

from .base import (
    IncompleteDiscovery,
    ProviderBlocked,
    ProviderError,
    PublicHttp,
    absolute_url,
    base_observation,
    clean_html,
    currency_from_html,
    decimal_string,
    is_placeholder,
    iso_currency,
    jsonld_offer,
    normalized_product_title,
    parse_jsonld_products,
    price_from_text,
    query_int,
    response_soup,
    safe_text,
    set_query,
    should_suppress_price,
    stock_from_text,
    validate_public_url,
)


_MAX_PAGES = 50
_KIMCHI_MAX_PAGES = 150
_KIMCHI_RESULT_RANGE = re.compile(
    r"\bShowing\s+([\d,]+)\s*(?:~|–|-)\s*([\d,]+)\s+of\s+([\d,]+)\s+results?\b",
    re.I,
)
_GENERIC_PRODUCT_LABELS = {
    "add to cart",
    "add to wishlist",
    "buy it now",
    "buy now",
    "details",
    "out of stock",
    "order now",
    "sold out",
    "view detail",
    "view larger image",
    "view product",
    "wishlist",
    "zoom",
}
_PAGE_NAMES = {
    "cafe24": ("page",),
    "youngcart": ("page",),
    "kimchidvd": ("pageNo", "page", "pageno"),
}
_NO_PRODUCTS = re.compile(r"no products|no items|검색\s*결과가\s*없|등록된\s*상품이\s*없|상품이\s*없", re.I)
_OPTION_DELTA = re.compile(r"\(\s*[+-]\s*[^)]*\d", re.I)


class HtmlCatalogProvider:
    def __init__(self, http: PublicHttp, platform: str) -> None:
        self.http = http
        self.platform = platform

    def discover(self, source: dict[str, Any]) -> list[dict[str, Any]]:
        source_url = str(source.get("url") or "")
        validate_public_url(source_url)
        page_names = _PAGE_NAMES[self.platform]
        current = query_int(source_url, page_names, 1)
        first_url = source_url
        seen_ids: set[str] = set()
        products: list[dict[str, Any]] = []
        fingerprints: set[tuple[str, ...]] = set()
        page = current
        expected_total: int | None = None
        expected_page_size: int | None = None
        expected_page_count: int | None = None
        max_pages = _KIMCHI_MAX_PAGES if self.platform == "kimchidvd" else _MAX_PAGES

        for scanned in range(1, max_pages + 1):
            page_url = first_url if scanned == 1 else set_query(first_url, **{page_names[0]: page})
            response = self.http.get(page_url, source_url)
            soup = response_soup(response)
            self._raise_if_gated(soup)
            cards = self._products_on_page(soup, response.url)
            ids = tuple(card["product_id"] for card in cards)
            if self.platform == "kimchidvd":
                range_info = self._kimchidvd_result_range(soup)
                if range_info is None:
                    page_text = soup.get_text(" ", strip=True)
                    if scanned == 1 and page == 1 and not cards and _NO_PRODUCTS.search(page_text):
                        return []
                    if expected_total is None:
                        raise IncompleteDiscovery(
                            "KimchiDVD page 1 did not report its result range; refusing to accept a homepage or partial listing as complete."
                        )
                    raise IncompleteDiscovery("KimchiDVD stopped reporting its result range during pagination.")
                start, end, total = range_info
                if total == 0:
                    if scanned == 1 and page == 1 and not cards:
                        return []
                    raise IncompleteDiscovery("KimchiDVD reported zero results but exposed product cards.")
                if expected_total is None:
                    if scanned != 1 or page != 1 or start != 1:
                        raise IncompleteDiscovery("KimchiDVD catalog discovery must begin on page 1.")
                    expected_total = total
                    expected_page_size = end - start + 1
                    if expected_page_size < 1 or total < end:
                        raise IncompleteDiscovery("KimchiDVD reported an invalid result range.")
                    expected_page_count = (total + expected_page_size - 1) // expected_page_size
                    if expected_page_count > max_pages:
                        raise IncompleteDiscovery(
                            f"KimchiDVD catalog needs {expected_page_count} pages, exceeding the {max_pages}-page safety cap."
                        )
                if total != expected_total:
                    raise IncompleteDiscovery("KimchiDVD catalog total changed during pagination.")
                expected_start = (page - 1) * expected_page_size + 1
                expected_end = min(page * expected_page_size, expected_total)
                if start != expected_start or end != expected_end:
                    raise IncompleteDiscovery(f"KimchiDVD page {page} returned an inconsistent result range.")
                if not re.search(r"</html\s*>\s*$", getattr(response, "text", ""), re.I):
                    raise IncompleteDiscovery(
                        f"KimchiDVD page {page} response ended before the HTML document closed; refusing a partial catalog."
                    )
                cards = self._kimchidvd_catalog_products(soup, response.url, cards, page)
                ids = tuple(card["product_id"] for card in cards)
                overlap = seen_ids.intersection(ids)
                if overlap:
                    raise IncompleteDiscovery(f"KimchiDVD page {page} overlaps earlier result pages.")
            if ids in fingerprints and ids:
                raise IncompleteDiscovery(f"{self.platform} repeated page {page}; pagination may be ignored.")
            fingerprints.add(ids)
            if not cards and scanned == 1:
                page_text = soup.get_text(" ", strip=True)
                if _NO_PRODUCTS.search(page_text):
                    return []
                raise IncompleteDiscovery(
                    f"{self.platform} listing contained no recognizable product cards; markup may have changed or access may be gated."
                )
            for product in cards:
                if product["product_id"] not in seen_ids:
                    seen_ids.add(product["product_id"])
                    products.append(product)

            linked_pages = self._linked_pages(soup, response.url, page_names)
            if expected_page_count is not None:
                has_next = page < expected_page_count
                if has_next:
                    page += 1
            else:
                next_pages = [candidate for candidate in linked_pages if candidate > page]
                has_next = bool(next_pages) or self._has_next_link(soup)
                if next_pages:
                    page = min(next_pages)
                elif has_next:
                    page += 1
            if not has_next:
                break
            if scanned == max_pages:
                raise IncompleteDiscovery(
                    f"{self.platform} listing exceeds the {max_pages}-page discovery cap; baseline was not accepted."
                )
            if page < 1 or page > 10000:
                raise IncompleteDiscovery(f"{self.platform} returned an invalid page number.")

        return self._filter(products, source)

    def _kimchidvd_catalog_products(
        self,
        soup: BeautifulSoup,
        page_url: str,
        parsed_products: list[dict[str, Any]],
        page: int,
    ) -> list[dict[str, Any]]:
        """Validate and parse every physical product row in the Kimchi catalog list.

        The caller has already validated the reported range and complete HTML
        document. Enumerate the physical public rows, requiring every row to
        resolve to one titled product and to match the page-wide parser output.
        """
        product_lists = soup.select(".goodsList > .proList > ul")
        if len(product_lists) != 1:
            raise IncompleteDiscovery(
                f"KimchiDVD page {page} did not expose exactly one public product-row list."
            )
        rows = product_lists[0].find_all("li", recursive=False)
        if not rows:
            raise IncompleteDiscovery(f"KimchiDVD page {page} reported products but exposed no public product rows.")

        products: list[dict[str, Any]] = []
        for row_number, row in enumerate(rows, start=1):
            row_products = self._products_on_page(row, page_url)
            if len(row_products) != 1:
                raise IncompleteDiscovery(
                    f"KimchiDVD page {page} public row {row_number} did not resolve to exactly one titled product."
                )
            products.append(row_products[0])

        row_ids = [product["product_id"] for product in products]
        parsed_ids = [product["product_id"] for product in parsed_products]
        if len(set(row_ids)) != len(row_ids):
            raise IncompleteDiscovery(f"KimchiDVD page {page} contains duplicate IDs across public product rows.")
        if set(row_ids) != set(parsed_ids) or len(row_ids) != len(parsed_ids):
            raise IncompleteDiscovery(
                f"KimchiDVD page {page} has product links outside or missing from its public product rows."
            )
        return products

    @staticmethod
    def _kimchidvd_result_range(soup: BeautifulSoup) -> tuple[int, int, int] | None:
        text = soup.get_text(" ", strip=True)
        match = _KIMCHI_RESULT_RANGE.search(text)
        if not match:
            return None
        start, end, total = (int(value.replace(",", "")) for value in match.groups())
        if total == 0 and end == 0 and start in {0, 1}:
            return 0, 0, 0
        if start < 1 or end < start or total < end:
            raise IncompleteDiscovery("KimchiDVD reported an invalid result range.")
        return start, end, total

    def _linked_pages(self, soup: BeautifulSoup, page_url: str, page_names: tuple[str, ...]) -> set[int]:
        pages: set[int] = set()
        for anchor in soup.select("a[href]"):
            target = absolute_url(page_url, anchor.get("href"))
            if not target:
                continue
            try:
                validate_public_url(target, page_url)
            except ProviderError:
                continue
            query = parse_qs(urlparse(target).query)
            for name in page_names:
                for value in query.get(name, []):
                    try:
                        pages.add(int(value))
                    except (TypeError, ValueError):
                        pass
        return pages

    @staticmethod
    def _has_next_link(soup: BeautifulSoup) -> bool:
        for anchor in soup.select("a[rel~='next'], a.next, a.pagination-next, a[aria-label*='Next' i]"):
            if anchor.get("href"):
                return True
        for anchor in soup.select("a[href]"):
            label = " ".join((safe_text(anchor.get_text(" ", strip=True)), safe_text(anchor.get("title")), safe_text(anchor.get("aria-label"))))
            if re.search(r"\bnext\b|다음\s*페이지|다음", label, re.I) and anchor.get("href"):
                return True
        return False

    def _products_on_page(self, soup: BeautifulSoup, page_url: str) -> list[dict[str, Any]]:
        found: dict[str, dict[str, Any]] = {}
        for anchor in soup.select("a[href]"):
            target = absolute_url(page_url, anchor.get("href"))
            if not target or not self._is_product_url(target):
                continue
            try:
                validate_public_url(target, page_url)
            except ProviderError:
                continue
            product_id = self._product_id(target)
            if not product_id or product_id in found:
                continue
            card = self._card_for(anchor)
            title = self._listing_title(anchor.get_text(" ", strip=True))
            image_url = None
            if card:
                if not title:
                    for selector in (
                        ".proTitle", ".goodsTitle", ".item_tt", ".name", ".product_name",
                        ".prd_name", ".goods_name", ".title", "[itemprop='name']",
                    ):
                        title_node = card.select_one(selector)
                        if title_node:
                            title = self._listing_title(title_node.get_text(" ", strip=True))
                            if title:
                                break
                if not title:
                    title = self._listing_title(anchor.get("title"))
                if not title:
                    title = self._listing_title(anchor.get("aria-label"))
                if not title:
                    for image in card.select("img[alt]"):
                        title = self._listing_title(image.get("alt"))
                        if title:
                            break
                image = card.select_one("img[src], img[data-src], img[data-original]")
                if image:
                    image_url = absolute_url(page_url, image.get("data-src") or image.get("data-original") or image.get("src"))
            elif not title:
                title = self._listing_title(anchor.get("title") or anchor.get("aria-label"))
            if not title:
                continue
            found[product_id] = {
                "product_id": product_id,
                "title": title,
                "url": target,
                "image_url": image_url,
                "variants": [],
            }
        return list(found.values())

    @staticmethod
    def _listing_title(value: Any) -> str:
        title = normalized_product_title(value)
        title = re.sub(r"\s*view larger image\s*$", "", title, flags=re.I).strip()
        if title.casefold() in _GENERIC_PRODUCT_LABELS:
            return ""
        return title

    def _is_product_url(self, url: str) -> bool:
        parsed = urlparse(url)
        path = parsed.path.lower()
        query = parse_qs(parsed.query)
        if self.platform == "cafe24":
            return (
                "product_no" in query
                or re.search(r"/product/(?:detail|[^/]+)/(?:\d+)/?$", path) is not None
                or re.search(r"/product/(?:detail|[^/]+)/", path) is not None
            ) and "list.html" not in path
        if self.platform == "youngcart":
            return "it_id" in query or re.search(r"(?:item|product)\.php$", path) is not None
        if self.platform == "kimchidvd":
            return bool(re.search(r"/\d+/(?:v|view)\.kimchi$", path) or ("goods" in query and "search" not in path))
        return False

    def _product_id(self, url: str) -> str:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        key = {"cafe24": "product_no", "youngcart": "it_id", "kimchidvd": "goods"}[self.platform]
        identifier = (query.get(key) or [None])[0]
        if not identifier and self.platform == "cafe24":
            match = re.search(r"/product/[^/]+/(\d+)(?:/|$)", parsed.path, re.I)
            identifier = match.group(1) if match else None
        if not identifier and self.platform == "kimchidvd":
            match = re.search(r"/(\d+)/(?:v|view)\.kimchi$", parsed.path, re.I)
            identifier = match.group(1) if match else None
        if not identifier:
            return ""
        host = (parsed.hostname or "").lower()
        return f"{self.platform}:{host}:{identifier}"

    @staticmethod
    def _card_for(anchor: Tag) -> Tag | None:
        for parent in anchor.parents:
            if not isinstance(parent, Tag):
                continue
            classes = " ".join(parent.get("class", [])).casefold()
            if parent.name in {"li", "article"}:
                return parent
            if re.search(r"product|prd|goods|item|box", classes) and not re.search(
                r"thumbnail|thumb|image|img|item_img|item_info",
                classes,
            ):
                return parent
            if parent.name in {"body", "html"}:
                break
        parent = anchor.parent
        return parent if isinstance(parent, Tag) else None

    def check(self, source: dict[str, Any], product_url: str, variant_id: str = "") -> list[dict[str, Any]]:
        source_url = str(source.get("url") or "")
        validate_public_url(product_url, source_url)
        if not self._is_product_url(product_url):
            raise ProviderError(f"{self.platform} watch URL is not a recognized product detail page.")
        response = self.http.get(product_url, source_url)
        soup = response_soup(response)
        self._raise_if_gated(soup)
        product_id = self._product_id(response.url) or self._product_id(product_url)
        if not product_id:
            raise ProviderError(f"{self.platform} product page did not expose a stable product identifier.")
        title = self._product_title(soup)
        if not title:
            raise ProviderError(f"{self.platform} product page did not expose a title.")
        product_url = response.url.split("#", 1)[0]
        currency = currency_from_html(soup, response.text, source.get("currency_hint"))
        primary_area = self._primary_product_area(soup)
        body_text = self._visible_text(primary_area) if primary_area is not None else soup.get_text(" ", strip=True)
        status_text = self._stock_text(soup, body_text)
        available, status, quantity, quantity_kind, stock_detail = stock_from_text(status_text)
        option_selects = self._selectable_option_selects(soup)
        single_option_stock = self._single_option_stock(soup) if self.platform == "cafe24" and not option_selects else None
        if single_option_stock is not None:
            public_quantity, is_reserve = single_option_stock
            if public_quantity == 0:
                available, status = False, "sold_out"
                quantity, quantity_kind = 0, "exact"
                stock_detail = "Public product data reports an exact stock count of zero."
            elif status != "sold_out":
                available = True
                status = "preorder" if is_reserve else ("in_stock" if status == "unknown" else status)
                quantity, quantity_kind = public_quantity, "exact"
                stock_detail = f"Public product data exposes an exact stock count of {public_quantity}."
        base_price, compare_at, offer_currency = self._structured_price(soup, currency)
        currency = offer_currency or currency
        if base_price is None:
            base_price, text_currency = self._visible_price(soup, currency)
            currency = text_currency or currency
        if not currency:
            base_price = None
            compare_at = None
        product_body = " ".join((title, body_text))
        base_price, price_detail = should_suppress_price(title, "", product_body, base_price)

        variants = self._variants(soup, product_id, title, product_url, available, status, quantity, quantity_kind, stock_detail, base_price, compare_at, currency, body_text)
        if not variants:
            detail = stock_detail
            if price_detail:
                detail = f"{detail or ''} {price_detail}".strip()
            variants = [
                base_observation(
                    product_id=product_id,
                    variant_id="",
                    product_title=title,
                    variant_title="Standard",
                    url=product_url,
                    available=available,
                    status=status,
                    quantity=quantity,
                    quantity_kind=quantity_kind,
                    price=base_price,
                    currency=currency,
                    compare_at_price=compare_at,
                    detail=detail,
                )
            ]
        if variant_id:
            matches = [item for item in variants if item["variant_id"] == str(variant_id)]
            if not matches:
                raise ProviderError(f"{self.platform} variant {variant_id} is not present on the public product page.")
            return matches
        return variants

    def _raise_if_gated(self, soup: BeautifulSoup) -> None:
        title = soup.title.get_text(" ", strip=True) if soup.title else ""
        body = soup.get_text(" ", strip=True)[:12000]
        combined = " ".join((title, body))
        if re.search(
            r"attention required.{0,80}cloudflare|you are unable to access|checking your browser|"
            r"verify you are human|enable cookies.{0,120}blocked|security service.{0,120}blocked|captcha",
            combined,
            re.I,
        ):
            raise ProviderBlocked(f"{self.platform} returned a site challenge or access gate for this page.")

    def _product_title(self, soup: BeautifulSoup) -> str:
        for selector, attr in (("meta[property='og:title']", "content"), ("meta[name='twitter:title']", "content")):
            node = soup.select_one(selector)
            if node and node.get(attr):
                return normalized_product_title(node.get(attr))
        for selector in (
            "h1", ".goodsTitle", ".proSubject_b", ".name", ".product_name", ".prd_name",
            ".goods_name", "#it_name", ".item_name",
        ):
            node = soup.select_one(selector)
            if node:
                title = normalized_product_title(node.get_text(" ", strip=True))
                if title:
                    return title
        products = parse_jsonld_products(soup)
        for product in products:
            if product.get("name"):
                return normalized_product_title(product["name"])
        if soup.title:
            title = clean_html(soup.title.get_text(" ", strip=True))
            title = re.split(r"\s*>\s*|\s+\|\s+", title, maxsplit=1)[0]
            return normalized_product_title(title)
        return ""

    def _primary_product_area(self, soup: BeautifulSoup) -> Tag | None:
        selectors = {
            "cafe24": (".xans-product-detail", "[itemtype*='Product']"),
            "youngcart": ("#it_ov", ".sit_info", ".sct_info", "main", "[itemtype*='Product']"),
            "kimchidvd": (".goodsDetail", "[itemtype*='Product']"),
        }[self.platform]
        for selector in selectors:
            area = soup.select_one(selector)
            if area:
                return area
        return soup.body or soup

    @staticmethod
    def _is_hidden(node: Tag) -> bool:
        current: Tag | None = node
        while current is not None:
            if current.attrs is None:
                return True
            classes = {safe_text(value).casefold() for value in current.get("class", [])}
            style = safe_text(current.get("style")).replace(" ", "").casefold()
            if (
                current.has_attr("hidden")
                or safe_text(current.get("aria-hidden")).casefold() == "true"
                or classes.intersection({"displaynone", "hidden", "hide"})
                or "display:none" in style
                or "visibility:hidden" in style
            ):
                return True
            current = current.parent if isinstance(current.parent, Tag) else None
        return False

    @staticmethod
    def _is_related_item(node: Tag) -> bool:
        related_classes = {
            "related", "recommend", "recommendation", "xans-product-relationlist",
            "xans-product-relation", "relation",
        }
        current: Tag | None = node
        while current is not None:
            classes = {safe_text(value).casefold() for value in current.get("class", [])}
            if classes.intersection(related_classes):
                return True
            current = current.parent if isinstance(current.parent, Tag) else None
        return False

    @classmethod
    def _visible_text(cls, node: Tag) -> str:
        clone = deepcopy(node)
        for candidate in list(clone.select("select, option, .related, .recommend, .recommendation, .review, .xans-product-relationlist, .xans-product-relation")):
            if candidate.parent is not None:
                candidate.decompose()
        for candidate in list(clone.find_all(True)):
            if candidate.parent is not None and candidate.attrs is not None and cls._is_hidden(candidate):
                candidate.decompose()
        return clone.get_text(" ", strip=True)

    def _stock_text(self, soup: BeautifulSoup, fallback: str) -> str:
        area = self._primary_product_area(soup)
        if area is None:
            return fallback
        for node in area.select("[itemprop='availability'], [data-stock-status]"):
            if self._is_hidden(node) or self._is_related_item(node):
                continue
            value = " ".join((safe_text(node.get("content")), safe_text(node.get("href")), safe_text(node.get("data-stock-status")), self._visible_text(node)))
            if re.search(r"outofstock|soldout|품절|재고\s*없음", value, re.I):
                return "out of stock"
            if re.search(r"preorder|presale|예약\s*(?:판매|상품|주문)|예판", value, re.I):
                return "preorder"
            if re.search(r"instock|in\s*stock|available|재고\s*있음", value, re.I):
                return "in stock"

        signal_nodes = area.select(".soldout, .sold_out, .product_status, .availability, #it_soldout, [data-stock-status]")
        for node in signal_nodes:
            if self._is_hidden(node) or self._is_related_item(node):
                continue
            value = " ".join((safe_text(node.get("data-stock-status")), self._visible_text(node)))
            if value and re.search(r"sold\s*out|out\s*of\s*stock|품절|재고\s*없음|pre[ -]?order|예약\s*(?:판매|상품|주문)|coming\s*soon|in\s*stock|available|재고\s*있음", value, re.I):
                return value

        purchase_available = False
        action_text = ""
        for node in area.select("button, input[type='submit'], input[type='button'], .btnSubmit, #addToCart a, #addToCart"):
            if self._is_hidden(node) or self._is_related_item(node) or node.has_attr("disabled") or safe_text(node.get("aria-disabled")).casefold() == "true":
                continue
            value = " ".join((safe_text(node.get("value")), self._visible_text(node)))
            if re.search(r"sold\s*out|out\s*of\s*stock|품절|재고\s*없음", value, re.I):
                return value
            if re.search(r"pre[ -]?order|예약\s*(?:판매|상품|주문)|예판", value, re.I):
                return value
            if re.search(r"add\s*to\s*cart|buy\s*(?:now|it\s*now)|장바구니|구매", value, re.I):
                purchase_available = True
                action_text = value

        text = self._visible_text(area) or fallback
        if self.platform == "kimchidvd" and purchase_available:
            release_area = soup.select_one("#qReleaseDate") or area.select_one(".proReady") or area
            release_text = self._visible_text(release_area) if release_area else ""
            release_date = re.search(r"\b(20\d{2}-\d{2}-\d{2})\b", release_text)
            if release_date:
                try:
                    if datetime.strptime(release_date.group(1), "%Y-%m-%d").date() > datetime.now(timezone.utc).date():
                        return "preorder"
                except ValueError:
                    pass
        if purchase_available and not re.search(r"sold\s*out|out\s*of\s*stock|품절|pre[ -]?order|coming\s*soon", text, re.I):
            text = f"{text} in stock"
        return f"{text} {action_text}".strip()

    def _structured_price(self, soup: BeautifulSoup, currency_hint: str | None) -> tuple[str | None, str | None, str | None]:
        for product in parse_jsonld_products(soup):
            offer = jsonld_offer(product)
            if not offer:
                continue
            currency = iso_currency(offer.get("priceCurrency")) or currency_hint
            price = decimal_string(offer.get("price"), currency)
            compare = decimal_string(offer.get("highPrice"), currency)
            if price or compare:
                return price, compare, currency
        return None, None, None

    @staticmethod
    def _visible_price(soup: BeautifulSoup, currency_hint: str | None) -> tuple[str | None, str | None]:
        for row in soup.select("tr"):
            cells = row.find_all(("th", "td"), recursive=False)
            if len(cells) < 2 or not re.search(r"\b(?:price|our\s+price|list\s+price)\b", cells[0].get_text(" ", strip=True), re.I):
                continue
            price, currency = price_from_text(cells[1].get_text(" ", strip=True), currency_hint)
            if price:
                return price, currency
        for node in soup.select("p.ft14"):
            raw = node.get_text(" ", strip=True)
            if re.match(r"Our\s+Price\s*:", raw, re.I):
                price, currency = price_from_text(raw, currency_hint)
                if price:
                    return price, currency
        selectors = (
            "[itemprop='price']", "#span_product_price_text", "#it_price", ".xans-product-price",
            ".product_price", ".priceValue", ".price", ".sale_price", ".ft14",
        )
        visited: set[int] = set()
        for selector in selectors:
            for node in soup.select(selector):
                if id(node) in visited:
                    continue
                visited.add(id(node))
                raw = safe_text(node.get("content") or node.get("value")) or node.get_text(" ", strip=True)
                price, currency = price_from_text(raw, currency_hint)
                if not price:
                    numeric = re.search(r"(?<!\w)(\d[\d,]*(?:\.\d{1,3})?)(?!\w)", raw)
                    if numeric:
                        price = decimal_string(numeric.group(1), currency_hint)
                        currency = iso_currency(currency_hint)
                if price:
                    return price, currency
        return None, iso_currency(currency_hint)

    def _variants(
        self,
        soup: BeautifulSoup,
        product_id: str,
        title: str,
        product_url: str,
        base_available: bool | None,
        base_status: str,
        base_quantity: int | None,
        base_quantity_kind: str,
        base_detail: str | None,
        base_price: str | None,
        compare_at: str | None,
        currency: str | None,
        body_text: str,
    ) -> list[dict[str, Any]]:
        json_variants = self._jsonld_variants(soup, product_id, title, product_url, currency, body_text)
        if json_variants:
            return json_variants

        selectors = self._selectable_option_selects(soup)
        # Cafe24, YoungCart and legacy pages often expose one option selector. Multiple groups do not prove combinations.
        if len(selectors) > 1:
            return [
                base_observation(
                    product_id=product_id,
                    variant_id="",
                    product_title=title,
                    variant_title="Multiple options",
                    url=product_url,
                    available=None,
                    status="unknown",
                    quantity=None,
                    quantity_kind="unknown",
                    price=None,
                    currency=currency,
                    detail="The public page has multiple option selectors but does not expose a complete combination inventory.",
                )
            ]
        if not selectors:
            return []

        select = selectors[0]
        result: list[dict[str, Any]] = []
        for option in select.select("option"):
            option_title = safe_text(option.get_text(" ", strip=True))
            option_key = safe_text(option.get("value"))
            if is_placeholder(option_title) or not option_key or option_key in {"*", "**"}:
                continue
            option_available, option_status, option_quantity, option_quantity_kind, option_detail = stock_from_text(option_title)
            disabled = option.has_attr("disabled")
            if disabled or option_available is False:
                available, status = False, "sold_out"
                detail = "Retailer disables this option or labels it sold out."
            elif base_status == "sold_out":
                available, status = False, "sold_out"
                detail = base_detail or "Retailer labels this product sold out."
            elif option_status in {"preorder", "in_stock"} and option_available is True:
                available, status, detail = option_available, option_status, option_detail
            elif base_status in {"preorder", "in_stock"} and base_available is True:
                available, status = base_available, base_status
                detail = base_detail or "The public product page reports this product as available."
            elif option_status == "announced" or base_status == "announced":
                available, status = None, "announced"
                detail = option_detail if option_status == "announced" else (base_detail or "Retailer labels this product as coming soon.")
            else:
                available, status = None, "unknown"
                detail = "A selectable option alone does not confirm that the retailer is accepting orders."
            option_price = base_price
            if _OPTION_DELTA.search(option_title):
                option_price = None
                detail = f"{detail} Option-specific price adjustment is not safely exposed.".strip()
            option_price, suppressed = should_suppress_price(title, option_title, body_text, option_price)
            if suppressed:
                detail = f"{detail} {suppressed}".strip()
            quantity = option_quantity if option_quantity is not None else (base_quantity if len(select.select("option")) == 1 else None)
            quantity_kind = "exact" if quantity is not None else ("availability" if available is not None else "unknown")
            if option_quantity is None and quantity is not None:
                quantity_kind = base_quantity_kind
            result.append(
                base_observation(
                    product_id=product_id,
                    variant_id=option_key,
                    product_title=title,
                    variant_title=option_title,
                    url=product_url,
                    available=available,
                    status=status,
                    quantity=quantity,
                    quantity_kind=quantity_kind,
                    price=option_price,
                    currency=currency,
                    compare_at_price=compare_at if not _OPTION_DELTA.search(option_title) else None,
                    detail=detail,
                )
            )
        return result

    def _selectable_option_selects(self, soup: BeautifulSoup) -> list[Tag]:
        option_area = self._primary_product_area(soup) or soup
        selectors: list[Tag] = []
        for select in option_area.select("select"):
            if self._is_hidden(select) or self._is_related_item(select):
                continue
            identity = " ".join((safe_text(select.get("name")), safe_text(select.get("id")), " ".join(select.get("class", [])))).casefold()
            if any(token in identity for token in ("qty", "quantity", "country", "language", "sort", "display")):
                continue
            options = [option for option in select.select("option") if not is_placeholder(option.get_text(" ", strip=True)) and safe_text(option.get("value")) not in {"*", "**"}]
            if options:
                selectors.append(select)
        return selectors

    def _single_option_stock(self, soup: BeautifulSoup) -> tuple[int, bool] | None:
        """Read Cafe24's public single-option stock JSON only when no option groups exist."""
        if self.platform != "cafe24":
            return None
        for script in soup.select("script:not([src])"):
            text = script.string or script.get_text()
            match = re.search(r"single_option_stock_data\s*=\s*(['\"])(.*?)\1\s*;", text, re.S)
            if not match:
                continue
            raw = match.group(2)
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                try:
                    payload = json.loads(raw.replace(r'\"', '"'))
                except json.JSONDecodeError:
                    continue
            if not isinstance(payload, dict) or payload.get("use_stock") is not True:
                continue
            stock = payload.get("stock_number")
            if isinstance(stock, int) and not isinstance(stock, bool):
                quantity = stock
            elif isinstance(stock, str) and re.fullmatch(r"\d+", stock.strip()):
                quantity = int(stock.strip())
            else:
                continue
            if quantity < 0:
                continue
            reserve = safe_text(payload.get("is_reserve_stat")).casefold() in {"y", "true", "1"}
            return quantity, reserve
        return None

    def _jsonld_variants(
        self,
        soup: BeautifulSoup,
        product_id: str,
        title: str,
        product_url: str,
        currency: str | None,
        body_text: str,
    ) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for product in parse_jsonld_products(soup):
            variants = product.get("hasVariant")
            if not isinstance(variants, list):
                continue
            for index, variant in enumerate(variants):
                if not isinstance(variant, dict):
                    continue
                variant_title = safe_text(variant.get("name")) or f"Option {index + 1}"
                offer = jsonld_offer(variant) or {}
                variant_currency = iso_currency(offer.get("priceCurrency")) or currency
                price = decimal_string(offer.get("price"), variant_currency)
                price, suppressed = should_suppress_price(title, variant_title, body_text, price)
                availability_raw = safe_text(offer.get("availability")).lower()
                if "outofstock" in availability_raw or "soldout" in availability_raw:
                    available, status, detail = False, "sold_out", "Public product data reports this option sold out."
                elif "preorder" in availability_raw:
                    available, status, detail = True, "preorder", "Public product data reports this option as a preorder."
                elif "instock" in availability_raw:
                    available, status, detail = True, "in_stock", "Public product data reports this option available."
                else:
                    available, status, detail = None, "unknown", "Public product data did not expose option availability."
                if suppressed:
                    detail = f"{detail} {suppressed}"
                key = safe_text(variant.get("sku") or variant.get("productID") or variant.get("@id") or variant.get("url"))
                if not key:
                    key = f"jsonld:{index + 1}"
                result.append(
                    base_observation(
                        product_id=product_id,
                        variant_id=key,
                        product_title=title,
                        variant_title=variant_title,
                        url=product_url,
                        available=available,
                        status=status,
                        price=price if variant_currency else None,
                        currency=variant_currency,
                        detail=detail,
                    )
                )
        return result

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
