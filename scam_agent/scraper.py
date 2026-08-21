"""Fetches scam reports from scamwatcher.com.

Parsing is intentionally tolerant: scamwatcher.com pages are matched with a
few candidate CSS selectors (schema.org markup, common heading/description
class names) with a plain-text fallback, since we could not confirm the
exact markup from this environment (outbound network access to the site is
blocked here). Adjust SELECTOR candidates below if the live site differs.
"""

import re
from urllib.parse import unquote, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from .models import ScamEntry

USER_AGENT = "ScamWatcherAgent/1.0 (+https://github.com/DzenanMuftic/scam_watcher)"
REQUEST_TIMEOUT = 15

SCAM_LINK_RE = re.compile(r"/scam/view/(\d+)")
LOCAL_FIXTURE_ID_RE = re.compile(r"scam_(\d+)\.html$")


def _fetch_text(url: str) -> str:
    """Fetches page text over HTTP(S), or reads it from disk when url is a
    file:// URI. The file:// mode lets the pipeline be exercised end-to-end
    against local HTML fixtures when the live site is unreachable."""
    if urlparse(url).scheme == "file":
        path = unquote(urlparse(url).path)
        with open(path, encoding="utf-8") as f:
            return f.read()
    resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    return resp.text


def _first_text(soup: BeautifulSoup, selectors) -> str:
    for selector in selectors:
        node = soup.select_one(selector)
        if node and node.get_text(strip=True):
            return node.get_text(" ", strip=True)
    return ""


def parse_scam_page(html: str, url: str, scam_id: str) -> ScamEntry:
    soup = BeautifulSoup(html, "html.parser")

    title = _first_text(soup, ["h1", ".scam-title", "[itemprop=name]", "title"])
    description = _first_text(
        soup,
        [
            ".scam-description",
            ".scam-details",
            "[itemprop=description]",
            "article",
            ".content",
            "main",
        ],
    )
    category = _first_text(soup, [".scam-category", ".category", "[itemprop=category]"])
    date_reported = _first_text(soup, [".scam-date", "time", "[itemprop=datePublished]"])
    loss_amount = _first_text(soup, [".loss-amount", ".amount-lost"])
    tags = [t.get_text(strip=True) for t in soup.select(".tag, .tags a, .badge") if t.get_text(strip=True)]

    return ScamEntry(
        scam_id=scam_id,
        url=url,
        title=title,
        category=category,
        date_reported=date_reported,
        description=description,
        tags=tags,
        loss_amount=loss_amount,
    )


def find_related_scam_urls(html: str, base_url: str, exclude_id: str, limit: int):
    """Finds links to other /scam/view/<id> pages on a scam detail page,
    e.g. a "similar" or "related scams" section, preserving page order."""
    soup = BeautifulSoup(html, "html.parser")
    seen = set()
    ordered = []
    for a in soup.find_all("a", href=True):
        match = SCAM_LINK_RE.search(a["href"])
        if not match:
            continue
        found_id = match.group(1)
        if found_id == exclude_id or found_id in seen:
            continue
        seen.add(found_id)
        if urlparse(base_url).scheme == "file":
            # Local fixtures use flat filenames (scam_<id>.html) rather than
            # the site's /scam/view/<id> path structure, so resolve siblings
            # by id instead of literally joining the href.
            related_url = urljoin(base_url, f"scam_{found_id}.html")
        else:
            related_url = urljoin(base_url, a["href"])
        ordered.append((found_id, related_url))
        if len(ordered) >= limit:
            break
    return ordered


def fetch_top_scams(source_url: str, top_n: int):
    """Fetches the seed scam report at source_url, then follows related-scam
    links found on that page (in page order) until top_n entries total are
    collected. Returns a list of ScamEntry."""
    match = SCAM_LINK_RE.search(source_url) or LOCAL_FIXTURE_ID_RE.search(source_url)
    seed_id = match.group(1) if match else source_url

    seed_html = _fetch_text(source_url)

    entries = [parse_scam_page(seed_html, source_url, seed_id)]

    related = find_related_scam_urls(seed_html, source_url, seed_id, limit=top_n - 1)
    for related_id, related_url in related:
        try:
            related_html = _fetch_text(related_url)
            entries.append(parse_scam_page(related_html, related_url, related_id))
        except (requests.RequestException, OSError):
            continue
        if len(entries) >= top_n:
            break

    return entries[:top_n]
