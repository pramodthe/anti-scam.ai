import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


URL_PATTERN = re.compile(r"https?://[^\s<>'\"()]+", flags=re.IGNORECASE)
HREF_PATTERN = re.compile(r"""href\s*=\s*["'](https?://[^"']+)["']""", flags=re.IGNORECASE)
TRAILING_PUNCT = ".,;:!?)]}'\""
TRACKING_QUERY_KEYS = {
    "fbclid",
    "gclid",
    "igshid",
    "mc_cid",
    "mc_eid",
    "ref",
    "ref_src",
}
TRACKING_QUERY_PREFIXES = ("utm_",)


@dataclass(frozen=True)
class ExtractedLink:
    original_url: str
    normalized_url: str


def _strip_trailing_punct(url: str) -> str:
    cleaned = url.strip()
    while cleaned and cleaned[-1] in TRAILING_PUNCT:
        cleaned = cleaned[:-1]
    return cleaned


def _normalize_url(raw_url: str, allow_http: bool) -> str | None:
    candidate = _strip_trailing_punct(raw_url)
    parsed = urlparse(candidate)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        return None
    if scheme == "http" and not allow_http:
        return None

    netloc = parsed.netloc.lower().strip()
    if not netloc:
        return None

    filtered_params: list[tuple[str, str]] = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        lowered = key.lower()
        if lowered in TRACKING_QUERY_KEYS:
            continue
        if any(lowered.startswith(prefix) for prefix in TRACKING_QUERY_PREFIXES):
            continue
        filtered_params.append((key, value))

    normalized_query = urlencode(filtered_params, doseq=True)
    normalized_path = parsed.path or "/"
    return urlunparse((scheme, netloc, normalized_path, "", normalized_query, ""))


def _extract_raw_urls(text: str) -> list[str]:
    if not text:
        return []
    raw_urls = URL_PATTERN.findall(text)
    raw_urls.extend(HREF_PATTERN.findall(text))
    return raw_urls


def extract_links_from_email(
    email: dict[str, Any],
    max_urls: int,
    allow_http: bool,
    explicit_urls: list[str] | None = None,
) -> tuple[list[ExtractedLink], int]:
    discovered: list[str] = []
    if explicit_urls:
        discovered.extend(explicit_urls)
    else:
        discovered.extend(_extract_raw_urls(str(email.get("subject", ""))))
        discovered.extend(_extract_raw_urls(str(email.get("body", ""))))

    deduped: list[ExtractedLink] = []
    seen: set[str] = set()
    for raw in discovered:
        normalized = _normalize_url(raw, allow_http=allow_http)
        if not normalized:
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(ExtractedLink(original_url=raw, normalized_url=normalized))

    links_found = len(deduped)
    return deduped[:max_urls], links_found
