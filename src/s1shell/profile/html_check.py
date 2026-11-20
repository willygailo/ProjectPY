"""Zero-extra-packet passive HTML inspection for SRI, mixed content, forms, origins, and libs."""

from __future__ import annotations

import contextlib
import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

from s1shell.profile.models import HTMLPassiveAnalysis

_MAX_PARSE_BYTES = 512 * 1024  # Cap HTML DOM parse at 512 KiB for speed & safety

_LIB_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("jquery", re.compile(r"jquery[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("bootstrap", re.compile(r"bootstrap[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("lodash", re.compile(r"lodash[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("angular", re.compile(r"angular(?:\.min)?[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("vue", re.compile(r"vue(?:\.global)?[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("react", re.compile(r"react(?:-dom)?[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("moment", re.compile(r"moment[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("dompurify", re.compile(r"(?:dom)?purify[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("axios", re.compile(r"axios[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("handlebars", re.compile(r"handlebars(?:\.min)?[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("alpinejs", re.compile(r"alpine(?:js)?[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("htmx", re.compile(r"htmx(?:\.min)?[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("swagger-ui", re.compile(r"swagger-ui[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
]


def _parse_external_origin(raw_url: str, page_host: str) -> tuple[bool, str | None, str | None]:
    """Return `(is_external, scheme, origin_host)` for a resource URL relative to `page_host`."""
    cleaned = raw_url.strip()
    if not cleaned or cleaned.startswith(("#", "data:", "javascript:", "mailto:", "blob:")):
        return False, None, None
    if cleaned.startswith("//"):
        parts = urlsplit("https:" + cleaned)
        host = (parts.hostname or "").lower()
        is_ext = bool(host and host != page_host)
        return is_ext, None, (host if is_ext else None)
    parts = urlsplit(cleaned)
    if parts.scheme in {"http", "https"}:
        host = (parts.hostname or "").lower()
        is_ext = bool(host and host != page_host)
        return is_ext, parts.scheme.lower(), (host if is_ext else None)
    return False, None, None


class _PassiveHTMLParser(HTMLParser):
    """Linear-time stdlib HTML parser extracting defensive posture & passive stack hints."""

    def __init__(self, *, page_host: str, is_https: bool) -> None:
        super().__init__(convert_charrefs=True)
        self._page_host = page_host.lower()
        self._is_https = is_https
        self._in_title = False
        self._title_chunks: list[str] = []
        self._in_form = False
        self._current_form_action = ""
        self._current_form_method = "get"
        self._form_has_password = False

        self.meta_generator: str | None = None
        self.meta_csp: str | None = None
        self.external_scripts_without_sri: list[str] = []
        self.external_styles_without_sri: list[str] = []
        self.mixed_content_urls: list[str] = []
        self.insecure_forms: list[str] = []
        self.detected_libraries: list[str] = []
        self.framework_hints: list[str] = []
        self.third_party_origins: list[str] = []
        self.inline_script_count: int = 0
        self.unsafe_blank_links: int = 0

    def _add_unique(self, target: list[str], value: str, *, limit: int = 25) -> None:
        if value and value not in target and len(target) < limit:
            target.append(value)

    def _scan_library(self, url: str) -> None:
        for lib_name, pat in _LIB_PATTERNS:
            m = pat.search(url)
            if m:
                self._add_unique(self.detected_libraries, f"{lib_name}/{m.group(1)}")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        low_tag = tag.lower()
        attr_map = {k.lower(): (v or "").strip() for k, v in attrs}

        if low_tag == "title":
            self._in_title = True
            return

        if "ng-version" in attr_map and attr_map["ng-version"]:
            self._add_unique(self.framework_hints, f"angular:{attr_map['ng-version']}")
        if "data-reactroot" in attr_map:
            self._add_unique(self.framework_hints, "react")
        if attr_map.get("id") in {"__next", "__NEXT_DATA__"}:
            self._add_unique(self.framework_hints, "nextjs")
        if attr_map.get("id") == "__nuxt":
            self._add_unique(self.framework_hints, "nuxt")
        if attr_map.get("id") == "swagger-ui":
            self._add_unique(self.framework_hints, "swagger-ui")
        if any(k.startswith("data-svelte") for k in attr_map):
            self._add_unique(self.framework_hints, "sveltekit")
        if any(k.startswith("data-astro-") for k in attr_map):
            self._add_unique(self.framework_hints, "astro")

        if low_tag == "meta":
            name = attr_map.get("name", "").lower()
            http_equiv = attr_map.get("http-equiv", "").lower()
            content = attr_map.get("content", "")
            if name == "generator" and content and self.meta_generator is None:
                self.meta_generator = content[:180]
            if http_equiv == "content-security-policy" and content and self.meta_csp is None:
                self.meta_csp = content[:400]
            return

        if low_tag == "script":
            src = attr_map.get("src", "")
            if src:
                self._scan_library(src)
                if "wp-content/" in src or "wp-includes/" in src:
                    self._add_unique(self.framework_hints, "wordpress")
                if "/_next/static/" in src:
                    self._add_unique(self.framework_hints, "nextjs")
                if "/_nuxt/" in src:
                    self._add_unique(self.framework_hints, "nuxt")
                is_ext, scheme, origin_host = _parse_external_origin(src, self._page_host)
                if origin_host:
                    self._add_unique(self.third_party_origins, origin_host, limit=40)
                if self._is_https and scheme == "http":
                    self._add_unique(self.mixed_content_urls, src[:200])
                if is_ext and not attr_map.get("integrity"):
                    self._add_unique(self.external_scripts_without_sri, src[:200])
            else:
                script_type = attr_map.get("type", "").lower()
                if not script_type or "javascript" in script_type or script_type == "module":
                    self.inline_script_count += 1
            return

        if low_tag == "link":
            rel = attr_map.get("rel", "").lower()
            href = attr_map.get("href", "")
            if href:
                self._scan_library(href)
                if "wp-content/" in href or "wp-includes/" in href:
                    self._add_unique(self.framework_hints, "wordpress")
                is_ext, scheme, origin_host = _parse_external_origin(href, self._page_host)
                if origin_host and ("stylesheet" in rel or "preload" in rel):
                    self._add_unique(self.third_party_origins, origin_host, limit=40)
                if (
                    self._is_https
                    and scheme == "http"
                    and ("stylesheet" in rel or "preload" in rel)
                ):
                    self._add_unique(self.mixed_content_urls, href[:200])
                if "stylesheet" in rel and is_ext and not attr_map.get("integrity"):
                    self._add_unique(self.external_styles_without_sri, href[:200])
            return

        if low_tag == "a":
            target_attr = attr_map.get("target", "").lower()
            href = attr_map.get("href", "")
            if target_attr == "_blank" and href:
                is_ext, _, _ = _parse_external_origin(href, self._page_host)
                rel_tokens = set(attr_map.get("rel", "").lower().split())
                if is_ext and "noopener" not in rel_tokens:
                    self.unsafe_blank_links += 1
            return

        if low_tag in {"img", "iframe", "audio", "video", "source"}:
            src = attr_map.get("src", "")
            if src:
                _, scheme, origin_host = _parse_external_origin(src, self._page_host)
                if origin_host:
                    self._add_unique(self.third_party_origins, origin_host, limit=40)
                if self._is_https and scheme == "http":
                    self._add_unique(self.mixed_content_urls, src[:200])
            return

        if low_tag == "form":
            self._in_form = True
            self._form_has_password = False
            action = attr_map.get("action", "")
            self._current_form_action = action
            self._current_form_method = (attr_map.get("method", "get") or "get").lower()
            if action.lower().startswith("http://"):
                self._add_unique(self.insecure_forms, f"form action over HTTP: {action[:160]}")
            return

        if low_tag == "input":
            in_name = attr_map.get("name", "")
            in_type = attr_map.get("type", "").lower()
            if in_name == "csrfmiddlewaretoken":
                self._add_unique(self.framework_hints, "django")
            if in_name == "authenticity_token":
                self._add_unique(self.framework_hints, "rails")
            if in_name == "_token":
                self._add_unique(self.framework_hints, "laravel")
            if in_type == "password":
                self._form_has_password = True
                if not self._is_https and not self._current_form_action.lower().startswith(
                    "https://"
                ):
                    self._add_unique(
                        self.insecure_forms,
                        "password input served over plain HTTP",
                    )
                if self._in_form and self._current_form_method == "get":
                    self._add_unique(
                        self.insecure_forms,
                        "password form uses HTTP GET method (credentials exposed in URL/logs)",
                    )

    def handle_endtag(self, tag: str) -> None:
        low_tag = tag.lower()
        if low_tag == "title":
            self._in_title = False
        elif low_tag == "form":
            self._in_form = False
            self._current_form_action = ""
            self._current_form_method = "get"
            self._form_has_password = False

    def handle_data(self, data: str) -> None:
        if self._in_title and len("".join(self._title_chunks)) < 200:
            self._title_chunks.append(data)

    @property
    def title(self) -> str | None:
        joined = " ".join("".join(self._title_chunks).split()).strip()
        return joined[:160] if joined else None


def _looks_like_html(body: bytes, headers: list[tuple[str, str]]) -> bool:
    for k, v in headers:
        if k.lower() == "content-type":
            low = v.lower()
            if "text/html" in low or "application/xhtml+xml" in low:
                return True
            if "json" in low or "octet-stream" in low or "image/" in low or "pdf" in low:
                return False
    prefix = body[:512].lstrip().lower()
    return prefix.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<meta", b"<title"))


def analyze_html_body(
    body: bytes,
    *,
    headers: list[tuple[str, str]],
    page_url: str,
) -> HTMLPassiveAnalysis:
    """Passively inspect an already-received HTML body with zero extra network requests."""
    if not body or not _looks_like_html(body, headers):
        return HTMLPassiveAnalysis(analyzed=False)

    parts = urlsplit(page_url)
    page_host = (parts.hostname or "").lower()
    is_https = parts.scheme.lower() == "https"

    text = body[:_MAX_PARSE_BYTES].decode("utf-8", errors="replace")
    parser = _PassiveHTMLParser(page_host=page_host, is_https=is_https)
    with contextlib.suppress(Exception):
        parser.feed(text)
        parser.close()

    hints = list(parser.framework_hints)
    if "__NEXT_DATA__" in text and "nextjs" not in hints:
        hints.append("nextjs")
    if "__NUXT__" in text and "nuxt" not in hints:
        hints.append("nuxt")
    if ("wp-content/" in text or "wp-includes/" in text) and "wordpress" not in hints:
        hints.append("wordpress")
    if ("Drupal.settings" in text or "drupal-settings-json" in text) and "drupal" not in hints:
        hints.append("drupal")

    return HTMLPassiveAnalysis(
        analyzed=True,
        title=parser.title,
        meta_generator=parser.meta_generator,
        meta_csp=parser.meta_csp,
        external_scripts_without_sri=parser.external_scripts_without_sri,
        external_styles_without_sri=parser.external_styles_without_sri,
        mixed_content_urls=parser.mixed_content_urls,
        insecure_forms=parser.insecure_forms,
        detected_libraries=parser.detected_libraries,
        framework_hints=hints,
        third_party_origins=parser.third_party_origins,
        inline_script_count=parser.inline_script_count,
        unsafe_blank_links=parser.unsafe_blank_links,
    )
