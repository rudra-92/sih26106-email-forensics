"""URL extractor for plain-text and HTML email content.

Extracts URLs from:
1. Plain-text body content
2. HTML anchors (<a href="...">visible text</a>)
3. HTML anchors where visible text itself contains a destination URL

Preserves strict provenance:
- visible_text
- actual_url
- raw_url
- source ('plain_text', 'html_href', 'html_visible_text')
"""

from html.parser import HTMLParser
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .models import ExtractedUrl

# Regex matching web schemes (http, https, ftp)
_URL_REGEX = re.compile(
    r"\b(?:https?://|ftp://)[^\s<>'\"`]+",
    re.IGNORECASE,
)

# Trailing punctuation characters commonly attached to URLs in plain text
_TRAILING_PUNCTUATION = ".,!?;:)>]}'\""


def _clean_plain_text_url(raw_match: str) -> str:
    """Strip trailing sentence punctuation from plain-text matched URLs."""
    url = raw_match
    while url and url[-1] in _TRAILING_PUNCTUATION:
        # Avoid stripping trailing slash or balanced closing parentheses in path
        if url[-1] == ")" and "(" in url:
            break
        url = url[:-1]
    return url


class _HtmlLinkParser(HTMLParser):
    """HTML parser extracting anchors, href targets, visible link text, and raw body text."""

    def __init__(self) -> None:
        super().__init__()
        self.extracted: List[ExtractedUrl] = []
        self._current_href: Optional[str] = None
        self._current_text: List[str] = []
        self._inside_anchor = False
        self._non_anchor_text: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag.lower() == "a":
            self._inside_anchor = True
            attrs_dict = dict(attrs)
            self._current_href = attrs_dict.get("href")
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._inside_anchor:
            self._current_text.append(data)
        else:
            self._non_anchor_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a":
            if self._current_href:
                actual_href = self._current_href.strip()
                visible_str = "".join(self._current_text).strip()

                # Determine if visible text itself is or contains a URL
                visible_has_url = bool(_URL_REGEX.search(visible_str))

                # Primary href record
                self.extracted.append(
                    ExtractedUrl(
                        actual_url=actual_href,
                        raw_url=actual_href,
                        source="html_href",
                        visible_text=visible_str if visible_str else None,
                    )
                )

                # If visible text contains a distinct URL, extract that as html_visible_text
                if visible_has_url:
                    for v_match in _URL_REGEX.finditer(visible_str):
                        clean_v_url = _clean_plain_text_url(v_match.group(0))
                        if clean_v_url:
                            self.extracted.append(
                                ExtractedUrl(
                                    actual_url=clean_v_url,
                                    raw_url=clean_v_url,
                                    source="html_visible_text",
                                    visible_text=visible_str,
                                )
                            )

            self._current_href = None
            self._current_text = []
            self._inside_anchor = False

    def get_non_anchor_text(self) -> str:
        return " ".join(self._non_anchor_text)


class UrlExtractor:
    """Forensic extractor capturing URLs and anchor provenance from email text/HTML."""

    def extract(self, content: Union[str, bytes, Dict[str, Any], Any]) -> List[ExtractedUrl]:
        """Extract all URLs from input text, HTML, or structured payload dictionary.

        Args:
            content: Raw string, bytes, dictionary with 'text'/'html' keys,
                     or email body content.

        Returns:
            List of ExtractedUrl objects with preserved provenance.
        """
        if content is None:
            return []

        # 1. Unpack dictionary format (e.g. {"text": "...", "html": "..."})
        if isinstance(content, dict):
            extracted: List[ExtractedUrl] = []
            if "html" in content and content["html"]:
                extracted.extend(self._extract_from_html(str(content["html"])))
            if "text" in content and content["text"]:
                extracted.extend(self._extract_from_plain_text(str(content["text"])))
            if not extracted and "body" in content and content["body"]:
                extracted.extend(self.extract(content["body"]))
            return self._deduplicate_preserving_provenance(extracted)

        # 2. Decode raw bytes
        if isinstance(content, bytes):
            try:
                text_content = content.decode("utf-8")
            except UnicodeDecodeError:
                text_content = content.decode("latin-1", errors="replace")
        elif isinstance(content, str):
            text_content = content
        else:
            text_content = str(content)

        # 3. Detect if content contains HTML markup
        has_html_tags = bool(re.search(r"<[a-zA-Z][^>]*>", text_content))

        if has_html_tags:
            extracted = self._extract_from_html(text_content)
        else:
            extracted = self._extract_from_plain_text(text_content)

        return self._deduplicate_preserving_provenance(extracted)

    def _extract_from_plain_text(self, text: str) -> List[ExtractedUrl]:
        """Extract URLs from plain text string with character offsets."""
        results: List[ExtractedUrl] = []
        for match in _URL_REGEX.finditer(text):
            raw = match.group(0)
            cleaned = _clean_plain_text_url(raw)
            if cleaned:
                results.append(
                    ExtractedUrl(
                        actual_url=cleaned,
                        raw_url=raw,
                        source="plain_text",
                        visible_text=None,
                        char_offset=match.start(),
                    )
                )
        return results

    def _extract_from_html(self, html_content: str) -> List[ExtractedUrl]:
        """Extract URLs from HTML anchors and surrounding non-anchor text."""
        parser = _HtmlLinkParser()
        try:
            parser.feed(html_content)
            parser.close()
        except Exception:
            # Fall back to regex if HTML is severely malformed
            return self._extract_from_plain_text(html_content)

        results = list(parser.extracted)

        # Also extract any loose URLs in non-anchor text
        remaining_text = parser.get_non_anchor_text()
        loose_urls = self._extract_from_plain_text(remaining_text)
        results.extend(loose_urls)

        return results

    def _deduplicate_preserving_provenance(
        self, urls: List[ExtractedUrl]
    ) -> List[ExtractedUrl]:
        """Deduplicate identical (actual_url, source, visible_text) triples while keeping sequence."""
        seen: Set[Tuple[str, str, Optional[str]]] = set()
        deduped: List[ExtractedUrl] = []
        for u in urls:
            key = (u.actual_url, u.source, u.visible_text)
            if key not in seen:
                seen.add(key)
                deduped.append(u)
        return deduped


def extract_urls(content: Union[str, bytes, Dict[str, Any], Any]) -> List[ExtractedUrl]:
    """Convenience function to extract URLs from text, HTML, or payload dict."""
    return UrlExtractor().extract(content)
