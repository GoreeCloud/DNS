"""Dependency-free static checks for GoreeCloud DNS public DoH setup accessibility."""
import re
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PageElements(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def contrast_against_white(hex_color):
    values = [int(hex_color[i:i + 2], 16) / 255.0 for i in (1, 3, 5)]
    linear = [v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4 for v in values]
    luminosity = sum(channel * weight for channel, weight in zip(linear, (0.2126, 0.7152, 0.0722)))
    return 1.05 / (luminosity + 0.05)


class DnsOverHttpsAccessibility(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page = (ROOT / "DnsServerCore/dohwww/index.html").read_text(encoding="utf-8")
        cls.css = (ROOT / "DnsServerCore/dohwww/css/goreecloud.css").read_text(encoding="utf-8")
        cls.elements = PageElements()
        cls.elements.feed(cls.page)

    def test_semantic_main_and_keyboard_skip_target(self):
        self.assertTrue(any(tag == "main" and attrs.get("id") == "content"
                            and attrs.get("tabindex") == "-1" for tag, attrs in self.elements.tags))
        self.assertTrue(any(tag == "a" and attrs.get("href") == "#content"
                            and "gc-skip-link" in attrs.get("class", "").split()
                            for tag, attrs in self.elements.tags))

    def test_dynamic_endpoint_remains_labeled_and_wrappable(self):
        self.assertTrue(any(tag == "a" and attrs.get("id") == "lnkDoH" for tag, attrs in self.elements.tags))
        self.assertIn('class="gc-doh-url"', self.page)
        self.assertIn("overflow-wrap: anywhere", self.css)

    def test_default_fallback_text_contrast(self):
        for selector in (".gc-doh-setup .features p", ".gc-doh-setup .features a"):
            pattern = re.escape(selector) + r"\s*\{[^}]*color:\s*var\(--gc-[\w-]+,\s*(#[0-9a-fA-F]{6})\)"
            match = re.search(pattern, self.css, flags=re.S)
            self.assertIsNotNone(match, f"missing semantic color fallback for {selector}")
            self.assertGreaterEqual(contrast_against_white(match.group(1)), 4.5)

    def test_forced_color_readability_is_preserved(self):
        self.assertIn("@media (forced-colors: active)", self.css)
        self.assertIn("color: LinkText", self.css)


if __name__ == "__main__":
    unittest.main()
