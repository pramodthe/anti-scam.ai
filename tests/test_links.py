import unittest

from backend.app.risk_agent.links import extract_links_from_email


class LinkExtractionTests(unittest.TestCase):
    def test_extracts_dedupes_and_limits_urls(self) -> None:
        email = {
            "subject": "Click https://Example.com/path?utm_source=x&a=1 and https://example.com/path?a=1",
            "body": '<a href="https://example.com/path?a=1&utm_campaign=test">open</a> '
            "and http://unsafe.example.com/page?fbclid=123",
        }

        links, found = extract_links_from_email(email=email, max_urls=3, allow_http=False)
        self.assertEqual(found, 1)
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].normalized_url, "https://example.com/path?a=1")

    def test_explicit_urls_override_body_parsing(self) -> None:
        email = {"subject": "", "body": "ignored"}
        links, found = extract_links_from_email(
            email=email,
            max_urls=3,
            allow_http=True,
            explicit_urls=["https://safe.example.com/a", "https://safe.example.com/a", "http://x.test/z"],
        )
        self.assertEqual(found, 2)
        self.assertEqual(len(links), 2)


if __name__ == "__main__":
    unittest.main()
