import pathlib

from scam_agent.scraper import find_related_scam_urls, parse_scam_page

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def test_parse_scam_page_extracts_fields():
    html = (FIXTURES / "scam_724988.html").read_text()
    scam = parse_scam_page(html, "https://www.scamwatcher.com/scam/view/724988", "724988")

    assert scam.title == "Fake Investment Broker Scam"
    assert scam.category == "Investment Scam"
    assert scam.date_reported == "2026-06-01"
    assert "GlobalTrade Investments" in scam.description
    assert "investment" in scam.tags


def test_parse_scam_page_extracts_indicators():
    html = (FIXTURES / "scam_724988.html").read_text()
    scam = parse_scam_page(html, "https://www.scamwatcher.com/scam/view/724988", "724988")

    assert "scammer@globaltrade-fake.com" in scam.emails
    assert any("555" in phone for phone in scam.phones)
    assert any(url.startswith("https://globaltrade-fake.com") for url in scam.urls)


def test_find_related_scam_urls_returns_other_ids_in_order():
    html = (FIXTURES / "scam_724988.html").read_text()
    related = find_related_scam_urls(
        html, "https://www.scamwatcher.com/scam/view/724988", exclude_id="724988", limit=5
    )

    ids = [scam_id for scam_id, _ in related]
    assert ids == ["724989", "724990"]
