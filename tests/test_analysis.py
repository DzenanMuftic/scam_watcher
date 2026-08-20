import pathlib

from scam_agent.analysis import find_relations
from scam_agent.scraper import parse_scam_page

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def load(name, scam_id):
    html = (FIXTURES / name).read_text()
    return parse_scam_page(html, f"https://www.scamwatcher.com/scam/view/{scam_id}", scam_id)


def test_find_relations_detects_shared_email_and_category():
    scam_a = load("scam_724988.html", "724988")
    scam_b = load("scam_724989.html", "724989")

    relations = find_relations([scam_a, scam_b])

    shared_emails = [i for i in relations["shared_indicators"] if i["type"] == "email"]
    assert shared_emails
    assert shared_emails[0]["value"] == "scammer@globaltrade-fake.com"
    assert set(shared_emails[0]["scam_ids"]) == {"724988", "724989"}

    assert "Investment Scam" in relations["shared_categories"]
    assert set(relations["shared_categories"]["Investment Scam"]) == {"724988", "724989"}


def test_find_relations_detects_keyword_overlap():
    scam_a = load("scam_724988.html", "724988")
    scam_b = load("scam_724989.html", "724989")

    relations = find_relations([scam_a, scam_b])

    assert relations["keyword_overlaps"]
    pair = relations["keyword_overlaps"][0]
    assert set(pair["scam_ids"]) == {"724988", "724989"}
    assert "investment" in pair["shared_keywords"] or "guaranteed" in pair["shared_keywords"]
