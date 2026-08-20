import json
import pathlib

from scam_agent.analysis import find_relations
from scam_agent.report import build_email, build_payload
from scam_agent.scraper import parse_scam_page

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def load(name, scam_id):
    html = (FIXTURES / name).read_text()
    return parse_scam_page(html, f"https://www.scamwatcher.com/scam/view/{scam_id}", scam_id)


def test_build_email_embeds_parseable_json_payload():
    scams = [load("scam_724988.html", "724988"), load("scam_724989.html", "724989")]
    relations = find_relations(scams)
    payload = build_payload("https://www.scamwatcher.com/scam/view/724988", scams, relations)

    subject, body = build_email(payload)

    assert "2" in subject
    assert "---BEGIN SCAM_WATCHER_JSON---" in body
    assert "---END SCAM_WATCHER_JSON---" in body

    json_text = body.split("---BEGIN SCAM_WATCHER_JSON---\n", 1)[1]
    json_text = json_text.rsplit("\n---END SCAM_WATCHER_JSON---", 1)[0]
    parsed = json.loads(json_text)

    assert parsed["scam_count"] == 2
    assert len(parsed["scams"]) == 2
    assert parsed["scams"][0]["scam_id"] == "724988"
