"""Fetches threat-intel "pulses" from AlienVault OTX (via the OTXv2 SDK,
https://github.com/AlienVault-OTX/OTX-Python-SDK) as the scam-report source.

Each pulse is mapped onto the same ScamEntry model the rest of the pipeline
(analysis.py, report.py) already works with, so pulse indicators (domains,
URLs, emails, IPs, hashes, ...) are folded into the entry's description text
where the existing phone/email/url regex extraction in models.py can still
pick them up.

search_pulses() only returns lightweight summaries (no indicators, usually
no tags), so each candidate pulse id is re-fetched with get_pulse_details()
to get the full record.
"""

import requests
from OTXv2 import OTXv2

from .models import ScamEntry

OTX_PULSE_URL = "https://otx.alienvault.com/pulse/{}"

# Only indicator types that can plausibly contain a phone/email/URL are
# folded into the description (which models.py mines with regex). File
# hashes, YARA rules, and mutexes are hex/opaque strings whose digit runs
# would otherwise register as false-positive phone matches.
CONTACT_INDICATOR_TYPES = {
    "domain",
    "hostname",
    "URL",
    "URI",
    "email",
    "IPv4",
    "IPv6",
}


def _pulse_to_scam_entry(pulse: dict) -> ScamEntry:
    pulse_id = str(pulse.get("id", ""))
    tags = pulse.get("tags") or []

    indicators = pulse.get("indicators") or []
    indicator_lines = [
        f"{ind.get('type', '')}: {ind.get('indicator', '')}"
        for ind in indicators
        if ind.get("indicator") and ind.get("type") in CONTACT_INDICATOR_TYPES
    ]
    description = pulse.get("description") or ""
    if indicator_lines:
        description = f"{description}\nIndicators: " + " | ".join(indicator_lines)

    return ScamEntry(
        scam_id=pulse_id,
        url=OTX_PULSE_URL.format(pulse_id),
        title=pulse.get("name", ""),
        category=tags[0] if tags else "",
        date_reported=pulse.get("created", ""),
        description=description,
        tags=tags,
        loss_amount="",
    )


def fetch_top_scams(api_key: str, query: str, top_n: int):
    """Searches OTX pulses matching query, then fetches each candidate's full
    details (tags + indicators), returning up to top_n as ScamEntry."""
    otx = OTXv2(api_key)
    result = otx.search_pulses(query, max_results=top_n)
    candidates = result.get("results", []) if isinstance(result, dict) else (result or [])

    entries = []
    for candidate in candidates[:top_n]:
        pulse_id = candidate.get("id")
        if not pulse_id:
            continue
        try:
            details = otx.get_pulse_details(pulse_id)
        except requests.RequestException:
            details = candidate
        entries.append(_pulse_to_scam_entry(details))
    return entries
