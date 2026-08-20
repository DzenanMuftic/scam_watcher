"""Finds relations between a set of scraped scam reports: shared contact
indicators, shared category, and overlapping description keywords."""

import re
from collections import defaultdict
from itertools import combinations

STOPWORDS = {
    "the", "a", "an", "and", "or", "but", "to", "of", "in", "on", "for",
    "with", "is", "was", "were", "are", "be", "been", "this", "that", "it",
    "as", "at", "by", "from", "my", "me", "i", "you", "your", "they", "them",
    "he", "she", "his", "her", "then", "so", "if", "not", "no", "would",
    "will", "have", "has", "had", "do", "did", "does", "their", "our",
}

WORD_RE = re.compile(r"[a-zA-Z]{4,}")


def _keywords(text: str):
    return {w.lower() for w in WORD_RE.findall(text) if w.lower() not in STOPWORDS}


def find_relations(scams):
    """Returns a dict with:
      - shared_indicators: contact indicators (phone/email/url) reused across >=2 scams
      - shared_categories: category -> [scam_ids]
      - keyword_overlaps: pairs of scams whose descriptions share notable keywords
    """
    indicator_map = defaultdict(set)
    for scam in scams:
        for phone in scam.phones:
            indicator_map[("phone", phone)].add(scam.scam_id)
        for email in scam.emails:
            indicator_map[("email", email)].add(scam.scam_id)
        for url in scam.urls:
            indicator_map[("url", url)].add(scam.scam_id)

    shared_indicators = [
        {"type": kind, "value": value, "scam_ids": sorted(ids)}
        for (kind, value), ids in indicator_map.items()
        if len(ids) >= 2
    ]

    category_map = defaultdict(list)
    for scam in scams:
        if scam.category:
            category_map[scam.category].append(scam.scam_id)
    shared_categories = {cat: ids for cat, ids in category_map.items() if len(ids) >= 2}

    keyword_sets = {scam.scam_id: _keywords(scam.description) for scam in scams}
    keyword_overlaps = []
    for a, b in combinations(scams, 2):
        set_a, set_b = keyword_sets[a.scam_id], keyword_sets[b.scam_id]
        if not set_a or not set_b:
            continue
        shared = set_a & set_b
        union = set_a | set_b
        jaccard = len(shared) / len(union) if union else 0.0
        if jaccard >= 0.15 and len(shared) >= 3:
            keyword_overlaps.append(
                {
                    "scam_ids": [a.scam_id, b.scam_id],
                    "similarity": round(jaccard, 3),
                    "shared_keywords": sorted(shared)[:15],
                }
            )

    return {
        "shared_indicators": shared_indicators,
        "shared_categories": shared_categories,
        "keyword_overlaps": keyword_overlaps,
    }
