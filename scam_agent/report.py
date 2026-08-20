"""Builds the isolated data payload and email body sent to the recipient.

The payload contains only the fields relevant to each scam (id, url, title,
category, date, description, tags, extracted contact indicators) plus the
computed relations. It is embedded in the email as a JSON block so a
separate local application can parse it directly -- this agent does not
read or write any local scam database itself.
"""

import json
from datetime import datetime, timezone


def build_payload(source_url: str, scams, relations: dict) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_url": source_url,
        "scam_count": len(scams),
        "scams": [scam.to_dict() for scam in scams],
        "relations": relations,
    }


def build_email(payload: dict) -> tuple:
    scam_count = payload["scam_count"]
    subject = f"Scam Watcher: {scam_count} scam reports + relation findings ({payload['generated_at'][:10]})"

    lines = [
        "Automated Scam Watcher report.",
        f"Source: {payload['source_url']}",
        f"Scams collected: {scam_count}",
        "",
        "Summary of findings:",
    ]

    relations = payload["relations"]
    if relations["shared_indicators"]:
        lines.append(f"- {len(relations['shared_indicators'])} contact indicator(s) reused across multiple scams:")
        for item in relations["shared_indicators"]:
            lines.append(f"    [{item['type']}] {item['value']} -> scam_ids {item['scam_ids']}")
    else:
        lines.append("- No reused contact indicators (phone/email/url) found across scams.")

    if relations["shared_categories"]:
        lines.append(f"- {len(relations['shared_categories'])} shared categor(y/ies):")
        for cat, ids in relations["shared_categories"].items():
            lines.append(f"    {cat} -> scam_ids {ids}")

    if relations["keyword_overlaps"]:
        lines.append(f"- {len(relations['keyword_overlaps'])} scam pair(s) with overlapping description keywords:")
        for pair in relations["keyword_overlaps"]:
            lines.append(
                f"    scam_ids {pair['scam_ids']} similarity={pair['similarity']} keywords={pair['shared_keywords']}"
            )

    lines.append("")
    lines.append("Full structured data (JSON) for the local application to parse:")
    lines.append("---BEGIN SCAM_WATCHER_JSON---")
    lines.append(json.dumps(payload, indent=2, ensure_ascii=False))
    lines.append("---END SCAM_WATCHER_JSON---")

    return subject, "\n".join(lines)
