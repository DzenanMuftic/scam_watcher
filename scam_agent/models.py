"""Data model for a single scraped scam report."""

import re
from dataclasses import dataclass, field

PHONE_RE = re.compile(r"(?<!\d)(\+?\d[\d\-\s().]{6,}\d)(?!\d)")
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
URL_RE = re.compile(r"https?://[^\s\"'<>)]+")


@dataclass
class ScamEntry:
    scam_id: str
    url: str
    title: str = ""
    category: str = ""
    date_reported: str = ""
    description: str = ""
    tags: list = field(default_factory=list)
    loss_amount: str = ""

    @property
    def phones(self):
        return sorted(set(m.strip() for m in PHONE_RE.findall(self.description)))

    @property
    def emails(self):
        return sorted(set(EMAIL_RE.findall(self.description)))

    @property
    def urls(self):
        return sorted(set(URL_RE.findall(self.description)))

    def to_dict(self) -> dict:
        return {
            "scam_id": self.scam_id,
            "url": self.url,
            "title": self.title,
            "category": self.category,
            "date_reported": self.date_reported,
            "description": self.description,
            "tags": self.tags,
            "loss_amount": self.loss_amount,
            "indicators": {
                "phones": self.phones,
                "emails": self.emails,
                "urls": self.urls,
            },
        }
