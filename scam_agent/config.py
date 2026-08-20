"""Configuration for the scam watcher agent, sourced from environment
variables (optionally loaded from a .env file)."""

import os
from dataclasses import dataclass

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

DEFAULT_SOURCE_URL = "https://www.scamwatcher.com/scam/view/724988"
DEFAULT_RECIPIENT = "dmuftic@ziraatbank.ba"
DEFAULT_TOP_N = 10


@dataclass(frozen=True)
class SmtpConfig:
    host: str
    port: int
    username: str
    password: str
    use_tls: bool
    sender: str

    @classmethod
    def from_env(cls) -> "SmtpConfig":
        return cls(
            host=os.environ.get("SMTP_HOST", "smtp.gmail.com"),
            port=int(os.environ.get("SMTP_PORT", "587")),
            username=os.environ.get("SMTP_USERNAME", ""),
            password=os.environ.get("SMTP_PASSWORD", ""),
            use_tls=os.environ.get("SMTP_USE_TLS", "true").lower() != "false",
            sender=os.environ.get("EMAIL_FROM", os.environ.get("SMTP_USERNAME", "")),
        )


def get_source_url() -> str:
    return os.environ.get("SCAM_SOURCE_URL", DEFAULT_SOURCE_URL)


def get_recipient() -> str:
    return os.environ.get("SCAM_REPORT_RECIPIENT", DEFAULT_RECIPIENT)


def get_top_n() -> int:
    return int(os.environ.get("SCAM_TOP_N", str(DEFAULT_TOP_N)))
