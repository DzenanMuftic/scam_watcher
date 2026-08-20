"""CLI entrypoint: scrape top scams from scamwatcher.com, find relations
between them, and email the isolated findings for a local app to parse.

Usage:
    python -m scam_agent.main [--url URL] [--top-n N] [--to EMAIL] [--dry-run]
"""

import argparse
import sys

from .analysis import find_relations
from .config import SmtpConfig, get_recipient, get_source_url, get_top_n
from .emailer import send_email
from .report import build_email, build_payload
from .scraper import fetch_top_scams


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=get_source_url(), help="Seed scam report URL")
    parser.add_argument("--top-n", type=int, default=get_top_n(), help="Number of scams to collect")
    parser.add_argument("--to", default=get_recipient(), help="Recipient email address")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the email subject/body instead of sending it",
    )
    args = parser.parse_args(argv)

    print(f"Fetching {args.top_n} scam report(s) starting from {args.url} ...", file=sys.stderr)
    scams = fetch_top_scams(args.url, args.top_n)
    print(f"Collected {len(scams)} scam report(s). Analyzing relations ...", file=sys.stderr)

    relations = find_relations(scams)
    payload = build_payload(args.url, scams, relations)
    subject, body = build_email(payload)

    if args.dry_run:
        print(subject)
        print(body)
        return 0

    smtp_config = SmtpConfig.from_env()
    send_email(smtp_config, args.to, subject, body)
    print(f"Email sent to {args.to}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
