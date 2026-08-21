"""CLI entrypoint: search AlienVault OTX for scam-related threat-intel
pulses, find relations between them, and email the isolated findings for a
local app to parse.

Usage:
    python -m scam_agent.main [--query TERM] [--top-n N] [--to EMAIL] [--dry-run]
"""

import argparse
import sys

from .analysis import find_relations
from .config import SmtpConfig, get_otx_api_key, get_otx_query, get_recipient, get_top_n
from .emailer import send_email
from .otx_source import fetch_top_scams
from .report import build_email, build_payload


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--query", default=get_otx_query(), help="OTX pulse search keyword")
    parser.add_argument("--top-n", type=int, default=get_top_n(), help="Number of pulses to collect")
    parser.add_argument("--to", default=get_recipient(), help="Recipient email address")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the email subject/body instead of sending it",
    )
    args = parser.parse_args(argv)

    api_key = get_otx_api_key()
    if not api_key:
        print("OTX_API_KEY is not set (add it to .env)", file=sys.stderr)
        return 1

    print(f"Searching OTX for {args.top_n} pulse(s) matching '{args.query}' ...", file=sys.stderr)
    scams = fetch_top_scams(api_key, args.query, args.top_n)
    print(f"Collected {len(scams)} pulse(s). Analyzing relations ...", file=sys.stderr)

    relations = find_relations(scams)
    payload = build_payload(f"otx-search:{args.query}", scams, relations)
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
