# scam_watcher

An agent that scrapes a scam report from [scamwatcher.com](https://www.scamwatcher.com),
collects related/similar scam reports linked from it (10 by default), finds
relations between them, and emails the isolated findings to a configured
recipient (default: `dmuftic@ziraatbank.ba`) as a structured JSON block for a
**separate local application to parse**. The agent itself never reads from or
writes to any local database — it only fetches from the remote site and sends
one email.

## What it does

1. **Scrape** — fetches the seed report (default:
   `https://www.scamwatcher.com/scam/view/724988`), then follows any
   `/scam/view/<id>` links found on that page (e.g. a "similar scams"
   section) until 10 reports are collected. For each report it extracts:
   `title`, `category`, `date_reported`, `description`, `tags`, and contact
   indicators (`phones`, `emails`, `urls`) parsed out of the description text.
2. **Analyze** — looks for relations across the collected scams:
   - contact indicators (phone / email / URL) reused across more than one scam
   - shared categories
   - overlapping description keywords (Jaccard similarity)
3. **Report & email** — builds an isolated JSON payload (only the fields
   above, nothing else) and emails it, along with a human-readable findings
   summary, to the recipient. The JSON is delimited with
   `---BEGIN SCAM_WATCHER_JSON---` / `---END SCAM_WATCHER_JSON---` markers so
   a local application can extract and parse it straight out of the email
   body.

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env   # fill in SMTP credentials
```

For Gmail as the sending account, use an
[App Password](https://myaccount.google.com/apppasswords) for `SMTP_PASSWORD`
(regular account passwords won't work with SMTP).

## Usage

```bash
# Preview the email without sending it
python -m scam_agent.main --dry-run

# Send it for real
python -m scam_agent.main

# Override the seed URL, count, or recipient
python -m scam_agent.main --url https://www.scamwatcher.com/scam/view/724988 --top-n 10 --to dmuftic@ziraatbank.ba
```

## Known limitation

The exact HTML structure of scamwatcher.com pages could not be confirmed
while building this agent, because outbound network access to that domain
was not available in the build environment. `scam_agent/scraper.py` matches
several common selector patterns (schema.org `itemprop` attributes, typical
`.scam-title` / `.scam-description` / `.scam-category` class names, generic
`article`/`main` fallback) plus regex-based extraction of phone numbers,
emails, and URLs straight from the description text. Run
`python -m scam_agent.main --dry-run` against the live site first and adjust
the `_first_text(...)` selector lists in `scraper.py` if any field comes back
empty.

## Tests

Unit tests run against local HTML fixtures (`tests/fixtures/`) so the parser,
relation-finder, and email/report builder are verified without needing
network access:

```bash
pytest
```
