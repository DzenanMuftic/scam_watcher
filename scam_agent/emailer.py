"""Sends the report email via SMTP."""

import smtplib
from email.mime.text import MIMEText

from .config import SmtpConfig


def send_email(smtp_config: SmtpConfig, to_addr: str, subject: str, body: str) -> None:
    if not smtp_config.username or not smtp_config.password:
        raise RuntimeError(
            "SMTP credentials are not configured. Set SMTP_USERNAME and SMTP_PASSWORD "
            "(and EMAIL_FROM if different) as environment variables."
        )

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = smtp_config.sender
    msg["To"] = to_addr

    with smtplib.SMTP(smtp_config.host, smtp_config.port, timeout=30) as server:
        if smtp_config.use_tls:
            server.starttls()
        server.login(smtp_config.username, smtp_config.password)
        server.sendmail(smtp_config.sender, [to_addr], msg.as_string())
