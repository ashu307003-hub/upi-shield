from email.message import EmailMessage
from smtplib import SMTP

from ..config import get_settings


def send_report(recipient: str, subject: str, body: str) -> None:
    settings = get_settings()
    message = EmailMessage()
    message["From"] = settings.report_from_email
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)
    with SMTP(settings.smtp_host, settings.smtp_port) as client:
        if settings.smtp_username:
            client.login(settings.smtp_username, settings.smtp_password)
        client.send_message(message)
