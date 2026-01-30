# app/services/email_service.py
import smtplib
from email.mime.text import MIMEText
from app.core.config import settings

def send_email(subject: str, recipient: str, html_body: str):
    msg = MIMEText(html_body, "html", "utf-8")
    msg["Subject"] = subject
    msg["From"] = settings.EMAIL_FROM
    msg["To"] = recipient

    s = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10)
    try:
        s.starttls()
        s.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        s.sendmail(settings.EMAIL_FROM, [recipient], msg.as_string())
    finally:
        s.quit()
__all__ = ["send_email"]