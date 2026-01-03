import os
import smtplib
import ssl
import logging
import socket
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)

def send_email(to: str, subject: str, html_body: str, reply_to: str = None):
    """
    Sends an email using the configured SMTP server.
    Supports 'reply_to' for contact forms.
    Forces IPv4 to avoid Render/Gmail network unreachable errors.
    """
    smtp_host = os.environ["SMTP_HOST"]
    smtp_port = int(os.environ["SMTP_PORT"])
    smtp_user = os.environ["SMTP_USERNAME"]
    smtp_pass = os.environ["SMTP_PASSWORD"]
    from_email = os.environ.get("SMTP_SENDER_EMAIL", smtp_user)

    msg = MIMEMultipart()
    msg["From"] = from_email
    msg["To"] = to
    msg["Subject"] = subject
    
    # --- LOGIC: Add Reply-To Header if provided ---
    if reply_to:
        msg.add_header('Reply-To', reply_to)

    msg.attach(MIMEText(html_body, "html"))

    context = ssl.create_default_context()

    try:
        # --- LOGIC: Force IPv4 Resolution ---
        try:
            addr_info = socket.getaddrinfo(smtp_host, smtp_port, socket.AF_INET, socket.SOCK_STREAM)
            family, socktype, proto, canonname, sockaddr = addr_info[0]
            target_ip = sockaddr[0]
        except socket.gaierror:
            target_ip = smtp_host

        # --- LOGIC: Connection ---
        if smtp_port == 465:
            with smtplib.SMTP_SSL(target_ip, smtp_port, context=context, timeout=30) as server:
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
        else:
            with smtplib.SMTP(target_ip, smtp_port, timeout=30) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
                
        logger.info(f"Email sent successfully to {to}")

    except Exception as e:
        logger.exception(f"Failed to send email: {e}")
        raise
