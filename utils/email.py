import os
import smtplib
import ssl
import logging
import socket
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)

def send_email(to: str, subject: str, html_body: str):
    smtp_host = os.environ["SMTP_HOST"]
    smtp_port = int(os.environ["SMTP_PORT"])
    smtp_user = os.environ["SMTP_USERNAME"]
    smtp_pass = os.environ["SMTP_PASSWORD"]
    from_email = os.environ.get("SMTP_SENDER_EMAIL", smtp_user)

    msg = MIMEMultipart()
    msg["From"] = from_email
    msg["To"] = to
    msg["Subject"] = subject
    msg.attach(MIMEText(html_body, "html"))

    # Create a secure SSL context
    context = ssl.create_default_context()

    try:
        # --- THE FIX: FORCE IPv4 ---
        # We ask DNS ONLY for the IPv4 address (AF_INET) to avoid Render's IPv6 routing issues
        try:
            addr_info = socket.getaddrinfo(smtp_host, smtp_port, socket.AF_INET, socket.SOCK_STREAM)
            # Get the IP address from the first result
            family, socktype, proto, canonname, sockaddr = addr_info[0]
            target_ip = sockaddr[0]  # This is the IPv4 IP (e.g., 142.250.x.x)
        except socket.gaierror:
            # Fallback: If DNS fails, try using the hostname directly (risky but better than crashing)
            target_ip = smtp_host

        # --- SENDING LOGIC ---
        # Note: We connect to 'target_ip' but we MUST keep 'smtp_host' for the logs/logic
        
        if smtp_port == 465:
            # SSL Connection (Legacy)
            with smtplib.SMTP_SSL(target_ip, smtp_port, context=context, timeout=30) as server:
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
        else:
            # TLS Connection (Standard - Port 587)
            # We connect to the IP, but we might need to be careful with certificate validation.
            with smtplib.SMTP(target_ip, smtp_port, timeout=30) as server:
                server.ehlo()
                server.starttls(context=context) # Secure the connection
                server.ehlo()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
                
        logger.info(f"Email sent successfully to {to}")

    except Exception as e:
        logger.exception(f"Failed to send email: {e}")
        raise # Re-raise so the user sees the error on the webpage
