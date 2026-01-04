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
    
    CRITICAL INFRASTRUCTURE FIXES:
    1. IPv4 Forcing: Manually resolves DNS to IPv4 to prevent Render/Brevo IPv6 timeouts.
    2. SSL Hostname Patch: Manually overrides the connection hostname so SSL certificates 
       verify against the domain (e.g., brevo.com) instead of the resolved IP address.
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
    
    # Add Reply-To Header if provided (for contact forms)
    if reply_to:
        msg.add_header('Reply-To', reply_to)

    msg.attach(MIMEText(html_body, "html"))

    context = ssl.create_default_context()

    try:
        # ------------------------------------------------------------------
        # STEP 1: FORCE IPv4 RESOLUTION
        # Fixes "Network Unreachable" errors on Render/IPv6 environments
        # ------------------------------------------------------------------
        try:
            addr_info = socket.getaddrinfo(smtp_host, smtp_port, socket.AF_INET, socket.SOCK_STREAM)
            family, socktype, proto, canonname, sockaddr = addr_info[0]
            target_ip = sockaddr[0]
        except socket.gaierror:
            # Fallback if DNS resolution fails
            target_ip = smtp_host

        logger.info(f"Connecting to {smtp_host} via IP: {target_ip} (Port: {smtp_port})")

        # ------------------------------------------------------------------
        # STEP 2: CONNECT & SEND
        # Includes fixes for SSL Certificate Verification failures
        # ------------------------------------------------------------------
        
        # CASE A: Port 465 (SSL/TLS Implicit)
        if smtp_port == 465:
            # We must pass `server_hostname` so the SSL socket verifies the domain, not the IP.
            with smtplib.SMTP_SSL(target_ip, smtp_port, context=context, timeout=30, server_hostname=smtp_host) as server:
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)

        # CASE B: Port 587 (STARTTLS) - Used by Brevo/Gmail
        else:
            with smtplib.SMTP(target_ip, smtp_port, timeout=30) as server:
                server.ehlo()
                
                # --- CRITICAL FIX FOR CERTIFICATE ERROR ---
                # Because we connected to an IP (`target_ip`), starttls() tries to verify 
                # the certificate against that IP, which fails.
                # We overwrite `_host` to tell it: "Pretend we connected to brevo.com"
                server._host = smtp_host
                
                server.starttls(context=context)
                server.ehlo()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
                
        logger.info(f"Email sent successfully to {to}")

    except Exception as e:
        logger.exception(f"Failed to send email: {e}")
        raise
