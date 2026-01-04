import os
import smtplib
import ssl
import logging
import socket
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# HELPER CLASS: Fixes the IP vs Hostname Conflict
# ------------------------------------------------------------------
class PatchedSMTP_SSL(smtplib.SMTP_SSL):
    """
    This custom class solves the Render/Brevo conflict.
    It allows us to TCP connect to a specific IP (IPv4) but force 
    SSL to verify the certificate against the original Domain Name.
    """
    def __init__(self, target_ip, port, context, real_hostname):
        self.real_hostname = real_hostname
        # Initialize the parent SMTP_SSL class with the IP address
        super().__init__(target_ip, port, context=context, timeout=30)

    def _get_socket(self, host, port, timeout):
        # 1. Create the TCP connection to the IP Address (`host` is the IP here)
        sock = socket.create_connection((host, port), timeout, self.source_address)
        
        # 2. Wrap the socket in SSL, but use `real_hostname` for SNI/Verification
        return self.context.wrap_socket(sock, server_hostname=self.real_hostname)

# ------------------------------------------------------------------

def send_email(to: str, subject: str, html_body: str, reply_to: str = None):
    smtp_host = os.environ["SMTP_HOST"]
    smtp_port = int(os.environ["SMTP_PORT"])
    smtp_user = os.environ["SMTP_USERNAME"]
    smtp_pass = os.environ["SMTP_PASSWORD"]
    from_email = os.environ.get("SMTP_SENDER_EMAIL", smtp_user)

    msg = MIMEMultipart()
    msg["From"] = from_email
    msg["To"] = to
    msg["Subject"] = subject
    
    if reply_to:
        msg.add_header('Reply-To', reply_to)

    msg.attach(MIMEText(html_body, "html"))

    context = ssl.create_default_context()

    try:
        # STEP 1: FORCE IPv4 RESOLUTION
        # Resolve the domain to an IP address manually to prevent IPv6 timeouts
        try:
            addr_info = socket.getaddrinfo(smtp_host, smtp_port, socket.AF_INET, socket.SOCK_STREAM)
            family, socktype, proto, canonname, sockaddr = addr_info[0]
            target_ip = sockaddr[0]
        except socket.gaierror:
            target_ip = smtp_host

        logger.info(f"Connecting to {smtp_host} via IP: {target_ip} on port {smtp_port}")

        # STEP 2: CONNECT AND SEND
        
        # CASE A: Port 465 (SSL/TLS Implicit) - Uses our Patched Class
        if smtp_port == 465:
            # We use our custom class to handle the IP/Hostname split cleanly
            with PatchedSMTP_SSL(target_ip, smtp_port, context=context, real_hostname=smtp_host) as server:
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)

        # CASE B: Port 587 (STARTTLS)
        else:
            with smtplib.SMTP(target_ip, smtp_port, timeout=30) as server:
                server.ehlo()
                # Manual fix for Port 587
                server._host = smtp_host 
                server.starttls(context=context)
                server.ehlo()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
                
        logger.info(f"Email sent successfully to {to}")

    except Exception as e:
        logger.exception(f"Failed to send email: {e}")
        raise
