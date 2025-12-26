import requests
from flask import current_app

def verify_hcaptcha(token: str, remote_ip: str | None = None) -> bool:
    """
    Server-side verification of hCaptcha.
    """
    if not token:
        return False

    payload = {
        "secret": current_app.config["HCAPTCHA_SECRET_KEY"],
        "response": token,
    }

    if remote_ip:
        payload["remoteip"] = remote_ip

    try:
        resp = requests.post(
            "https://hcaptcha.com/siteverify",
            data=payload,
            timeout=5,
        )
        data = resp.json()
        return data.get("success", False)
    except Exception:
        return False
