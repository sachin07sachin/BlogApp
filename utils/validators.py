import re
from wtforms.validators import ValidationError


def validate_strong_password(form, field):
    """
    Industry-grade password policy:

    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character
    - Cannot be the same as the user's email
    """

    password = field.data or ""

    # -----------------------------
    # Basic length check
    # -----------------------------
    if len(password) < 8 or len(password) > 128:
        raise ValidationError("Password must be between 8 and 128 characters.")

    # -----------------------------
    # Character class checks
    # -----------------------------
    if not re.search(r"[A-Z]", password):
        raise ValidationError(
            "Password must contain at least one uppercase letter."
        )

    if not re.search(r"[a-z]", password):
        raise ValidationError(
            "Password must contain at least one lowercase letter."
        )

    if not re.search(r"\d", password):
        raise ValidationError(
            "Password must contain at least one number."
        )

    if not re.search(r"[^a-zA-Z0-9]", password):
        raise ValidationError(
            "Password must contain at least one special character or symbol."
        )

    # -----------------------------
    # Email ≠ Password check
    # -----------------------------
    email_field = getattr(form, "email", None)
    if email_field and email_field.data:
        if password.lower() == email_field.data.lower():
            raise ValidationError(
                "Password cannot be the same as your email address."
            )
