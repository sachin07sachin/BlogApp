import os
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps
from threading import Thread

# Third-Party Imports
import click
from dotenv import load_dotenv
from flask import (
    Flask, abort, render_template, redirect,
    url_for, flash, request, session
)
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_ckeditor.utils import cleanify
from flask_gravatar import Gravatar
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded
from flask_login import (
    UserMixin, login_user, LoginManager,
    current_user, logout_user, login_required
)
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from sqlalchemy import Integer, String, Text, Boolean, DateTime, text
from sqlalchemy.orm import DeclarativeBase, relationship, Mapped, mapped_column
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash

# Local Imports
from forms import (
    CreatePostForm, RegisterForm, LoginForm,
    CommentForm, ResendVerificationForm, ContactForm, 
    RequestResetForm, ResetPasswordForm
)
from utils.email import send_email 
from utils.captcha import verify_hcaptcha

# -------------------------------------------------------------------
# 1. CONFIGURATION & ENVIRONMENT SETUP
# -------------------------------------------------------------------

# Load environment variables
load_dotenv()

# VALIDATION: Ensure critical environment variables are set
REQUIRED_ENV_VARS = [
    "SECRET_KEY", "DATABASE_URL", "EMAIL_SECRET_KEY", 
    "SMTP_HOST", "SMTP_PORT", "SMTP_USERNAME", "SMTP_PASSWORD"
]
missing_vars = [var for var in REQUIRED_ENV_VARS if not os.environ.get(var)]
if missing_vars:
    raise RuntimeError(f"Missing required environment variables: {', '.join(missing_vars)}")

# Initialize Flask App
app = Flask(__name__)

# Security: CSRF Protection
csrf = CSRFProtect(app)

# Security: Proxy Fix (Required for Render/Heroku/Nginx)
if os.environ.get("ENV") == "production":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# Application Configuration
app.config.update(
    SECRET_KEY=os.environ["SECRET_KEY"],
    
    # Session Security
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(os.environ.get("ENV") == "production"),
    
    # Email Tokens
    EMAIL_SECRET_KEY=os.environ["EMAIL_SECRET_KEY"],
    EMAIL_TOKEN_SALT=os.environ.get("EMAIL_TOKEN_SALT", "email-confirm-salt"),
    EMAIL_TOKEN_EXPIRES=int(os.environ.get("EMAIL_TOKEN_EXPIRES", 3600)),
    
    # Password Reset
    PASSWORD_RESET_SALT=os.environ.get("PASSWORD_RESET_SALT", "password-reset-salt"),
    PASSWORD_RESET_EXPIRES=int(os.environ.get("PASSWORD_RESET_EXPIRES", 1800)), # 30 mins
    
    # CAPTCHA Config
    CAPTCHA_ENABLED=(os.environ.get("ENABLE_CAPTCHA", "false").lower() == "true"),
    HCAPTCHA_SITE_KEY=os.environ.get("HCAPTCHA_SITE_KEY"),
    HCAPTCHA_SECRET_KEY=os.environ.get("HCAPTCHA_SECRET_KEY"),
    
    # Database Config
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

# Database URI Fix (Postgres/Render compatibility)
uri = os.environ["DATABASE_URL"]
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = uri

# Initialize Extensions
ckeditor = CKEditor(app)
bootstrap = Bootstrap5(app)

# -------------------------------------------------------------------
# 2. LOGGING & EXTENSIONS SETUP
# -------------------------------------------------------------------

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
if os.environ.get("ENV") == "production":
    logging.getLogger().setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

# Initialize Database
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(
    model_class=Base,
    engine_options={
        "pool_pre_ping": True,
        "pool_recycle": 180,
        "pool_size": 5,
        "max_overflow": 10,
    }
)
db.init_app(app)

# Initialize Migration Engine
migrate = Migrate(app, db)

# Initialize Login Manager
login_manager = LoginManager()
login_manager.login_view = "login_get"
login_manager.login_message = "Please log in to access this page."
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# -------------------------------------------------------------------
# 3. DATABASE MODELS
# -------------------------------------------------------------------

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    password: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="user", server_default="user")
    
    # Verification & Security Fields
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    verification_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reset_password_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")

    # Relationships
    posts = relationship("BlogPost", back_populates="author", passive_deletes=True)
    comments = relationship("Comment", back_populates="comment_author", passive_deletes=True)


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id", ondelete="CASCADE"))
    author = relationship("User", back_populates="posts")
    
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    
    comments = relationship("Comment", back_populates="parent_post", passive_deletes=True)


class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id", ondelete="CASCADE"))
    comment_author = relationship("User", back_populates="comments")
    
    post_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("blog_posts.id", ondelete="CASCADE"))
    parent_post = relationship("BlogPost", back_populates="comments")

# -------------------------------------------------------------------
# 4. CORE DECORATORS & CLI
# -------------------------------------------------------------------

gravatar = Gravatar(app, size=100, rating="g", default="retro", use_ssl=True)

def admin_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        if current_user.role != "admin":
            abort(403)
        return f(*args, **kwargs)
    return wrapper

@app.cli.command("create-admin")
@click.argument("email")
def create_admin(email):
    """Promotes a user to admin role."""
    user = db.session.scalar(db.select(User).where(User.email == email))
    if user:
        user.role = "admin"
        db.session.commit()
        print(f"User {email} is now an ADMIN.")
    else:
        print(f"User {email} not found.")

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

# -------------------------------------------------------------------
# 5. RATE LIMITING & SECURITY HELPERS
# -------------------------------------------------------------------

# Initialize Rate Limiter
redis_url = os.environ.get("REDIS_URL")
if not redis_url:
    raise RuntimeError("REDIS_URL environment variable not set")

def login_rate_limit_key():
    """Rate limit key: IP + Email (Prevents brute force on specific user)"""
    ip = get_remote_address()
    email = request.form.get("email", "unknown").lower().strip()
    return f"{ip}:{email}"

def email_rate_limit_key():
    """Rate limit key: IP + Email (For verification/reset flows)"""
    ip = get_remote_address()
    email = request.form.get("email", "unknown").lower().strip()
    return f"{ip}:{email}"

# --- FIX: LOOP OF DEATH (Rate Limit Bypass) ---
def match_captcha_bypass():
    """
    Tells Flask-Limiter to SKIP the rate limit check if the user
    has submitted a Captcha response in the form.
    This prevents the user from being blocked immediately after solving the CAPTCHA.
    """
    return request.form.get("h-captcha-response") is not None

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=redis_url,
    default_limits=[], 
    strategy="sliding-window-counter"
)

# Constants
RATE_LIMIT_LOGIN_GLOBAL = "60 per hour"
RATE_LIMIT_LOGIN_SPECIFIC = "10 per minute"
RATE_LIMIT_EMAIL_GLOBAL = "20 per hour"
RATE_LIMIT_EMAIL_SPECIFIC = "5 per hour"
MAX_LOGIN_ATTEMPTS = 5
DUMMY_PASSWORD_HASH = generate_password_hash("dummy_password_for_timing_protection")

# -------------------------------------------------------------------
# 6. TOKEN & SECURITY UTILITIES
# -------------------------------------------------------------------

def _get_serializer():
    return URLSafeTimedSerializer(app.config["EMAIL_SECRET_KEY"])

# --- FIX: TIMESTAMP PRECISION ---
# We now accept the datetime object directly to ensure it matches the DB.
def generate_email_token(user_id: int, timestamp: datetime) -> str:
    """
    Generates verification token using a specific datetime object.
    Converts to integer timestamp (IAT) for the token payload.
    """
    return _get_serializer().dumps(
        {
            "user_id": str(user_id),
            "iat": int(timestamp.timestamp())
        },
        salt=app.config["EMAIL_TOKEN_SALT"]
    )

def confirm_email_token(token: str):
    try:
        return _get_serializer().loads(
            token,
            salt=app.config["EMAIL_TOKEN_SALT"],
            max_age=app.config["EMAIL_TOKEN_EXPIRES"]
        )
    except (SignatureExpired, BadSignature):
        return None

def generate_password_reset_token(user_id: int, timestamp: datetime) -> str:
    """
    Generates reset token using a specific datetime object.
    """
    return _get_serializer().dumps(
        {
            "user_id": str(user_id),
            "iat": int(timestamp.timestamp())
        },
        salt=app.config["PASSWORD_RESET_SALT"]
    )

def confirm_password_reset_token(token: str):
    try:
        return _get_serializer().loads(
            token,
            salt=app.config["PASSWORD_RESET_SALT"],
            max_age=app.config["PASSWORD_RESET_EXPIRES"]
        )
    except (SignatureExpired, BadSignature):
        return None

# -------------------------------------------------------------------
# 7. GLOBAL ERROR HANDLERS
# -------------------------------------------------------------------

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("Your session expired. Please try again.", "warning")
    return redirect(request.referrer or url_for("login_get"))

@app.errorhandler(RateLimitExceeded)
def handle_rate_limit(e):
    """
    Escalates to CAPTCHA instead of blocking entirely.
    Renders the specific template so the user can actually SOLVE the CAPTCHA.
    """
    if app.config["CAPTCHA_ENABLED"]:
        session["captcha_required"] = True

    logger.warning(
        f"Rate limit exceeded ({e.description}) "
        f"IP={get_remote_address()} "
        f"email={request.form.get('email', 'unknown')}"
    )
    
    flash("Too many requests detected. Please verify you are human.", "danger")

    # Determine context to render correct template
    endpoint = request.endpoint
    
    if endpoint == "login_post":
        return render_template(
            "login.html", 
            login_form=LoginForm(), 
            captcha_required=True,
            hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"]
        ), 429

    elif endpoint == "resend_verification_post":
        return render_template(
            "resend_verification.html", 
            resend_form=ResendVerificationForm(),
            captcha_required=True,
            hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"]
        ), 429

    elif endpoint == "request_reset_post":
        return render_template(
            "request_reset.html", 
            form=RequestResetForm(),
            captcha_required=True,
            hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"]
        ), 429

    return redirect(url_for("login_get"))

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin"
    response.headers["Permissions-Policy"] = "geolocation=()"
    return response

@app.route("/health")
def health():
    return "OK", 200


# -------------------------------------------------------------------
# 8. AUTHENTICATION ROUTES
# -------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    # FIX: Single Source of Truth (Microseconds stripped)
    now = datetime.now(timezone.utc).replace(microsecond=0)

    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        
        # Check if user exists
        existing_user = db.session.scalar(db.select(User).where(User.email == email))

        # flash the same success message for everyone.
        flash(
            "Registration successful! Please check your email to verify your account.",
            "success"
        )

        # CASE 1: User Already Exists
        if existing_user:
            login_url = url_for("login_get", _external=True)
            reset_url = url_for("request_reset_get", _external=True)
            
            # Send "Already Registered" email
            html_body = render_template(
                "email/already_registered.html", 
                name=existing_user.name,
                login_url=login_url,
                reset_url=reset_url
            )
            
            # THREADING: Send in background
            Thread(
                target=send_email,
                args=(existing_user.email, "You already have an account", html_body)
            ).start()

        # CASE 2: New User
        else:
            new_user = User(
                email=email,
                password=generate_password_hash(
                    form.password.data,
                    method="pbkdf2:sha256",
                    salt_length=16
                ),
                name=form.name.data,
                verification_sent_at=now # <--- Uses the clean 'now'
            )

            db.session.add(new_user)
            db.session.commit()

            # Send "Verify Email" link
            # FIX: Pass 'now' to generate_email_token
            token = generate_email_token(new_user.id, now)
            
            verify_url = url_for(
                "verify_email",
                token=token,
                _external=True
            )

            # THREADING: Send in background
            Thread(
                target=send_email,
                args=(
                    new_user.email,
                    "Verify your email",
                    render_template(
                        "email/verify.html",
                        verify_url=verify_url,
                        user=new_user
                    )
                )
            ).start()

        return redirect(url_for("resend_verification_get"))

    return render_template("register.html", form=form)


@app.route("/verify-email/<token>")
def verify_email(token):
    data = confirm_email_token(token)
    if not data:
        flash("Invalid or expired verification link.", "danger")
        return redirect(url_for("resend_verification_get"))

    user = db.session.get(User, int(data["user_id"]))
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("register"))

    token_issued_at = datetime.fromtimestamp(
        data["iat"], tz=timezone.utc
    )

    # Invalidate older verification links
    # FIX: Clean comparison (no subtraction needed because we stripped microseconds)
    if (
        user.verification_sent_at
        and token_issued_at < user.verification_sent_at
    ):
        flash(
            "This verification link has been replaced by a newer one.",
            "danger"
        )
        return redirect(url_for("resend_verification_get"))

    if user.email_verified:
        flash("Email already verified. Please log in.", "info")
        return redirect(url_for("login_get"))

    user.email_verified = True
    db.session.commit()

    # Clear any previous CAPTCHA trust
    session.pop("captcha_required", None)

    flash("Email verified successfully! Please log in.", "success")
    return redirect(url_for("login_get"))


# -------------------------------------------------------------------
# RESEND VERIFICATION
# -------------------------------------------------------------------

@app.route("/resend-verification", methods=["GET"])
def resend_verification_get():
    resend_form = ResendVerificationForm()

    return render_template(
        "resend_verification.html",
        resend_form=resend_form,
        captcha_required=(
            app.config["CAPTCHA_ENABLED"] and session.get("captcha_required")
        ),
        hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"],
    )

@app.route("/resend-verification", methods=["POST"])
@limiter.limit(RATE_LIMIT_EMAIL_GLOBAL, key_func=get_remote_address, exempt_when=match_captcha_bypass) # FIX: Added exempt
@limiter.limit(RATE_LIMIT_EMAIL_SPECIFIC, key_func=email_rate_limit_key, exempt_when=match_captcha_bypass) # FIX: Added exempt
def resend_verification_post():
    resend_form = ResendVerificationForm()
    # FIX: Single Source of Truth
    now = datetime.now(timezone.utc).replace(microsecond=0)

    # HELPER: Re-render to preserve input on failure
    def render_failure():
        return render_template(
            "resend_verification.html",
            resend_form=resend_form,
            captcha_required=(
                app.config["CAPTCHA_ENABLED"] and session.get("captcha_required")
            ),
            hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"],
        )

    # Form Validation
    if not resend_form.validate_on_submit():
        return render_failure()

    # CAPTCHA Check
    if (
        app.config["CAPTCHA_ENABLED"]
        and session.get("captcha_required")
    ):
        token = request.form.get("h-captcha-response")
        if not verify_hcaptcha(token, get_remote_address()):
            flash("CAPTCHA verification failed. Please try again.", "danger")
            return render_failure()

        session.pop("captcha_required", None)

    email = resend_form.email.data.lower().strip()
    user = db.session.scalar(
        db.select(User).where(User.email == email)
    )

    # flash the SAME message for everyone.
    flash(
        "If an account exists with this email, a verification link has been sent.",
        "info"
    )

    # If user exists (verified OR unverified), send the link.
    if user:
        # FIX: Pass 'now'
        token = generate_email_token(user.id, now)
        
        verify_url = url_for(
            "verify_email",
            token=token,
            _external=True
        )

        # THREADING: Send in background (Prevents Timing Attack)
        Thread(
            target=send_email,
            args=(
                user.email,
                "Verify your email",
                render_template(
                    "email/verify.html",
                    verify_url=verify_url,
                    user=user
                )
            )
        ).start()

        # Update timestamp
        user.verification_sent_at = now
        db.session.commit()

    # Clear CAPTCHA escalation after successful flow
    session.pop("captcha_required", None)

    return redirect(url_for("resend_verification_get"))


# -------------------------------------------------------------------
# PASSWORD RESET FLOW
# -------------------------------------------------------------------

@app.route("/request-reset", methods=["GET"])
def request_reset_get():
    form = RequestResetForm()

    return render_template(
        "request_reset.html",
        form=form,
        captcha_required=(
            app.config["CAPTCHA_ENABLED"] and session.get("captcha_required")
        ),
        hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"],
    )

@app.route("/request-reset", methods=["POST"])
@limiter.limit(RATE_LIMIT_EMAIL_GLOBAL, key_func=get_remote_address, exempt_when=match_captcha_bypass) # FIX: Added exempt
@limiter.limit(RATE_LIMIT_EMAIL_SPECIFIC, key_func=email_rate_limit_key, exempt_when=match_captcha_bypass) # FIX: Added exempt
def request_reset_post():
    form = RequestResetForm()
    # FIX: Single Source of Truth
    now = datetime.now(timezone.utc).replace(microsecond=0)

    # HELPER: Re-render to preserve input on failure
    def render_failure():
        return render_template(
            "request_reset.html",
            form=form,
            captcha_required=(
                app.config["CAPTCHA_ENABLED"] and session.get("captcha_required")
            ),
            hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"],
        )

    # Form Validation
    if not form.validate_on_submit():
        return render_failure()

    # CAPTCHA Check
    if (
        app.config["CAPTCHA_ENABLED"]
        and session.get("captcha_required")
    ):
        token = request.form.get("h-captcha-response")
        if not verify_hcaptcha(token, get_remote_address()):
            flash("CAPTCHA verification failed. Please try again.", "danger")
            return render_failure()

        session.pop("captcha_required", None)

    email = form.email.data.lower().strip()
    user = db.session.scalar(
        db.select(User).where(User.email == email)
    )

    # GENERIC RESPONSE (Prevents Enumeration)
    flash(
        "If an account exists, a password reset link has been sent.",
        "info"
    )

    if user:
        # FIX: Pass 'now'
        token = generate_password_reset_token(user.id, now)
        
        reset_url = url_for(
            "reset_password",
            token=token,
            _external=True
        )

        subject = "Reset your password"
        html_body = render_template(
            "email/reset_password.html",
            reset_url=reset_url,
            user=user
        )

        # THREADING: Send in background
        Thread(
            target=send_email, 
            args=(user.email, subject, html_body)
        ).start()

        user.reset_password_sent_at = now
        db.session.commit()

    # Clear CAPTCHA escalation after successful flow
    session.pop("captcha_required", None)

    return redirect(url_for("request_reset_get"))


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    data = confirm_password_reset_token(token)
    if not data:
        flash("Invalid or expired reset link.", "danger")
        return redirect(url_for("request_reset_get"))

    user = db.session.get(User, int(data["user_id"]))
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("request_reset_get"))

    token_issued_at = datetime.fromtimestamp(
        data["iat"], tz=timezone.utc
    )

    # Invalidate older reset links immediately
    # FIX: Clean comparison
    if (
        user.reset_password_sent_at
        and token_issued_at < user.reset_password_sent_at
    ):
        flash(
            "This reset link has been replaced by a newer one.",
            "danger"
        )
        return redirect(url_for("request_reset_get"))

    form = ResetPasswordForm()

    # Inject email for validator
    form.email.data = user.email

    if form.validate_on_submit():
        user.password = generate_password_hash(
            form.password.data,
            method="pbkdf2:sha256",
            salt_length=16
        )

        # Invalidate reset intent
        user.reset_password_sent_at = None
        db.session.commit()

        # Logout all sessions
        logout_user()
        session.clear()

        flash(
            "Password reset successful. Please log in again.",
            "success"
        )
        return redirect(url_for("login_get"))

    return render_template("reset_password.html", form=form)


# -------------------------------------------------------------------
# LOGIN ROUTES
# -------------------------------------------------------------------

@app.route("/login", methods=["GET"])
def login_get():
    form = LoginForm()

    return render_template(
        "login.html",
        login_form=form,
        captcha_required=(
            app.config["CAPTCHA_ENABLED"] and session.get("captcha_required")
        ),
        hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"],
    )

@app.route("/login", methods=["POST"])
# Layer 1: Global IP Protection
@limiter.limit(RATE_LIMIT_LOGIN_GLOBAL, key_func=get_remote_address, exempt_when=match_captcha_bypass) # FIX: Added exempt
# Layer 2: Specific Account Protection
@limiter.limit(RATE_LIMIT_LOGIN_SPECIFIC, key_func=login_rate_limit_key, exempt_when=match_captcha_bypass) # FIX: Added exempt
def login_post():
    form = LoginForm()
    
    # HELPER: This function re-renders the page with the user's data + errors.
    def render_login_failure():
        return render_template(
            "login.html",
            login_form=form, # Pass the 'dirty' form back so email stays filled
            captcha_required=(
                app.config["CAPTCHA_ENABLED"] and session.get("captcha_required")
            ),
            hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"],
        )

    # Form Validation Check
    if not form.validate_on_submit():
        return render_login_failure()

    # CAPTCHA CHECK
    if (
        app.config["CAPTCHA_ENABLED"]
        and session.get("captcha_required")
    ):
        token = request.form.get("h-captcha-response")
        if not verify_hcaptcha(token, get_remote_address()):
            flash("CAPTCHA verification failed. Please try again.", "danger")
            return render_login_failure()

        # CAPTCHA passed successfully -> Remove requirement
        session.pop("captcha_required", None)

    email = form.email.data.lower().strip()
    password = form.password.data

    user = db.session.scalar(
        db.select(User).where(User.email == email)
    )

    # Credential Validation (Timing-safe)
    valid_password = False
    if user:
        valid_password = check_password_hash(user.password, password)
    else:
        # Timing attack protection
        check_password_hash(DUMMY_PASSWORD_HASH, password)

    # Handle Failure
    if not user or not valid_password:
        if user:
            user.failed_login_count += 1
            logger.info(
                f"Failed login for {email}. Count: {user.failed_login_count}"
            )

            # Escalate to CAPTCHA after max attempts
            if user.failed_login_count >= MAX_LOGIN_ATTEMPTS:
                user.failed_login_count = 0
                session["captcha_required"] = True
                
                logger.warning(
                    f"CAPTCHA escalation triggered for {email}"
                )

            db.session.commit()

        flash("Invalid email or password.", "danger")
        return render_login_failure()

    # Handle Success
    user.failed_login_count = 0
    db.session.commit()

    # Clear CAPTCHA state on success
    session.pop("captcha_required", None)

    if not user.email_verified:
        logger.info(f"Unverified login attempt: {email}")
        flash("Please verify your email before logging in.", "warning")
        return redirect(url_for("resend_verification_get"))

    logger.info(f"Successful login: {email}")
    login_user(user, fresh=True)

    return redirect(url_for("get_all_posts"))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("captcha_required", None)
    return redirect(url_for("get_all_posts"))

# -------------------------------------------------------------------
# 9. BLOG ROUTES
# -------------------------------------------------------------------

@app.route("/")
def get_all_posts():
    posts = db.session.scalars(db.select(BlogPost).order_by(BlogPost.date.desc())).all()
    return render_template("index.html", all_posts=posts)

@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()

    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login to comment.", "warning")
            return redirect(url_for("login_get"))
        
        if not current_user.email_verified:
            flash("Please verify your email first.", "warning")
            return redirect(url_for("resend_verification_get"))

        comment = Comment(
            text=cleanify(form.comment_text.data),
            comment_author=current_user,
            parent_post=post
        )
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("post.html", post=post, form=form)

@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=cleanify(form.body.data),
            img_url=form.img_url.data,
            author=current_user,
        )
        db.session.add(post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)

@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    form = CreatePostForm(obj=post)
    if form.validate_on_submit():
        form.populate_obj(post)
        post.body = cleanify(form.body.data)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=form, is_edit=True)

@app.route("/delete/<int:post_id>", methods=["POST", "GET"])
@admin_only
def delete_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for("get_all_posts"))

# -------------------------------------------------------------------
# 10. STATIC PAGES & CONTACT
# -------------------------------------------------------------------

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact", methods=["GET", "POST"])
def contact():
    form = ContactForm()
    
    if form.validate_on_submit():
        try:
            html_body = render_template(
                "email/contact_message.html",
                name=form.name.data,
                email=form.email.data,
                phone=form.phone.data,
                message=form.message.data
            )
            
            # Use environment variable for receiver
            send_email(
                to=os.environ["CONTACT_RECEIVER_EMAIL"],
                subject="New Contact Form Message",
                html_body=html_body,
                reply_to=form.email.data 
            )

            flash("Your message has been sent successfully!", "success")
            return redirect(url_for('contact'))

        except Exception:
            logger.exception("Contact email failed")
            flash("Failed to send message. Please try again later.", "danger")
    
    return render_template("contact.html", form=form)


# -------------------------------------------------------------------
# ENTRY POINT
# -------------------------------------------------------------------

if __name__ == "__main__":
    app.run(
        debug=os.environ.get("ENV") != "production",
        port=int(os.environ.get("PORT", 5002))
    )
