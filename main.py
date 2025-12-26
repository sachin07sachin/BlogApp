import os
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps
from dotenv import load_dotenv
from flask import (
    Flask, abort, render_template, redirect,
    url_for, flash, request, session
)
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_ckeditor.utils import cleanify
from flask_gravatar import Gravatar
from flask_login import (
    UserMixin, login_user, LoginManager,
    current_user, logout_user, login_required
)
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, relationship, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, Boolean, DateTime, text
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded
import click

# Import your forms and email helper
from forms import (
    CreatePostForm, RegisterForm, LoginForm,
    CommentForm, ResendVerificationForm, ContactForm, RequestResetForm, ResetPasswordForm
)
from utils.email import send_email
from utils.captcha import verify_hcaptcha

# -------------------------------------------------------------------
# CONFIGURATION & CONSTANTS

# MAX_LOGIN_ATTEMPTS = 5
# LOGIN_LOCK_SECONDS = 60
# RESEND_COOLDOWN_SECONDS = 60  # Increased to 60s for better UX

load_dotenv()
if not os.environ.get("SECRET_KEY"):
    raise RuntimeError("SECRET_KEY not set")

if not os.environ.get("DATABASE_URL"):
    raise RuntimeError("DATABASE_URL not set")

app = Flask(__name__)

csrf = CSRFProtect(app)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("ENV") == "production"
)


# Production Proxy Fix (for Nginx/Heroku/Render)
if os.environ.get("ENV") == "production":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
app.config["EMAIL_TOKEN_SALT"] = os.environ.get("EMAIL_TOKEN_SALT", "email-confirm-salt")
app.config["EMAIL_TOKEN_EXPIRES"] = int(os.environ.get("EMAIL_TOKEN_EXPIRES", 3600))

# Password Reset Config
app.config["PASSWORD_RESET_SALT"] = os.environ.get(
    "PASSWORD_RESET_SALT", "password-reset-salt"
)
app.config["PASSWORD_RESET_EXPIRES"] = int(
    os.environ.get("PASSWORD_RESET_EXPIRES", 1800)  # 30 minutes
)

# -------------------------------------------------
# CAPTCHA GLOBAL SWITCH
# -------------------------------------------------
app.config["CAPTCHA_ENABLED"] = os.environ.get("ENV") == "production"

# -------------------------------------------------
# hCaptcha Configuration
# -------------------------------------------------
if app.config["CAPTCHA_ENABLED"]:
    app.config["HCAPTCHA_SITE_KEY"] = os.environ["HCAPTCHA_SITE_KEY"]
    app.config["HCAPTCHA_SECRET_KEY"] = os.environ["HCAPTCHA_SECRET_KEY"]
else:
    app.config["HCAPTCHA_SITE_KEY"] = None
    app.config["HCAPTCHA_SECRET_KEY"] = None

# Database Config (Fix for Postgres on some platforms)
uri = os.environ.get("DATABASE_URL")
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = uri
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize Extensions
ckeditor = CKEditor(app)
bootstrap = Bootstrap5(app)

# -------------------------------------------------------------------
# DATABASE SETUP

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

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

migrate = Migrate(app, db)

# -------------------------------------------------------------------
# LOGIN & RATE LIMITING

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."
login_manager.init_app(app)

# -------------------------------------------------------------------------
# 1. Configuration & Constants
# -------------------------------------------------------------------------
# Rate Limit Strings
RATE_LIMIT_LOGIN_GLOBAL = "60 per hour"     # IP only (stops mass scanning)
RATE_LIMIT_LOGIN_SPECIFIC = "10 per minute"  # IP + Email (stops brute force on specific user)

# Rate limits for email-based flows
RATE_LIMIT_EMAIL_GLOBAL = "20 per hour"      # Per IP
RATE_LIMIT_EMAIL_SPECIFIC = "5 per hour"     # Per IP + Email

# Account Lockout Settings
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCK_SECONDS = 60         # 1 minute lockout for specific account
RESEND_COOLDOWN_SECONDS = 60    # 1 minute wait for resending emails
RESET_COOLDOWN_SECONDS = 60


# Security: Timing Attack Protection
# (Requires: from werkzeug.security import generate_password_hash)
DUMMY_PASSWORD_HASH = generate_password_hash("dummy_password_for_timing_protection")

# -------------------------------------------------------------------------
# Logging Configuration
# -------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

if os.environ.get("ENV") == "production":
    logging.getLogger().setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

# -------------------------------------------------------------------------
# 2. Rate Limiting Setup
# -------------------------------------------------------------------------
def login_rate_limit_key():
    """
    Rate limit by IP + Email.
    Used for the 'Specific' limit to prevent hammering a single account.
    """
    ip = get_remote_address()
    # Safely get email, default to 'unknown' so a key is always generated
    email = request.form.get("email", "unknown").lower().strip()
    return f"{ip}:{email}"

def email_rate_limit_key():
    ip = get_remote_address()
    email = request.form.get("email", "unknown").lower().strip()
    return f"{ip}:{email}"

redis_url = os.environ.get("REDIS_URL")
if not redis_url:
    raise RuntimeError("REDIS_URL environment variable not set")

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri = redis_url if redis_url else "memory://",
    default_limits=[], # Explicitly empty to prevent global limits affecting static assets
    strategy="sliding-window-counter"
)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("Your session expired. Please try again.", "warning")
    return redirect(request.referrer or url_for("login"))


@app.errorhandler(RateLimitExceeded)
def handle_rate_limit(e):
    """
    Generic rate limit handler.
    Escalates to CAPTCHA instead of exposing timing.
    """

    if app.config["CAPTCHA_ENABLED"]:
        session["captcha_required"] = True

    logger.warning(
        f"Rate limit exceeded ({e.description}) "
        f"IP={get_remote_address()} "
        f"email={request.form.get('email', 'unknown')}"
    )

    flash(
        "Too many requests detected. Please verify you are human.",
        "danger"
    )

    endpoint = request.endpoint

    if endpoint == "login":
        form = LoginForm()
        template = "login.html"
        context = {"login_form": form}

    elif endpoint == "resend_verification":
        form = ResendVerificationForm()
        template = "resend_verification.html"
        context = {
            "resend_form": form,
            "remaining_seconds": 0,
        }

    elif endpoint == "request_reset":
        form = RequestResetForm()
        template = "request_reset.html"
        context = {
            "form": form,
            "remaining_seconds": 0,
        }

    else:
        return redirect(url_for("login"))

    if request.method == "POST":
        form.process(request.form)

    return render_template(
        template,
        captcha_required=(
            app.config["CAPTCHA_ENABLED"] and session.get("captcha_required")
        ),
        hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"],
        **context
    ), 429




@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin"
    response.headers["Permissions-Policy"] = "geolocation=()"
    return response

# -------------------------------------------------------------------
# MODELS

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    password: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="user", server_default="user")
    
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    verification_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reset_password_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    login_locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # 🟢 OPTIMIZED: passive_deletes=True tells SQLAlchemy to let the DB handle it
    posts = relationship("BlogPost", back_populates="author", passive_deletes=True)
    comments = relationship("Comment", back_populates="comment_author", passive_deletes=True)


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    
    # 🔴 CORE LOGIC: ondelete="CASCADE" ensures DB wipes posts when User is deleted
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id", ondelete="CASCADE"))
    author = relationship("User", back_populates="posts")
    
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    # date: Mapped[str] = mapped_column(String(50), nullable=False)
    date: Mapped[datetime] = mapped_column(
    DateTime(timezone=True),
    default=lambda: datetime.now(timezone.utc)
    )
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    
    # 🟢 OPTIMIZED: Let DB handle comment deletion
    comments = relationship("Comment", back_populates="parent_post", passive_deletes=True)


class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    
    # 🔴 CORE LOGIC: If User is deleted, delete their comments
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id", ondelete="CASCADE"))
    comment_author = relationship("User", back_populates="comments")
    
    # 🔴 CORE LOGIC: If Post is deleted, delete its comments
    post_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("blog_posts.id", ondelete="CASCADE"))
    parent_post = relationship("BlogPost", back_populates="comments")

# -------------------------------------------------------------------
# HELPERS & DECORATORS

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


if not os.environ.get("EMAIL_SECRET_KEY"):
    raise RuntimeError("EMAIL_SECRET_KEY not set")

app.config["EMAIL_SECRET_KEY"] = os.environ["EMAIL_SECRET_KEY"]

def _get_serializer():
    return URLSafeTimedSerializer(app.config["EMAIL_SECRET_KEY"])

def generate_email_token(user_id: int) -> str:
    """
    Generates an email verification token.
    Includes issued-at (iat) to invalidate older tokens.
    """
    return _get_serializer().dumps(
        {
            "user_id": str(user_id),
            "iat": int(datetime.now(timezone.utc).timestamp())
        },
        salt=app.config["EMAIL_TOKEN_SALT"]
    )


def confirm_email_token(token: str):
    """
    Confirms email verification token.
    Verifies signature, expiry, and returns payload.
    """
    try:
        return _get_serializer().loads(
            token,
            salt=app.config["EMAIL_TOKEN_SALT"],
            max_age=app.config["EMAIL_TOKEN_EXPIRES"]
        )
    except (SignatureExpired, BadSignature):
        return None
    
def generate_password_reset_token(user_id: int) -> str:
    """
    Generates a password reset token.
    Includes issued-at (iat) to invalidate older tokens.
    """
    return _get_serializer().dumps(
        {
            "user_id": str(user_id),
            "iat": int(datetime.now(timezone.utc).timestamp())
        },
        salt=app.config["PASSWORD_RESET_SALT"]
    )


def confirm_password_reset_token(token: str):
    """
    Confirms password reset token.
    Verifies signature, expiry, and returns payload.
    """
    try:
        return _get_serializer().loads(
            token,
            salt=app.config["PASSWORD_RESET_SALT"],
            max_age=app.config["PASSWORD_RESET_EXPIRES"]
        )
    except (SignatureExpired, BadSignature):
        return None


# -------------------------------------------------------------------
# CLI COMMANDS

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

# -------------------------------------------------------------------
# AUTH ROUTES

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        
        if db.session.scalar(db.select(User).where(User.email == email)):
            flash("Account already exists. Please log in.", "warning")
            return redirect(url_for("login"))

        user = User(
            email=email,
            password=generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=16),
            name=form.name.data,
            verification_sent_at=datetime.now(timezone.utc)
        )
        db.session.add(user)
        db.session.commit()

        # Send Verification
        token = generate_email_token(user.id)
        verify_url = url_for("verify_email", token=token, _external=True)
        send_email(
            user.email,
            "Verify your email",
            render_template("email/verify.html", verify_url=verify_url, user=user)
        )

        # Important: Store email in session for the resend countdown
        session['verification_email'] = user.email
        flash("Registration successful! Please check your email.", "success")
        return redirect(url_for("resend_verification"))

    return render_template("register.html", form=form)

@app.route("/verify-email/<token>")
def verify_email(token):
    data = confirm_email_token(token)
    if not data:
        flash("Invalid or expired verification link.", "danger")
        return redirect(url_for("resend_verification"))

    user = db.session.get(User, int(data["user_id"]))
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("register"))

    token_issued_at = datetime.fromtimestamp(
        data["iat"], tz=timezone.utc
    )

    # 🔐 Invalidate older verification links
    if (
        user.verification_sent_at
        and token_issued_at < user.verification_sent_at
    ):
        flash(
            "This verification link has been replaced by a newer one.",
            "danger"
        )
        return redirect(url_for("resend_verification"))

    if user.email_verified:
        flash("Email already verified. Please log in.", "info")
        return redirect(url_for("login"))

    user.email_verified = True
    db.session.commit()

    flash("Email verified successfully!", "success")
    return redirect(url_for("login"))


@app.route("/resend-verification", methods=["GET", "POST"])
@limiter.limit(RATE_LIMIT_EMAIL_GLOBAL, key_func=get_remote_address)
@limiter.limit(RATE_LIMIT_EMAIL_SPECIFIC, key_func=email_rate_limit_key)
def resend_verification():
    resend_form = ResendVerificationForm()
    cooldown = timedelta(seconds=RESEND_COOLDOWN_SECONDS)
    remaining_seconds = 0

    # -------------------------------------------------
    # POST: User requests verification email
    # -------------------------------------------------
    if resend_form.validate_on_submit():

        # 🚨 CAPTCHA check (only if escalated)
        if app.config["CAPTCHA_ENABLED"] and session.get("captcha_required"):
            token = request.form.get("h-captcha-response")
            if not verify_hcaptcha(token, get_remote_address()):
                flash("CAPTCHA verification failed.", "danger")
                return render_template(
                    "resend_verification.html",
                    resend_form=resend_form,
                    remaining_seconds=0,
                    captcha_required=True,
                    hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"],
                )

        email = resend_form.email.data.lower().strip()
        user = db.session.scalar(
            db.select(User).where(User.email == email)
        )

        # 🛡️ Fake success for non-existing users (no enumeration)
        if not user:
            flash(
                "If an account exists, a verification email has been sent.",
                "info"
            )
            session.pop("captcha_required", None)
            return redirect(url_for("resend_verification"))

        # Already verified
        if user.email_verified:
            flash(
                "This email is already verified. Please log in.",
                "info"
            )
            return redirect(url_for("login"))

        # -------------------------------------------------
        # Cooldown enforcement
        # -------------------------------------------------
        if user.verification_sent_at:
            last_sent = user.verification_sent_at.replace(
                tzinfo=timezone.utc
            )
            delta = datetime.now(timezone.utc) - last_sent

            if delta < cooldown:
                # Escalate CAPTCHA on abuse
                if app.config["CAPTCHA_ENABLED"]:
                    session["captcha_required"] = True
                session["verification_email"] = user.email
                return redirect(url_for("resend_verification"))

        # -------------------------------------------------
        # Send verification email
        # -------------------------------------------------
        token = generate_email_token(user.id)
        verify_url = url_for(
            "verify_email",
            token=token,
            _external=True
        )

        send_email(
            user.email,
            "Verify your email",
            render_template(
                "email/verify.html",
                verify_url=verify_url,
                user=user
            )
        )

        user.verification_sent_at = datetime.now(timezone.utc)
        db.session.commit()

        session["verification_email"] = user.email
        session.pop("captcha_required", None)

        flash("Verification email sent!", "success")
        return redirect(url_for("resend_verification"))

    # -------------------------------------------------
    # GET: Calculate remaining cooldown time
    # -------------------------------------------------
    target_user = None
    if current_user.is_authenticated:
        target_user = current_user
    elif "verification_email" in session:
        target_user = db.session.scalar(
            db.select(User).where(
                User.email == session["verification_email"]
            )
        )

    if target_user and target_user.verification_sent_at:
        last_sent = target_user.verification_sent_at.replace(
            tzinfo=timezone.utc
        )
        delta = datetime.now(timezone.utc) - last_sent

        if delta < cooldown:
            remaining_seconds = int(
                (cooldown - delta).total_seconds()
            )
        else:
            session.pop("verification_email", None)

    # -------------------------------------------------
    # Render page
    # -------------------------------------------------
    return render_template(
        "resend_verification.html",
        resend_form=resend_form,
        remaining_seconds=remaining_seconds,
        captcha_required=session.get("captcha_required"),
        hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"],
    )


from utils.captcha import verify_hcaptcha

@app.route("/request-reset", methods=["GET", "POST"])
@limiter.limit(RATE_LIMIT_EMAIL_GLOBAL, key_func=get_remote_address)
@limiter.limit(RATE_LIMIT_EMAIL_SPECIFIC, key_func=email_rate_limit_key)
def request_reset():
    form = RequestResetForm()
    cooldown = timedelta(seconds=RESET_COOLDOWN_SECONDS)
    remaining_seconds = 0

    # -------------------------------------------------
    # POST: User requests password reset
    # -------------------------------------------------
    if form.validate_on_submit():

        # 🚨 CAPTCHA check (only if escalated)
        if app.config["CAPTCHA_ENABLED"] and session.get("captcha_required"):
            token = request.form.get("h-captcha-response")
            if not verify_hcaptcha(token, get_remote_address()):
                flash("CAPTCHA verification failed.", "danger")
                return render_template(
                    "request_reset.html",
                    form=form,
                    remaining_seconds=0,
                    captcha_required=True,
                    hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"],
                )

        email = form.email.data.lower().strip()
        user = db.session.scalar(
            db.select(User).where(User.email == email)
        )

        # 🛡️ Fake success (prevents email enumeration)
        flash(
            "If an account exists, a reset link has been sent.",
            "info"
        )

        if user:
            # -------------------------------------------------
            # Cooldown enforcement
            # -------------------------------------------------
            if user.reset_password_sent_at:
                delta = datetime.now(timezone.utc) - user.reset_password_sent_at
                if delta < cooldown:
                    # Escalate CAPTCHA on abuse
                    if app.config["CAPTCHA_ENABLED"]:
                        session["captcha_required"] = True
                    session["reset_email"] = email
                    return redirect(url_for("request_reset"))

            # -------------------------------------------------
            # Send reset email
            # -------------------------------------------------
            token = generate_password_reset_token(user.id)
            reset_url = url_for(
                "reset_password",
                token=token,
                _external=True
            )

            send_email(
                user.email,
                "Reset your password",
                render_template(
                    "email/reset_password.html",
                    reset_url=reset_url,
                    user=user
                )
            )

            user.reset_password_sent_at = datetime.now(timezone.utc)
            db.session.commit()
            session["reset_email"] = email

        # CAPTCHA no longer required after successful flow
        session.pop("captcha_required", None)
        return redirect(url_for("request_reset"))

    # -------------------------------------------------
    # GET: Calculate remaining cooldown time
    # -------------------------------------------------
    target_user = None
    if "reset_email" in session:
        target_user = db.session.scalar(
            db.select(User).where(
                User.email == session["reset_email"]
            )
        )

    if target_user and target_user.reset_password_sent_at:
        delta = datetime.now(timezone.utc) - target_user.reset_password_sent_at
        if delta < cooldown:
            remaining_seconds = int(
                (cooldown - delta).total_seconds()
            )
        else:
            session.pop("reset_email", None)

    # -------------------------------------------------
    # Render page
    # -------------------------------------------------
    return render_template(
        "request_reset.html",
        form=form,
        remaining_seconds=remaining_seconds,
        captcha_required=session.get("captcha_required"),
        hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"],
    )


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    data = confirm_password_reset_token(token)
    if not data:
        flash("Invalid or expired reset link.", "danger")
        return redirect(url_for("request_reset"))

    user = db.session.get(User, int(data["user_id"]))
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("request_reset"))

    token_issued_at = datetime.fromtimestamp(
        data["iat"], tz=timezone.utc
    )

    # 🔐 Invalidate older reset links immediately
    if (
        user.reset_password_sent_at
        and token_issued_at < user.reset_password_sent_at
    ):
        flash(
            "This reset link has been replaced by a newer one.",
            "danger"
        )
        return redirect(url_for("request_reset"))

    form = ResetPasswordForm()

    # 🔐 Inject email for validator (Option A)
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

        # 🔐 Logout all sessions (industry default)
        logout_user()
        session.clear()

        flash(
            "Password reset successful. Please log in again.",
            "success"
        )
        return redirect(url_for("login"))

    return render_template("reset_password.html", form=form)



# -------------------------------------------------------------------------
# Login Route
# -------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
# Layer 1: Global IP Protection
@limiter.limit(RATE_LIMIT_LOGIN_GLOBAL, key_func=get_remote_address)
# Layer 2: Specific Account Protection
@limiter.limit(RATE_LIMIT_LOGIN_SPECIFIC, key_func=login_rate_limit_key)
def login():
    form = LoginForm()

    if form.validate_on_submit():

        # -------------------------------------------------
        # 🚨 CAPTCHA CHECK (only if required)
        # -------------------------------------------------
        if app.config["CAPTCHA_ENABLED"] and session.get("captcha_required"):
            token = request.form.get("h-captcha-response")
            if not verify_hcaptcha(token, get_remote_address()):
                flash("CAPTCHA verification failed.", "danger")
                return render_template(
                    "login.html",
                    login_form=form,
                    captcha_required=True,
                    hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"],
                )

        email = form.email.data.lower().strip()
        password = form.password.data
        now = datetime.now(timezone.utc)

        # Fetch user
        user = db.session.scalar(db.select(User).where(User.email == email))

        # -------------------------------------------------
        # 1️⃣ Database Lockout Check (with remaining time)
        # -------------------------------------------------
        if user and user.login_locked_until and user.login_locked_until > now:
            remaining = int((user.login_locked_until - now).total_seconds())

            if remaining <= 0:
                # Lock expired just now
                user.login_locked_until = None
                user.failed_login_count = 0
                db.session.commit()
            else:
                logger.info(f"Locked account login attempt: {email}")
                session["captcha_required"] = True  # escalate
                flash("Please try again later.", "danger")
                return render_template(
                    "login.html",
                    login_form=form,
                    lockout_seconds=remaining,
                    captcha_required=True,
                    hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"],
                )

        # -------------------------------------------------
        # 2️⃣ Credential Validation (Timing-safe)
        # -------------------------------------------------
        valid_password = False
        if user:
            valid_password = check_password_hash(user.password, password)
        else:
            check_password_hash(DUMMY_PASSWORD_HASH, password)

        # -------------------------------------------------
        # 3️⃣ Handle Failure
        # -------------------------------------------------
        if not user or not valid_password:
            if user:
                user.failed_login_count += 1
                logger.info(
                    f"Failed login for {email}. Count: {user.failed_login_count}"
                )

                if user.failed_login_count >= MAX_LOGIN_ATTEMPTS:
                    user.login_locked_until = now + timedelta(
                        seconds=LOGIN_LOCK_SECONDS
                    )
                    user.failed_login_count = 0
                    if app.config["CAPTCHA_ENABLED"]:
                        session["captcha_required"] = True  # escalate
                    db.session.commit()

                    logger.warning(
                        f"Account locked due to max attempts: {email}"
                    )
                    flash("Too many failed attempts. Please try again later.", "danger")

                    return render_template(
                        "login.html",
                        login_form=form,
                        lockout_seconds=LOGIN_LOCK_SECONDS,
                        captcha_required=True,
                        hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"],
                    )

                db.session.commit()

            flash("Invalid email or password.", "danger")
            return redirect(url_for("login"))

        # -------------------------------------------------
        # 4️⃣ Handle Success
        # -------------------------------------------------
        user.failed_login_count = 0
        user.login_locked_until = None
        db.session.commit()

        # Clear CAPTCHA escalation on success
        session.pop("captcha_required", None)

        if not user.email_verified:
            logger.info(f"Unverified login attempt: {email}")
            flash("Please verify your email before logging in.", "warning")
            return redirect(url_for("resend_verification"))

        logger.info(f"Successful login: {email}")
        login_user(user, fresh=True)
        return redirect(url_for("get_all_posts"))

    # -------------------------------------------------
    # GET Request
    # -------------------------------------------------
    return render_template(
        "login.html",
        login_form=form,
        captcha_required=session.get("captcha_required"),
        hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"],
    )



@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("get_all_posts"))

# -------------------------------------------------------------------
# BLOG ROUTES

@app.route("/")
def get_all_posts():
    # Sort by date desc if needed, assuming id correlates to time here
    posts = db.session.scalars(db.select(BlogPost).order_by(BlogPost.date.desc())).all()
    return render_template("index.html", all_posts=posts)

@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()

    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login to comment.", "warning")
            return redirect(url_for("login"))
        
        if not current_user.email_verified:
            flash("Please verify your email first.", "warning")
            return redirect(url_for("resend_verification"))

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
            
            send_email(
                to=os.environ["CONTACT_RECEIVER_EMAIL"],
                subject="New Contact Form Message",
                html_body=html_body
            )

            # SUCCESS: Flash message and REDIRECT.
            # Redirecting forces a page reload, which clears the form fields automatically.
            flash("Your message has been sent successfully!", "success")
            return redirect(url_for('contact'))

        except Exception as e:
            # FAILURE (SMTP): Flash error and allow code to fall through to render_template.
            # Because we didn't redirect, the 'form' object still holds the user's data.
            logger.exception("Contact email failed") # Helpful for debugging
            flash("Failed to send message. Please try again later.", "danger")
    
    # Renders on: 
    # 1. Initial Page Load (GET)
    # 2. Form Validation Error (POST) -> 'form' contains input data + errors
    # 3. Exception caught above (POST) -> 'form' contains input data
    return render_template("contact.html", form=form)


if __name__ == "__main__":
    app.run(
        debug=os.environ.get("ENV") != "production",
        port=int(os.environ.get("PORT", 5002))
    )
