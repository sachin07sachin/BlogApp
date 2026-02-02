import eventlet
eventlet.monkey_patch()
import os
import logging
import json
import contextlib
from datetime import datetime, timedelta, timezone
from functools import wraps
import uuid
import hashlib
import time
# Replaced native threading with SocketIO background tasks for Eventlet compatibility
# from threading import Thread 

import click
import bleach
from bleach.css_sanitizer import CSSSanitizer
from dotenv import load_dotenv
from flask import (
    Flask, abort, render_template, redirect,
    url_for, flash, request, session, send_from_directory, current_app
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
from sqlalchemy import Integer, String, Text, Boolean, ForeignKey, DateTime, text, or_, and_, extract, func, select, desc
from sqlalchemy.orm import DeclarativeBase, relationship, Mapped, mapped_column
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit, join_room, leave_room
from pywebpush import webpush, WebPushException

# Local Imports
from forms import (
    CreatePostForm, RegisterForm, LoginForm,
    CommentForm, ResendVerificationForm, ContactForm, 
    RequestResetForm, ResetPasswordForm, DeleteReasonForm, WarnUserForm, MessageForm, SettingsForm, AdminDeleteUserForm, DeleteAccountForm
)
from utils.email import send_email 
from utils.captcha import verify_hcaptcha

# -------------------------------------------------------------------
# 1. CONFIGURATION & ENVIRONMENT SETUP
# -------------------------------------------------------------------

# Load environment variables
load_dotenv()


class Config:
    """Base Configuration Class."""
    SECRET_KEY = os.environ["SECRET_KEY"]
    CRON_SECRET = os.environ["CRON_SECRET"]
    
    # Database (Fix Postgres URI for Render/Heroku)
    SQLALCHEMY_DATABASE_URI = os.environ["DATABASE_URL"].replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = (os.environ.get("ENV") == "production")
    
    # Email Tokens
    EMAIL_SECRET_KEY = os.environ["EMAIL_SECRET_KEY"]
    EMAIL_TOKEN_SALT = os.environ.get("EMAIL_TOKEN_SALT", "email-confirm-salt")
    EMAIL_TOKEN_EXPIRES = int(os.environ.get("EMAIL_TOKEN_EXPIRES", 3600))
    
    # Password Reset
    PASSWORD_RESET_SALT = os.environ.get("PASSWORD_RESET_SALT", "password-reset-salt")
    PASSWORD_RESET_EXPIRES = int(os.environ.get("PASSWORD_RESET_EXPIRES", 1800))
    
    # CAPTCHA
    CAPTCHA_ENABLED = (os.environ.get("ENABLE_CAPTCHA", "false").lower() == "true")
    HCAPTCHA_SITE_KEY = os.environ.get("HCAPTCHA_SITE_KEY")
    HCAPTCHA_SECRET_KEY = os.environ.get("HCAPTCHA_SECRET_KEY")
    
    # Third Party
    TINYMCE_API_KEY = os.environ.get("TINYMCE_API_KEY")

# Initialize Flask App
app = Flask(__name__)
app.config.from_object(Config)

# Security: CSRF Protection
csrf = CSRFProtect(app)

# Initialize SocketIO
# async_mode='eventlet' is the industry standard for production performance
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Security: Proxy Fix (Required for Render/Heroku/Nginx)
if os.environ.get("ENV") == "production":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# Initialize Extensions
ckeditor = CKEditor(app)
bootstrap = Bootstrap5(app)

# -------------------------------------------------------------------
# 2. LOGGING & DATABASE SETUP
# -------------------------------------------------------------------

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
if os.environ.get("ENV") == "production":
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

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
# PUSH NOTIFICATION CONFIG
# -------------------------------------------------------------------
vapid_email = os.environ.get("VAPID_ADMIN_EMAIL")
VAPID_CLAIMS = {"sub": f"mailto:{vapid_email}"} 
VAPID_PRIVATE_KEY = os.environ.get("VAPID_PRIVATE_KEY")

# -------------------------------------------------------------------
# 3. DATABASE MODELS
# -------------------------------------------------------------------

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    
    # --- CREDENTIALS ---
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password: Mapped[str] = mapped_column(String(255), nullable=False)
    username: Mapped[str] = mapped_column(String(30), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="user", server_default="user")
    joined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # --- PROFILE ---
    about_me: Mapped[str | None] = mapped_column(Text())
    
    # --- SETTINGS / PREFERENCES ---
    notify_on_comments: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    notify_new_post: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    notify_post_edit: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    notify_on_message: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    allow_dms: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    
    # --- SECURITY ---
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    verification_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reset_password_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")

    # --- RELATIONSHIPS ---
    posts = relationship("BlogPost", back_populates="author", passive_deletes=True)
    comments = relationship("Comment", back_populates="comment_author", passive_deletes=True)

    # --- MESSAGING RELATIONSHIPS ---
    # No 'cascade="all, delete-orphan"' to protect chat history from user deletion (Ghost User logic)
    messages_sent = relationship(
        "Message", 
        foreign_keys="Message.sender_id", 
        back_populates="sender", 
        lazy="dynamic"
    )
    messages_received = relationship(
        "Message", 
        foreign_keys="Message.recipient_id", 
        back_populates="recipient", 
        lazy="dynamic"
    )

    # Helper method to count unread messages
    def new_messages(self):
        return Message.query.filter_by(recipient=self, is_read=False).count()


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
    img_url: Mapped[str] = mapped_column(String(500), nullable=False)

    # Moderation
    can_comment: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    
    comments = relationship("Comment", back_populates="parent_post", passive_deletes=True)


class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    # --- RELATIONSHIPS ---
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id", ondelete="CASCADE"))
    comment_author = relationship("User", back_populates="comments")
    
    post_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("blog_posts.id", ondelete="CASCADE"))
    parent_post = relationship("BlogPost", back_populates="comments")
    
    # --- CHAIN COMMENT LOGIC ---
    parent_id: Mapped[int | None] = mapped_column(Integer, db.ForeignKey("comments.id", ondelete="CASCADE"))
    replies = relationship("Comment", back_populates="parent", cascade="all, delete-orphan")
    parent = relationship("Comment", back_populates="replies", remote_side=[id])


class Message(db.Model):
    __tablename__ = 'messages'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Removing ondelete="CASCADE" to support Ghost Users (Chats survive user deletion)
    sender_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'))
    recipient_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'))
    
    body: Mapped[str] = mapped_column(String(1000), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, default=func.now())
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    
    sender = relationship("User", foreign_keys=[sender_id], back_populates="messages_sent")
    recipient = relationship("User", foreign_keys=[recipient_id], back_populates="messages_received")

    def __repr__(self):
        return f'<Message {self.body}>'


class PushSubscription(db.Model):
    __tablename__ = "push_subscriptions"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    subscription_json: Mapped[str] = mapped_column(Text, nullable=False)
    user = relationship("User", backref="push_subscriptions")


# --- NEW: NOTIFICATION MODEL (Persistence Layer for Activity) ---
# Added to support the industry-standard "Activity Feed" and robust Daily Digest
class Notification(db.Model):
    __tablename__ = "notifications"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    recipient_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(String(500), nullable=False)
    link_url: Mapped[str] = mapped_column(String(500), nullable=False)
    
    # Metadata for filtering/cleanup
    category: Mapped[str] = mapped_column(String(50)) # 'comment', 'post', 'edit', 'chat'
    related_post_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("blog_posts.id", ondelete="CASCADE")) 

    # --- NEW: Comment Link (The Fix) ---
    related_comment_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("comments.id", ondelete="CASCADE"))

    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)

    recipient = relationship("User", backref="notifications")

class DeletedAccountLog(db.Model):
    __tablename__ = "deleted_accounts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    
    # We store the ORIGINAL details here before anonymization
    original_email: Mapped[str] = mapped_column(String(255), nullable=False)
    original_username: Mapped[str] = mapped_column(String(30), nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False) # Keep ID to link to ghost content if needed
    
    reason: Mapped[str] = mapped_column(String(500), nullable=True) # "Why are you leaving?"
    ip_address: Mapped[str] = mapped_column(String(45), nullable=True) # IPv4/IPv6
    
    deleted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class BannedUser(db.Model):
    __tablename__ = "banned_users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    
    # Indexed for fast lookup during registration
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    banned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    banned_by: Mapped[str] = mapped_column(String(120), nullable=False) # Stores admin username

# -------------------------------------------------------------------
# 4. HELPERS & DECORATORS
# -------------------------------------------------------------------

gravatar = Gravatar(app, size=100, rating="g", default="retro", use_ssl=True)

@contextlib.contextmanager
def safe_commit():
    """
    Context manager for safe database transactions.
    Automatically commits on success, rolls back on exception.
    """
    try:
        yield
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database transaction failed: {e}")
        raise

def admin_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        if current_user.role != "admin":
            abort(403)
        return f(*args, **kwargs)
    return wrapper

def clean_html(text):
    """
    Cleans HTML text using Bleach, allowing specific tags and attributes.
    """
    allowed_tags = [
        'a', 'b', 'i', 'u', 'em', 'strong', 'p', 'img', 'br', 'span', 
        'div', 'blockquote', 'ul', 'ol', 'li', 
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'table', 'thead', 'tbody', 'tr', 'th', 'td', 'pre', 'code'
    ]
    allowed_attrs = {
        '*': ['class', 'style'],
        'a': ['href', 'target', 'rel'],
        'img': ['src', 'alt', 'width', 'height', 'style']
    }

    css_sanitizer = CSSSanitizer()
    return bleach.clean(
        text,
        tags=allowed_tags,
        attributes=allowed_attrs,
        css_sanitizer=css_sanitizer,
        strip=True
    )

def get_gravatar_url(email, size=200):
    """Generates a Gravatar URL for the given email."""
    email_hash = hashlib.md5(email.lower().strip().encode('utf-8')).hexdigest()
    return f"https://www.gravatar.com/avatar/{email_hash}?s={size}&d=retro"

def anonymize_user_data(user):
    """
    Scrub user data to create a 'Ghost User'.
    Preserves ID for chat history integrity but removes PII.
    """
    random_suffix = uuid.uuid4().hex[:8]
    
    # 1. Anonymize Identity
    user.name = "Deleted User"
    user.username = f"ghost_{random_suffix}"
    user.email = f"deleted_{uuid.uuid4().hex}@example.com" # Free up original email
    user.about_me = None
    user.password = generate_password_hash(uuid.uuid4().hex) # Impossible login
    user.email_verified = False
    
    # 2. Clear Personal Settings
    user.notify_on_comments = False
    user.notify_new_post = False
    user.notify_post_edit = False
    user.notify_on_message = False
    user.allow_dms = False
    
    # 3. Delete Public Content (Posts)
    # Note: We keep comments/messages as "Deleted User" context
    for post in user.posts:
        db.session.delete(post)
    
    # 4. Remove Push Subscriptions
    for sub in user.push_subscriptions:
        db.session.delete(sub)
        
    return user

# -------------------------------------------------------------------
# 5. NOTIFICATION SYSTEM
# -------------------------------------------------------------------

def send_notification_async(recipient_id, title, body, link_url, category, related_post_id=None, related_comment_id=None, icon_url=None, image_url=None):
    """
    Background Task:
    1. Saves notification to DB (Persistence for Daily Digest).
    2. Sends immediate Web Push Notification.
    """
    with app.app_context():
        try:
            # A. SAVE TO DATABASE (History)
            if category != 'chat':
                with safe_commit():
                    new_notif = Notification(
                        recipient_id=recipient_id,
                        title=title,
                        message=body,
                        link_url=link_url,
                        category=category,
                        related_post_id=related_post_id,
                        related_comment_id=related_comment_id
                    )
                    db.session.add(new_notif)

            # B. SEND RICH PUSH (Immediate)
            subscriptions = db.session.scalars(
                db.select(PushSubscription).where(PushSubscription.user_id == recipient_id)
            ).all()

            if subscriptions:
                timestamp_ms = int(time.time() * 1000)
                # --- MODERN PAYLOAD STRUCTURE ---
                payload_data = {
                    "title": title,
                    "body": body,
                    "url": link_url,
                    "timestamp": timestamp_ms,
                    # 1. Avatar of the person causing the action (or App Logo)
                    "icon": icon_url or url_for('static', filename='assets/favicon.ico', _external=True),
                    # 2. Rich Image (For New Posts) - Android/Windows only
                    "image": image_url, 
                    # 3. Badge (Small monochrome icon for Android status bar)
                    "badge": url_for('static', filename='assets/badge.png', _external=True),
                    # 4. Tag (Prevents stacking: updates existing notif instead of adding new one)
                    "tag": f"{category}_{related_post_id}" if related_post_id else "general"
                }
                
                payload_json = json.dumps(payload_data)

                for sub in subscriptions:
                    try:
                        webpush(
                            subscription_info=json.loads(sub.subscription_json),
                            data=payload_json,
                            vapid_private_key=VAPID_PRIVATE_KEY,
                            vapid_claims=VAPID_CLAIMS
                        )
                    except WebPushException as ex:
                        if ex.response and ex.response.status_code == 410:
                            with safe_commit():
                                db.session.delete(sub)
                        else:
                            logger.error(f"WebPush Error for user {recipient_id}: {ex}")

            # # B. SEND PUSH (Immediate)
            # subscriptions = db.session.scalars(
            #     db.select(PushSubscription).where(PushSubscription.user_id == recipient_id)
            # ).all()

            # if subscriptions:
            #     payload = json.dumps({
            #         "title": title,
            #         "body": body,
            #         "url": link_url
            #     })

            #     for sub in subscriptions:
            #         try:
            #             webpush(
            #                 subscription_info=json.loads(sub.subscription_json),
            #                 data=payload,
            #                 vapid_private_key=VAPID_PRIVATE_KEY,
            #                 vapid_claims=VAPID_CLAIMS
            #             )
            #         except WebPushException as ex:
            #             # Clean up expired subscriptions (HTTP 410 Gone)
            #             if ex.response and ex.response.status_code == 410:
            #                 with safe_commit():
            #                     db.session.delete(sub)
            #             else:
            #                 logger.error(f"WebPush Error for user {recipient_id}: {ex}")

        except Exception as e:
            logger.exception(f"Notification Failed for user {recipient_id}: {e}")

# -------------------------------------------------------------------
# 6. CLI COMMANDS (Daily Digest)
# -------------------------------------------------------------------

# @app.cli.command("create-admin")
# @click.argument("email")
# def create_admin(email):
#     """Promotes a user to admin role."""
#     user = db.session.scalar(db.select(User).where(User.email == email))
#     if user:
#         try:
#             with safe_commit():
#                 user.role = "admin"
#             logger.info(f"User {email} is now an ADMIN.")
#         except Exception:
#             logger.error(f"Failed to promote user {email}.")
#     else:
#         logger.warning(f"User {email} not found.")

@csrf.exempt
@app.route("/cron/send-digest", methods=["POST"])
def send_digest():
    """
    Consolidates unread Chat Messages AND unread Notifications (Posts/Comments)
    older than 24 hours into a single daily email.
    """
    # Security Check
    secret = request.headers.get("X-Cron-Secret")

    if not secret or secret != current_app.config["CRON_SECRET"]:
        return "Unauthorized", 403

    logger.info("Starting Daily Digest...")
    
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    
    # 1. FIND USERS WITH MISSED ACTIVITY
    # A. Users with old unread messages (who have opted in)
    users_with_messages = db.session.scalars(
        db.select(User).join(Message, Message.recipient_id == User.id)
        .where(
            Message.is_read == False, 
            Message.timestamp < cutoff, 
            User.notify_on_message == True
        )
    ).unique().all()

    # B. Users with old unread notifications
    users_with_notifs = db.session.scalars(
        db.select(User).join(Notification, Notification.recipient_id == User.id)
        .where(
            Notification.is_read == False, 
            Notification.timestamp < cutoff
        )
    ).unique().all()

    # Combine lists
    all_users = set(users_with_messages + users_with_notifs)

    if not all_users:
        logger.info("No users need a digest today.")
        return "No digests needed", 200

    # 2. SEND EMAILS
    # In production, you will add an Environment Variable 'DOMAIN_URL' = 'https://your-app-name.onrender.com'
    server_url = os.environ.get("DOMAIN_URL", "http://localhost:5000")

    # This creates a "Fake" request context so url_for knows the domain
    with app.test_request_context(base_url=server_url):
        for user in all_users:
            logger.info(f"Processing digest for {user.email}")
            
            try:
                # Get Chat Stats
                unread_msgs = user.new_messages()
                
                # Get Notification Activity
                unread_activity = db.session.scalars(
                    db.select(Notification)
                    .where(
                        Notification.recipient_id == user.id, 
                        Notification.is_read == False, 
                        Notification.timestamp < cutoff
                    )
                ).all()
                
                # Double check there is actually something to send
                if unread_msgs == 0 and len(unread_activity) == 0:
                    continue

                # Render & Send
                # --- FAIL-SAFE: Generate all URLs here via Flask Context ---
                inbox_url = url_for('inbox', _external=True)
                home_url = url_for('get_all_posts', _external=True)
                settings_url = url_for('settings', _external=True)
                privacy_url = url_for('legal', page_name='privacy', _external=True)
                support_url = url_for('contact', _external=True)

                html_body = render_template(
                    "email/unread_digest.html", 
                    user=user,
                    msg_count=unread_msgs,
                    activity_list=unread_activity,
                    inbox_url=inbox_url,
                    home_url=home_url,
                    settings_url=settings_url,
                    privacy_url=privacy_url, # New: Passed to template
                    support_url=support_url  # New: Passed to template
                )
                
                send_email(
                    to=user.email,
                    subject=f"You missed some activity on Blog App",
                    html_body=html_body
                )
            except Exception as e:
                logger.error(f"Failed to send digest to {user.email}: {e}")
            
    logger.info("Digest Complete.")
    return "Digest Run Complete", 200

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

# -------------------------------------------------------------------
# 7. RATE LIMITING & SECURITY HELPERS
# -------------------------------------------------------------------

# Initialize Rate Limiter
redis_url = os.environ.get("REDIS_URL")
if not redis_url:
    raise RuntimeError("REDIS_URL environment variable not set")

limiter = Limiter(
    app=app, 
    key_func=get_remote_address, 
    storage_uri=redis_url, 
    strategy="sliding-window-counter"
)

def login_rate_limit_key():
    ip = get_remote_address()
    email = request.form.get("email", "unknown").lower().strip()
    return f"{ip}:{email}"

def email_rate_limit_key():
    ip = get_remote_address()
    email = request.form.get("email", "unknown").lower().strip()
    return f"{ip}:{email}"

def match_captcha_bypass():
    return request.form.get("h-captcha-response") is not None

# Constants for Rate Limits
RATE_LIMIT_LOGIN_GLOBAL = "60 per hour"
RATE_LIMIT_LOGIN_SPECIFIC = "10 per minute"
RATE_LIMIT_EMAIL_GLOBAL = "20 per hour"
RATE_LIMIT_EMAIL_SPECIFIC = "5 per hour"
MAX_LOGIN_ATTEMPTS = 5
DUMMY_PASSWORD_HASH = generate_password_hash("dummy_password_for_timing_protection")

# -------------------------------------------------------------------
# 8. TOKEN & SECURITY UTILITIES
# -------------------------------------------------------------------

def _get_serializer():
    return URLSafeTimedSerializer(app.config["EMAIL_SECRET_KEY"])

def generate_email_token(user_id: int, timestamp: datetime) -> str:
    return _get_serializer().dumps(
        {"user_id": str(user_id), "iat": int(timestamp.timestamp())},
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
    return _get_serializer().dumps(
        {"user_id": str(user_id), "iat": int(timestamp.timestamp())},
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
# 9. GLOBAL ERROR HANDLERS
# -------------------------------------------------------------------

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("Your session expired. Please try again.", "warning")
    return redirect(request.referrer or url_for("login_get"))

@app.errorhandler(RateLimitExceeded)
def handle_rate_limit(e):
    if app.config["CAPTCHA_ENABLED"]:
        session["captcha_required"] = True
    
    logger.warning(f"Rate limit exceeded ({e.description}) IP={get_remote_address()} email={request.form.get('email', 'unknown')}")
    flash("Too many requests detected. Please verify you are human.", "danger")

    endpoint = request.endpoint
    if endpoint == "login_post":
        return render_template("login.html", login_form=LoginForm(), captcha_required=True, hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"]), 429
    elif endpoint == "resend_verification_post":
        return render_template("resend_verification.html", resend_form=ResendVerificationForm(), captcha_required=True, hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"]), 429
    elif endpoint == "request_reset_post":
        return render_template("request_reset.html", form=RequestResetForm(), captcha_required=True, hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"]), 429
    
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
# 10. AUTHENTICATION ROUTES
# -------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    if form.validate_on_submit():
        email = form.email.data.lower().strip()

        # --- 1. BAN CHECK (Industry Standard Enforcement) ---
        is_banned = db.session.scalar(db.select(BannedUser).where(BannedUser.email == email))
        if is_banned:
            logger.warning(f"Banned email attempted registration: {email}")
            flash("Unable to create account. Please contact support.", "danger")
            return render_template("register.html", form=form)
        # ----------------------------------------------------

        username = form.username.data.strip()
        
        existing_email = db.session.scalar(db.select(User).where(User.email == email))
        existing_username = db.session.scalar(db.select(User).where(User.username == username))
        
        # --- FAIL-SAFE: Generate Common Links for Emails ---
        privacy_url = url_for('legal', page_name='privacy', _external=True)
        support_url = url_for('contact', _external=True)
        
        if existing_username:
            flash("That username is already taken. Please choose another.", "warning")
            return render_template("register.html", form=form)

        flash("Registration successful! Please check your email to verify your account.", "success")

        if existing_email:
            login_url = url_for("login_get", _external=True)
            reset_url = url_for("request_reset_get", _external=True)
            
            html_body = render_template(
                "email/already_registered.html", 
                name=existing_email.name, 
                login_url=login_url, 
                reset_url=reset_url,
                privacy_url=privacy_url, # Passed here
                support_url=support_url  # Passed here
            )
            
            socketio.start_background_task(send_email, existing_email.email, "You already have an account", html_body)
        else:
            try:
                with safe_commit():
                    new_user = User(
                        email=email, 
                        username=username, 
                        password=generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=16), 
                        name=form.name.data, 
                        verification_sent_at=now
                    )
                    db.session.add(new_user)
                
                token = generate_email_token(new_user.id, now)
                verify_url = url_for("verify_email", token=token, _external=True)
                
                socketio.start_background_task(
                    send_email, 
                    new_user.email, 
                    "Verify your email", 
                    render_template(
                        "email/verify.html", 
                        verify_url=verify_url, 
                        user=new_user,
                        privacy_url=privacy_url, # Passed here
                        support_url=support_url  # Passed here
                    )
                )
            except Exception as e:
                flash("An error occurred during registration.", "danger")
                logger.error(f"Registration failed: {e}")
                return render_template("register.html", form=form)

        return redirect(url_for("resend_verification_get"))

    return render_template("register.html", form=form)

# --- UNIVERSAL LEGAL ROUTE ---
@app.route('/legal/<page_name>')
def legal(page_name):
    # This dictionary maps the URL name to the Template file
    pages = {
        'privacy': 'legal/privacy.html',
        'terms': 'legal/terms.html',
        'guidelines': 'legal/guidelines.html'
    }
    
    # Safety check: if they type a random URL, 404
    if page_name not in pages:
        return render_template('404.html'), 404
        
    return render_template(pages[page_name])

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

    token_issued_at = datetime.fromtimestamp(data["iat"], tz=timezone.utc)
    if user.verification_sent_at and token_issued_at < user.verification_sent_at:
        flash("This verification link has been replaced by a newer one.", "danger")
        return redirect(url_for("resend_verification_get"))

    if user.email_verified:
        flash("Email already verified. Please log in.", "info")
        return redirect(url_for("login_get"))

    with safe_commit():
        user.email_verified = True
    
    session.pop("captcha_required", None)
    flash("Email verified successfully! Please log in.", "success")
    return redirect(url_for("login_get"))


@app.route("/resend-verification", methods=["GET"])
def resend_verification_get():
    resend_form = ResendVerificationForm()
    return render_template("resend_verification.html", resend_form=resend_form, captcha_required=(app.config["CAPTCHA_ENABLED"] and session.get("captcha_required")), hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"])

@app.route("/resend-verification", methods=["POST"])
@limiter.limit(RATE_LIMIT_EMAIL_GLOBAL, key_func=get_remote_address, exempt_when=match_captcha_bypass)
@limiter.limit(RATE_LIMIT_EMAIL_SPECIFIC, key_func=email_rate_limit_key, exempt_when=match_captcha_bypass)
def resend_verification_post():
    resend_form = ResendVerificationForm()
    now = datetime.now(timezone.utc).replace(microsecond=0)

    if not resend_form.validate_on_submit():
        return render_template("resend_verification.html", resend_form=resend_form, captcha_required=(app.config["CAPTCHA_ENABLED"] and session.get("captcha_required")), hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"])

    if app.config["CAPTCHA_ENABLED"] and session.get("captcha_required"):
        if not verify_hcaptcha(request.form.get("h-captcha-response"), get_remote_address()):
            flash("CAPTCHA verification failed. Please try again.", "danger")
            return render_template("resend_verification.html", resend_form=resend_form, captcha_required=True, hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"])
        session.pop("captcha_required", None)

    email = resend_form.email.data.lower().strip()
    user = db.session.scalar(db.select(User).where(User.email == email))

    flash("If an account exists with this email, a verification link has been sent.", "info")

    if user:
        token = generate_email_token(user.id, now)
        verify_url = url_for("verify_email", token=token, _external=True)
        # --- FAIL-SAFE: Generate Common Links for Emails ---
        privacy_url = url_for('legal', page_name='privacy', _external=True)
        support_url = url_for('contact', _external=True)

        socketio.start_background_task(
            send_email, 
            user.email, 
            "Verify your email", 
            render_template(
                "email/verify.html", 
                verify_url=verify_url, 
                user=user,
                privacy_url=privacy_url, # Passed here
                support_url=support_url  # Passed here
            )
        )
        with safe_commit():
            user.verification_sent_at = now

    session.pop("captcha_required", None)
    return redirect(url_for("resend_verification_get"))


@app.route("/request-reset", methods=["GET"])
def request_reset_get():
    form = RequestResetForm()
    return render_template("request_reset.html", form=form, captcha_required=(app.config["CAPTCHA_ENABLED"] and session.get("captcha_required")), hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"])

@app.route("/request-reset", methods=["POST"])
@limiter.limit(RATE_LIMIT_EMAIL_GLOBAL, key_func=get_remote_address, exempt_when=match_captcha_bypass)
@limiter.limit(RATE_LIMIT_EMAIL_SPECIFIC, key_func=email_rate_limit_key, exempt_when=match_captcha_bypass)
def request_reset_post():
    form = RequestResetForm()
    now = datetime.now(timezone.utc).replace(microsecond=0)

    if not form.validate_on_submit():
        return render_template("request_reset.html", form=form, captcha_required=(app.config["CAPTCHA_ENABLED"] and session.get("captcha_required")), hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"])

    if app.config["CAPTCHA_ENABLED"] and session.get("captcha_required"):
        if not verify_hcaptcha(request.form.get("h-captcha-response"), get_remote_address()):
            flash("CAPTCHA verification failed. Please try again.", "danger")
            return render_template("request_reset.html", form=form, captcha_required=True, hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"])
        session.pop("captcha_required", None)

    email = form.email.data.lower().strip()
    user = db.session.scalar(db.select(User).where(User.email == email))

    flash("If an account exists, a password reset link has been sent.", "info")

    if user:
        token = generate_password_reset_token(user.id, now)
        reset_url = url_for("reset_password", token=token, _external=True)
        # --- FAIL-SAFE: Generate Common Links for Emails ---
        privacy_url = url_for('legal', page_name='privacy', _external=True)
        support_url = url_for('contact', _external=True)

        html_body = render_template(
            "email/reset_password.html", 
            reset_url=reset_url, 
            user=user,
            privacy_url=privacy_url, # Passed here
            support_url=support_url  # Passed here
        )
        
        socketio.start_background_task(send_email, user.email, "Reset your password", html_body)
        
        with safe_commit():
            user.reset_password_sent_at = now

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

    token_issued_at = datetime.fromtimestamp(data["iat"], tz=timezone.utc)
    if user.reset_password_sent_at and token_issued_at < user.reset_password_sent_at:
        flash("This reset link has been replaced by a newer one.", "danger")
        return redirect(url_for("request_reset_get"))

    form = ResetPasswordForm()
    form.email.data = user.email

    if form.validate_on_submit():
        with safe_commit():
            user.password = generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=16)
            user.reset_password_sent_at = None
            
        logout_user()
        session.clear()
        flash("Password reset successful. Please log in again.", "success")
        return redirect(url_for("login_get"))

    return render_template("reset_password.html", form=form)


@app.route("/login", methods=["GET"])
def login_get():
    form = LoginForm()
    return render_template("login.html", login_form=form, captcha_required=(app.config["CAPTCHA_ENABLED"] and session.get("captcha_required")), hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"])

@app.route("/login", methods=["POST"])
@limiter.limit(RATE_LIMIT_LOGIN_GLOBAL, key_func=get_remote_address, exempt_when=match_captcha_bypass)
@limiter.limit(RATE_LIMIT_LOGIN_SPECIFIC, key_func=login_rate_limit_key, exempt_when=match_captcha_bypass)
def login_post():
    form = LoginForm()
    
    def render_login_failure():
        return render_template("login.html", login_form=form, captcha_required=(app.config["CAPTCHA_ENABLED"] and session.get("captcha_required")), hcaptcha_site_key=app.config["HCAPTCHA_SITE_KEY"])

    if not form.validate_on_submit():
        return render_login_failure()

    if app.config["CAPTCHA_ENABLED"] and session.get("captcha_required"):
        token = request.form.get("h-captcha-response")
        if not verify_hcaptcha(token, get_remote_address()):
            flash("CAPTCHA verification failed. Please try again.", "danger")
            return render_login_failure()
        session.pop("captcha_required", None)

    email = form.email.data.lower().strip()
    password = form.password.data
    user = db.session.scalar(db.select(User).where(User.email == email))

    valid_password = False
    if user:
        valid_password = check_password_hash(user.password, password)
    else:
        # Dummy check to mitigate timing attacks
        check_password_hash(DUMMY_PASSWORD_HASH, password)

    if not user or not valid_password:
        if user:
            with safe_commit():
                user.failed_login_count += 1
                logger.info(f"Failed login for {email}. Count: {user.failed_login_count}")
                if user.failed_login_count >= MAX_LOGIN_ATTEMPTS:
                    user.failed_login_count = 0
                    session["captcha_required"] = True
                    logger.warning(f"CAPTCHA escalation triggered for {email}")
        
        flash("Invalid email or password.", "danger")
        return render_login_failure()

    with safe_commit():
        user.failed_login_count = 0
    
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
# 11. BLOG ROUTES
# -------------------------------------------------------------------

# ==============================================================================
# SEARCH ROUTE (Advanced Filtering & Context-Aware Rendering)
# ==============================================================================
@app.route("/search")
def search():
    """
    Handles complex search queries with multiple filters.
    - Scope: 'me' (current user), specific username, or empty (global).
    - Text: Matches title, subtitle, body, or author name.
    - Date: Filters by Year, Month, Day.
    - Sort: Newest or Oldest.
    
    Returns:
    - profile.html: If searching within a specific user's scope.
    - index.html: If searching globally.
    """
    # 1. Retrieve & Sanitize Parameters
    query = request.args.get("q", "").strip()
    sort_order = request.args.get("sort", "newest")
    scope = request.args.get("scope", "").strip()
    f_year = request.args.get("year", "")
    f_month = request.args.get("month", "")
    f_day = request.args.get("day", "")

    # 2. Fast Exit: If no filters are active, return to Home
    active_filters = [query,sort_order, scope, f_year, f_month, f_day]
    if not any(f for f in active_filters if f):
        return redirect(url_for("get_all_posts"))

    # 3. Build Base Query
    stmt = db.select(BlogPost).join(User)
    msg_parts = []
    
    # We track 'profile_user' to decide which template to render later
    profile_user = None 

    # 4. Apply Scope Filtering
    if scope:
        if scope == "me" and current_user.is_authenticated:
            # Case A: My Posts
            stmt = stmt.where(BlogPost.author_id == current_user.id)
            msg_parts.append("in my posts")
            profile_user = current_user # We want to stay on My Profile
        elif scope != "me":
            # Case B: Specific User Posts
            target_user = db.session.scalar(db.select(User).where(User.username == scope))
            if target_user:
                stmt = stmt.where(BlogPost.author_id == target_user.id)
                msg_parts.append(f"in @{target_user.username}'s posts")
                profile_user = target_user # We want to stay on Target User's Profile

    # 5. Apply Date Filtering
    if f_year:
        stmt = stmt.where(extract('year', BlogPost.date) == f_year)
    if f_month:
        stmt = stmt.where(extract('month', BlogPost.date) == f_month)
    if f_day:
        stmt = stmt.where(extract('day', BlogPost.date) == f_day)

    # 6. Generate Date Message
    if f_year or f_month or f_day:
        # ... (Keep your existing Date Message logic here, it is correct) ...
        # I am omitting the lines for brevity, but paste the previous Date Logic block here.
        m_name = f_month
        if f_month:
            from calendar import month_name
            try:
                m_name = month_name[int(f_month)]
            except (ValueError, IndexError):
                pass
        
        date_str = ""
        if f_year and f_month and f_day:
            date_str = f"on {m_name} {f_day}, {f_year}"
        elif f_year and f_month:
            date_str = f"in {m_name} {f_year}"
        elif f_year:
            date_str = f"in {f_year}"
        elif f_month and f_day:
            date_str = f"on {m_name} {f_day}"
        elif f_month:
            date_str = f"in {m_name}"
            
        msg_parts.append(date_str)

    # 7. Apply Text Search
    if query:
        msg_parts.append(f"matching '{query}'")
        stmt = stmt.where(
            or_(
                BlogPost.title.ilike(f"%{query}%"),
                BlogPost.subtitle.ilike(f"%{query}%"),
                BlogPost.body.ilike(f"%{query}%"),
                User.name.ilike(f"%{query}%")
            )
        )

    # 8. Apply Sorting
    if sort_order == "oldest":
        stmt = stmt.order_by(BlogPost.date.asc())
    else:
        stmt = stmt.order_by(BlogPost.date.desc())

    # 9. Execute Query
    posts = db.session.scalars(stmt).all()
    
    # 10. Finalize Feedback Message
    search_message = "Found results " + " ".join(msg_parts) if msg_parts else "All Posts"

    # 11. SMART RENDER (The Fix)
    # If we are scoped to a user, render 'profile.html'. 
    # Otherwise, render 'index.html'.
    
    if profile_user:
        # Render Profile with results
        # Note: profile.html expects 'posts', index.html expects 'all_posts'
        return render_template(
            "profile.html", 
            user=profile_user, 
            posts=posts, 
            search_message=search_message
        )
    else:
        # Render Home with results
        return render_template(
            "index.html", 
            all_posts=posts, 
            search_message=search_message
        )

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    form = SettingsForm()
    delete_form = DeleteAccountForm()
    
    if form.validate_on_submit():
        if form.username.data != current_user.username:
            existing_user = db.session.scalar(db.select(User).where(User.username == form.username.data))
            if existing_user:
                flash("That username is already taken. Please choose another.", "warning")
                return render_template("settings.html", form=form, delete_form=delete_form)
        
        with safe_commit():
            current_user.username = form.username.data
            current_user.name = form.name.data
            current_user.about_me = form.about_me.data
            current_user.notify_on_comments = form.notify_on_comments.data
            current_user.notify_new_post = form.notify_new_post.data
            current_user.notify_post_edit = form.notify_post_edit.data
            current_user.notify_on_message = form.notify_on_message.data
            current_user.allow_dms = form.allow_dms.data 
        
        flash("Your settings have been updated successfully.", "success")
        return redirect(url_for('settings'))
    
    elif request.method == "GET":
        form.username.data = current_user.username
        form.name.data = current_user.name
        form.about_me.data = current_user.about_me
        form.notify_on_comments.data = current_user.notify_on_comments
        form.notify_new_post.data = current_user.notify_new_post
        form.notify_post_edit.data = current_user.notify_post_edit
        form.notify_on_message.data = current_user.notify_on_message
        form.allow_dms.data = current_user.allow_dms 
        
    return render_template("settings.html", form=form, delete_form=delete_form)

# @app.route("/")
# def get_all_posts():
#     posts = db.session.scalars(db.select(BlogPost).order_by(BlogPost.date.desc())).all()
#     return render_template("index.html", all_posts=posts)

# --- UPDATED HOME ROUTE (INITIAL LOAD) ---
@app.route("/")
def get_all_posts():
    # Get page from URL (default 1), load 9 posts per batch
    page = request.args.get('page', 1, type=int)
    per_page = 9
    
    # Efficient Pagination Query
    stmt = db.select(BlogPost).order_by(BlogPost.date.desc())
    pagination = db.paginate(stmt, page=page, per_page=per_page, error_out=False)
    
    # Render index.html with the first batch of items
    return render_template("index.html", 
                           all_posts=pagination.items, 
                           has_next=pagination.has_next,
                           next_page=pagination.next_num)

# --- NEW API ROUTE (INFINITE SCROLL) ---
@app.route("/posts/load")
def load_posts():
    """
    API endpoint called by JavaScript to fetch the next page of posts.
    Returns HTML fragment (the cards) to be appended to the grid.
    """
    page = request.args.get('page', 1, type=int)
    per_page = 9
    
    stmt = db.select(BlogPost).order_by(BlogPost.date.desc())
    pagination = db.paginate(stmt, page=page, per_page=per_page, error_out=False)
    
    # Return JUST the list of cards
    return render_template("_post_list.html", posts=pagination.items)

# @app.route("/user/<string:username>")
# def user_profile(username):
#     user = User.query.filter_by(username=username).first_or_404()
#     posts = BlogPost.query.filter_by(author=user).order_by(BlogPost.date.desc()).all()
    
#     can_message = False
#     if current_user.is_authenticated and current_user.id != user.id:
#         if user.allow_dms or current_user.role == "admin":
#             can_message = True
            
#     return render_template("profile.html", user=user, posts=posts, can_message=can_message)

# --- UPDATED PROFILE ROUTE (Page 1) ---
@app.route("/user/<string:username>")
def user_profile(username):
    user = db.session.scalar(db.select(User).where(User.username == username))
    if not user:
        abort(404)
    
    # Pagination Logic
    page = request.args.get('page', 1, type=int)
    per_page = 9
    
    # Filter by Author
    stmt = db.select(BlogPost).where(BlogPost.author_id == user.id).order_by(BlogPost.date.desc())
    pagination = db.paginate(stmt, page=page, per_page=per_page, error_out=False)
    
    can_message = False
    if current_user.is_authenticated and current_user.id != user.id:
        if user.allow_dms or current_user.role == "admin":
            can_message = True
            
    return render_template("profile.html", 
                           user=user, 
                           posts=pagination.items, 
                           has_next=pagination.has_next, 
                           next_page=pagination.next_num,
                           can_message=can_message)

# --- NEW API ROUTE (Profile Infinite Scroll) ---
@app.route("/user/<string:username>/load")
def load_user_posts(username):
    user = db.session.scalar(db.select(User).where(User.username == username))
    if not user:
        return "", 404
        
    page = request.args.get('page', 1, type=int)
    per_page = 9
    
    stmt = db.select(BlogPost).where(BlogPost.author_id == user.id).order_by(BlogPost.date.desc())
    pagination = db.paginate(stmt, page=page, per_page=per_page, error_out=False)
    
    # Reuse the same partial template!
    return render_template("_post_list.html", posts=pagination.items)

@app.route("/my-posts")
@login_required
def get_user_posts():
    posts = db.session.scalars(
        db.select(BlogPost)
        .where(BlogPost.author_id == current_user.id)
        .order_by(BlogPost.date.desc())
    ).all()
    return render_template("index.html", all_posts=posts, page_title="My Posts")

@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    post = db.session.get(BlogPost, post_id)
    
    if not post:
        flash("That post has been deleted or does not exist.", "info")
        return redirect(url_for("get_all_posts"))
    
    # --- SMART READ: Mark Activity as Read ---
    # If a user views this post, clear any pending notifications about it.
    if current_user.is_authenticated:
        with safe_commit():
            db.session.execute(
                db.update(Notification)
                .where(
                    Notification.recipient_id == current_user.id,
                    Notification.related_post_id == post_id,
                    Notification.is_read == False
                )
                .values(is_read=True)
            )

    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login to comment.", "warning")
            return redirect(url_for("login_get"))
        
        if not current_user.email_verified:
            flash("Please verify your email first.", "warning")
            return redirect(url_for("resend_verification_get"))

        if not post.can_comment:
             flash("Comments are disabled for this post.", "comment_danger")
             return redirect(url_for("show_post", post_id=post.id))

        parent_id = form.parent_id.data
        if not parent_id or parent_id == "":
            parent_id = None
        else:
            parent_id = int(parent_id)

        # 1. SAVE COMMENT (Critical: Database Transaction)
        try:
            with safe_commit():
                new_comment = Comment(
                    text=clean_html(form.comment_text.data),
                    comment_author=current_user,
                    parent_post=post,
                    parent_id=parent_id
                )
                db.session.add(new_comment)
                # Flush happens in safe_commit
            # Comment is safely saved here.
        except Exception as e:
            logger.error(f"Database Error saving comment: {e}")
            flash("Failed to post comment. Please try again.", "comment_danger")
            return redirect(url_for("show_post", post_id=post.id))

        # 2. NOTIFICATIONS (Non-Critical: Push/Activity)
        # Wrapped in separate try/except so it doesn't crash the response
        try:
            # --- SMART NOTIFICATIONS (Push + Email) ---
            post_url = url_for('show_post', post_id=post.id,comment_id=new_comment.id, _anchor=f"comment-{new_comment.id}", _external=True)
            notification_queue = {}
            
            # 1. Notify Post Author
            if post.author.notify_on_comments and post.author.id != current_user.id:
                # A. Send Push/Activity
                socketio.start_background_task(
                    send_notification_async,
                    post.author.id,
                    f"New comment on: {post.title}",
                    f"{current_user.name}: {new_comment.text[:60]}...", 
                    post_url,
                    "comment",
                    related_post_id=post.id,
                    related_comment_id=new_comment.id,
                    icon_url=get_gravatar_url(current_user.email)
                )
                
            # 2. Notify Parent Commenter (Reply Logic)
            if parent_id:
                parent_comment = db.session.get(Comment, parent_id)
                if parent_comment and parent_comment.comment_author.notify_on_comments:
                    target_user = parent_comment.comment_author
                    
                    if target_user.id != current_user.id and target_user.id != post.author.id:
                        # A. Send Push/Activity
                        socketio.start_background_task(
                            send_notification_async,
                            target_user.id,
                            f"{current_user.name} replied to you",
                            f"{new_comment.text[:60]}...",
                            post_url,
                            "comment",
                            related_post_id=post.id,
                            related_comment_id=new_comment.id,
                            icon_url=get_gravatar_url(current_user.email)
                        )

        except Exception as e:
            # Log error but do not disrupt the user
            logger.error(f"Notification Error for comment {new_comment.id}: {e}")

        flash("Comment Posted", "comment_success")
        return redirect(url_for("show_post", post_id=post.id,comment_id=new_comment.id, _anchor=f"comment-{new_comment.id}"))
    # =========================================================
    # NEW LOGIC: COMMENT PAGINATION & DEEP LINKING
    # =========================================================
    per_page = 10
    page = request.args.get('page', 1, type=int)
    
    # Check if a specific comment was requested (Deep Link)
    target_comment_id = request.args.get('comment_id', type=int)
    
    if target_comment_id:
        target_comment = db.session.get(Comment, target_comment_id)
        # Verify comment belongs to this post
        # --- 1. EDGE CASE: Comment Deleted ---
        if not target_comment:
            # This is the Flash Message you asked about
            flash("The comment you are looking for has been deleted.", "warning")
            
        # --- 2. EDGE CASE: Wrong Post (Security) ---
        elif target_comment.post_id != post.id:
            flash("That comment belongs to a different post.", "warning")
            
        # --- 3. HAPPY PATH: Comment Exists ---
        else:
            # Find the root parent (pagination is based on top-level comments)
            root_comment = target_comment
            while root_comment.parent_id is not None:
                # Defensive check for orphan replies
                if root_comment.parent is None:
                    break 
                root_comment = root_comment.parent
            
            # Calculate how many comments are NEWER than this one
            newer_comments_count = db.session.scalar(
                db.select(func.count(Comment.id))
                .where(
                    Comment.post_id == post.id,
                    Comment.parent_id == None,
                    Comment.timestamp > root_comment.timestamp
                )
            )
            # Determine the correct page number
            page = (newer_comments_count // per_page) + 1

    # Fetch Top-Level Comments (Newest First)
    stmt = db.select(Comment).where(
        Comment.post_id == post.id, 
        Comment.parent_id == None
    ).order_by(Comment.timestamp.desc())
    
    pagination = db.paginate(stmt, page=page, per_page=per_page, error_out=False)
    return render_template("post.html", post=post, form=form, comments_pagination=pagination)

@app.route("/post/<int:post_id>/load-comments")
def load_more_comments(post_id):
    post = db.get_or_404(BlogPost, post_id)
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    stmt = db.select(Comment).where(
        Comment.post_id == post.id, 
        Comment.parent_id == None
    ).order_by(Comment.timestamp.desc())
    
    pagination = db.paginate(stmt, page=page, per_page=per_page, error_out=False)
    
    # Make sure you created 'templates/_comment_list.html' as discussed!
    return render_template("_comment_list.html", comments=pagination.items, current_user=current_user, post=post)

@app.route("/new-post", methods=["GET", "POST"])
@login_required 
def add_new_post():
    form = CreatePostForm()
    
    if form.validate_on_submit():
        # 1. DUPLICATE CHECK (Case-Insensitive)
        # Prevents database "UniqueViolation" crashes
        existing_post = db.session.scalar(
            db.select(BlogPost).where(BlogPost.title.ilike(form.title.data))
        )
        
        if existing_post:
            flash("A post with this title already exists. Please choose a different title.", "warning")
            # This will now show up because we fixed make-post.html!
            return render_template("make-post.html", form=form)

        # 2. SAVE POST (Database Transaction)
        # We isolate the DB save so we know exactly when the post is safe.
        try:
            with safe_commit():
                post = BlogPost(
                    title=form.title.data,
                    subtitle=form.subtitle.data,
                    body=clean_html(form.body.data),
                    img_url=form.img_url.data,
                    author=current_user,
                    can_comment=form.can_comment.data
                )
                db.session.add(post)
                # Flush ensures post.id is available
            # Post is safely saved here (Commit happened in safe_commit)
        
        except Exception as e:
            # If the database fails, we must stop everything and alert the user.
            logger.error(f"Database Error during post creation: {e}")
            flash("Failed to create post. Please try again.", "danger")
            return render_template("make-post.html", form=form)

        # 3. NOTIFICATIONS (Web Push & Digest Log)
        # Wrapped in a separate try/except block.
        # If this fails, the post is still saved, so we do NOT show an error to the user.
        try:
            subscribers = db.session.scalars(db.select(User).where(User.notify_new_post == True)).all()
            
            if subscribers:
                post_url = url_for('show_post', post_id=post.id, _anchor='post-content', _external=True)
                
                for sub in subscribers:
                    if sub.id != current_user.id:
                        # 1. Push
                        socketio.start_background_task(
                            send_notification_async,
                            sub.id,
                            f"New Post: {post.title}",
                            f"{current_user.name} published a new story.", # Plain text for Web Push
                            post_url,
                            "post",
                            related_post_id=post.id,
                            icon_url=get_gravatar_url(current_user.email),
                            image_url=post.img_url
                        )
        except Exception as e:
            # Log the error internally but allow the request to succeed
            logger.error(f"Notification Error for post {post.id}: {e}")

        # --- UPDATE: Success Logic for Animation & Scroll ---
        
        # 1. Flash 'success' category triggers the JS animation in index.html
        flash("New post published successfully!", "success")
        
        # 2. Add _anchor to scroll to the specific post ID
        return redirect(url_for("get_all_posts", _anchor=f"post-{post.id}"))
        
    return render_template("make-post.html", form=form)

@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required 
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    
    if current_user.id != post.author_id:
        abort(403) 

    form = CreatePostForm(obj=post)
    
    if form.validate_on_submit():
        # 1. DUPLICATE CHECK (Excluding current post)
        existing_post = db.session.scalar(
            db.select(BlogPost).where(
                BlogPost.title.ilike(form.title.data),
                BlogPost.id != post_id 
            )
        )
        
        if existing_post:
            flash("A post with this title already exists. Please choose a different title.", "warning")
            return render_template("make-post.html", form=form, is_edit=True)

        # 2. SAVE CHANGES (Database Transaction)
        try:
            with safe_commit():
                form.populate_obj(post)
                post.body = clean_html(form.body.data)
            # Changes safely saved
        
        except Exception as e:
            logger.error(f"Database Error during post edit: {e}")
            flash("Failed to update post.", "danger")
            return render_template("make-post.html", form=form, is_edit=True)
            
        # 3. NOTIFICATIONS (Web Push & Digest Log)
        try:
            subscribers = db.session.scalars(db.select(User).where(User.notify_post_edit == True)).all()
            
            if subscribers:
                post_url = url_for('show_post', post_id=post.id, _anchor='post-content', _external=True)
                
                for sub in subscribers:
                    if sub.id != current_user.id:
                        # 1. Push
                        socketio.start_background_task(
                            send_notification_async,
                            sub.id,
                            f"Update: {post.title}",
                            f"{current_user.name} updated this post.",
                            post_url,
                            "edit",
                            related_post_id=post.id,
                            icon_url=get_gravatar_url(current_user.email),
                            image_url=post.img_url
                        )
        except Exception as e:
            logger.error(f"Notification Error for post {post.id}: {e}")

        flash("Updated post successfully!", "success")
        return redirect(url_for("show_post", post_id=post.id))
        
    return render_template("make-post.html", form=form, is_edit=True)

@app.route("/delete/<int:post_id>", methods=["POST", "GET"])
@login_required 
def delete_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    target_username = post.author.username
    if current_user.id == post.author_id:
        with safe_commit():
            db.session.delete(post)
        flash("Post deleted.", "info")
        return redirect(url_for("user_profile", username=target_username))
    elif current_user.role == "admin":
        return redirect(url_for("admin_delete_post", post_id=post.id))
    else:
        abort(403)

@app.route("/admin-delete/<int:post_id>", methods=["GET", "POST"])
@admin_only
def admin_delete_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    target_username = post.author.username
    form = DeleteReasonForm()

    if form.validate_on_submit():
        try:
            reason = form.reason.data
            subject = f"Your post '{post.title}' has been removed"
            
            # --- FAIL-SAFE: Generate Common Links for Emails ---
            guidelines_url = url_for('legal', page_name='guidelines', _external=True)
            terms_url = url_for('legal', page_name='terms', _external=True)
            support_url = url_for('contact', _external=True)

            html_body = render_template(
                "email/post_deleted.html", 
                user=post.author, 
                post_title=post.title, 
                reason=reason,
                guidelines_url=guidelines_url, # Passed here
                terms_url=terms_url,           # Passed here
                support_url=support_url        # Passed here
            )
            
            # Send Email
            socketio.start_background_task(send_email, post.author.email, subject, html_body)
            
            with safe_commit():
                db.session.delete(post)
            
            flash("Post deleted and user notified.", "success")
            return redirect(url_for("user_profile", username=target_username))
        except Exception:
            flash("Error deleting post.", "danger")

    return render_template("admin_delete_post.html", form=form, post=post)

@app.route("/admin-warn/<int:post_id>", methods=["GET", "POST"])
@admin_only
def warn_post_author(post_id):
    post = db.get_or_404(BlogPost, post_id)
    target_username = post.author.username
    form = WarnUserForm()

    if form.validate_on_submit():
        warning_message = form.message.data
        subject = f"Warning regarding your post: '{post.title}'"
        
        # --- FAIL-SAFE: Generate Common Links for Emails ---
        guidelines_url = url_for('legal', page_name='guidelines', _external=True)
        terms_url = url_for('legal', page_name='terms', _external=True)
        support_url = url_for('contact', _external=True)

        html_body = render_template(
            "email/warning_notification.html", 
            user=post.author, 
            post_title=post.title, 
            message=warning_message,
            guidelines_url=guidelines_url, # Passed here
            terms_url=terms_url,           # Passed here
            support_url=support_url        # Passed here
        )
        
        socketio.start_background_task(send_email, post.author.email, subject, html_body)
        flash(f"Warning sent to {post.author.name}.", "success")
        return redirect(url_for("user_profile", username=target_username))

    return render_template("admin_warn_author.html", form=form, post=post, page_title="Warn User")

@app.route("/delete-comment/<int:comment_id>", methods=["POST"])
@login_required
def delete_comment(comment_id):
    comment_to_delete = db.get_or_404(Comment, comment_id)
    post_id = comment_to_delete.post_id
    
    if comment_to_delete.comment_author.id == current_user.id or current_user.role == "admin":
        with safe_commit():
            db.session.delete(comment_to_delete)
        return redirect(url_for('show_post', post_id=post_id, _anchor='comment-form-section'))
    else:
        flash("You are not authorized to delete this comment.")
        return redirect(url_for('show_post', post_id=post_id, _anchor='comment-form-section'))

@app.route("/contact", methods=["GET", "POST"])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        try:
            html_body = render_template("email/contact_message.html", name=form.name.data, email=form.email.data, phone=form.phone.data, message=form.message.data)
            send_email(to=os.environ["CONTACT_RECEIVER_EMAIL"], subject="New Contact Form Message", html_body=html_body, reply_to=form.email.data)
            flash("Your message has been sent successfully!", "success")
            return redirect(url_for('contact'))
        except Exception:
            logger.exception("Contact email failed")
            flash("Failed to send message. Please try again later.", "danger")
    
    return render_template("contact.html", form=form)

# -------------------------------------------------------------------
# 12. MESSAGING SYSTEM ROUTES
# -------------------------------------------------------------------

# -------------------------------------------------------------------
# CONTEXT PROCESSORS (Global Variables for Templates)
# -------------------------------------------------------------------

@app.context_processor
def inject_global_vars():
    """
    Injects variables available to ALL templates automatically.
    1. current_year: For footers and copyrights.
    2. unread_count: For the navbar messaging badge.
    """
    # Default values
    vars = {
        'current_year': datetime.now(timezone.utc).year,
        'unread_count': 0
    }

    # Add user-specific data if logged in
    if current_user.is_authenticated:
        vars['unread_count'] = current_user.new_messages()
    
    return vars

@app.route("/subscribe", methods=["POST"])
def subscribe():
    if not current_user.is_authenticated:
        return "Unauthorized", 401

    try:
        subscription_json = json.dumps(request.json)
        existing = db.session.scalar(
            db.select(PushSubscription).where(
                PushSubscription.user_id == current_user.id, 
                PushSubscription.subscription_json == subscription_json
            )
        )

        if not existing:
            with safe_commit():
                new_sub = PushSubscription(user_id=current_user.id, subscription_json=subscription_json)
                db.session.add(new_sub)
            return "Subscribed", 201
        
        return "Already Subscribed", 200
    except Exception as e:
        logger.error(f"Subscription failed: {e}")
        return "Error", 500

@app.route('/sw.js')
def service_worker():
    response = send_from_directory('static', 'sw.js')
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Expires'] = '0'
    return response

@app.route('/inbox')
@login_required
def inbox():
    stmt = db.select(Message).where(
        or_(Message.sender_id == current_user.id, Message.recipient_id == current_user.id)
    ).order_by(Message.timestamp.desc())
    
    messages = db.session.scalars(stmt).all()
    conversations = {}
    
    for msg in messages:
        if msg.sender_id == current_user.id:
            partner = msg.recipient
        else:
            partner = msg.sender
            
        if partner.id not in conversations:
            conversations[partner.id] = {'user': partner, 'last_message': msg, 'unread_count': 0}
            
        if msg.recipient_id == current_user.id and not msg.is_read:
            conversations[partner.id]['unread_count'] += 1

    return render_template('inbox.html', conversations=conversations, current_date=datetime.now(timezone.utc).date())

@app.route('/chat/<int:user_id>', methods=['GET', 'POST'])
@login_required
def chat(user_id):
    recipient = db.session.get(User, user_id)
    if not recipient: abort(404)
    
    if recipient.id == current_user.id:
        flash("You cannot chat with yourself.", "warning")
        return redirect(url_for('user_profile', username=current_user.username))

    can_message = recipient.allow_dms or current_user.role == "admin" or recipient.role == "admin"
    # if not can_message:
    #     flash("This user does not accept private messages.", "warning")
    #     return redirect(url_for('user_profile', username=recipient.username))

    form = MessageForm()
    
    # FALLBACK: Handle Message Sending via HTTP (No JS)
    if form.validate_on_submit():
        if not can_message:
            flash("This user does not accept private messages.", "danger")
        else:
            with safe_commit():
                msg = Message(sender=current_user, recipient=recipient, body=form.message.data)
                db.session.add(msg)
            return redirect(url_for('chat', user_id=user_id))
    
    # Load History & Mark Read
    history_stmt = db.select(Message).where(
        or_(
            and_(Message.sender_id == current_user.id, Message.recipient_id == user_id),
            and_(Message.sender_id == user_id, Message.recipient_id == current_user.id)
        )
    ).order_by(Message.timestamp.asc())
    
    history = db.session.scalars(history_stmt).all()
    
    unread_updates = False
    for msg in history:
        if msg.recipient_id == current_user.id and not msg.is_read:
            msg.is_read = True
            unread_updates = True
            
    if unread_updates:
        with safe_commit():
            pass # Commit handled by context manager
        socketio.emit('messages_read_update', {
            'reader_id': current_user.id, 
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, room=f"user_{user_id}")

    return render_template('chat.html', form=form, recipient=recipient, history=history, can_message=can_message)

@app.route('/message/delete/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    msg = db.session.get(Message, message_id)
    if msg:
        if msg.sender_id == current_user.id or current_user.role == "admin":
            with safe_commit():
                db.session.delete(msg)
        else:
            flash("You cannot delete this message.", "danger")
    return redirect(request.referrer or url_for('inbox'))

# main.py (Update/Add these routes)

# 1. USER SELF-DELETE (Does NOT Ban email)
@app.route("/delete-account", methods=["POST"])
@login_required
def delete_account():
    form = DeleteAccountForm()
    
    # 1. SECURITY: Validate Form & Password
    if form.validate_on_submit():
        if not check_password_hash(current_user.password, form.password.data):
            flash("Incorrect password. Account deletion canceled.", "danger")
            return redirect(url_for('settings'))

        try:
            original_email = current_user.email
            original_name = current_user.name

            # 2. LOGGING: Create the permanent record
            deletion_log = DeletedAccountLog(
                original_email=original_email,
                original_username=current_user.username,
                user_id=current_user.id,
                reason=form.reason.data,
                ip_address=get_remote_address() # Captures IP for security audit
            )
            
            with safe_commit():
                db.session.add(deletion_log)
                
                # 3. GHOST PROTOCOL: Anonymize the live user data
                anonymize_user_data(current_user)
            
            # 4. NOTIFICATION: Send Goodbye Email (Async)
            # Do this BEFORE logging out, but use the `original_email` variable
            try:
                home_url = url_for('get_all_posts', _external=True)
                support_url = url_for('contact', _external=True)

                html_body = render_template("email/goodbye.html", name=original_name, home_url=home_url, support_url=support_url)
                socketio.start_background_task(
                    send_email, 
                    original_email, 
                    "Your account has been deleted", 
                    html_body
                )
            except Exception as e:
                logger.error(f"Failed to send goodbye email: {e}")

            logout_user()
            session.clear()
            flash("Your account has been successfully deleted.", "success")
            return redirect(url_for('get_all_posts'))

        except Exception as e:
            logger.error(f"Account deletion failed: {e}")
            flash("An error occurred while deleting your account.", "danger")
            return redirect(url_for('settings'))
            
    # If form validation fails (e.g. empty password field submitted via tool)
    flash("Please confirm your password to delete your account.", "warning")
    return redirect(url_for('settings'))


# @app.route("/delete-account", methods=["POST"])
# @login_required
# def delete_account():
#     try:
#         with safe_commit():
#             anonymize_user_data(current_user)
#             # We do NOT add to BannedUser here, allowing them to return later if they wish.
            
#         logout_user()
#         session.clear()
#         flash("Your account has been deleted. We are sad to see you go.", "success")
#         return redirect(url_for('get_all_posts'))

#     except Exception as e:
#         logger.error(f"Account deletion failed: {e}")
#         flash("An error occurred while deleting your account.", "danger")
#         return redirect(url_for('settings'))


# 2. ADMIN FORCE-DELETE (BANS email)
@app.route("/admin/delete-user/<int:user_id>", methods=["GET", "POST"])
@admin_only
def admin_delete_user(user_id):
    user_to_delete = db.get_or_404(User, user_id)
    
    # Safety: Admin cannot delete themselves or other admins via this route
    if user_to_delete.role == "admin":
        flash("You cannot ban an administrator.", "warning")
        return redirect(url_for('user_profile', username=user_to_delete.username))
 
    form = AdminDeleteUserForm()

    if form.validate_on_submit():
        try:
            original_email = user_to_delete.email
            reason = form.reason.data
            
            # A. Send Termination Email (Before anonymizing so we have the email)
            support_url = url_for('contact', _external=True)
            guidelines_url = url_for('legal', page_name='guidelines', _external=True)
            
            html_body = render_template(
                "email/account_terminated.html",
                user=user_to_delete,
                reason=reason,
                support_url=support_url,
                guidelines_url=guidelines_url
            )
            
            socketio.start_background_task(
                send_email, 
                original_email, 
                "Important: Your account has been terminated", 
                html_body
            )

            with safe_commit():
                # B. Add to Ban List
                ban_entry = BannedUser(
                    email=original_email,
                    reason=reason,
                    banned_by=current_user.username
                )
                db.session.add(ban_entry)
                
                # C. Anonymize User Data (Ghost Protocol)
                anonymize_user_data(user_to_delete)
            
            flash(f"User {original_email} has been banned and data anonymized.", "success")
            return redirect(url_for('get_all_posts'))
            
        except Exception as e:
            logger.error(f"Failed to ban user: {e}")
            flash("Error banning user.", "danger")

    return render_template("admin_delete_user.html", form=form, user=user_to_delete)

# -------------------------------------------------------------------
# 13. REAL-TIME SOCKET EVENTS
# -------------------------------------------------------------------

@socketio.on('connect')
def handle_connect():
    if not current_user.is_authenticated:
        return False
    join_room(f"user_{current_user.id}")

@socketio.on('send_message')
def handle_socket_message(data):
    if not current_user.is_authenticated: return
    
    recipient_id = int(data.get('recipient_id'))
    body = data.get('body', '').strip()
    
    if not body: return

    recipient = db.session.get(User, recipient_id)

    # --- NEW SECURITY CHECK ---
    can_message = recipient.allow_dms or current_user.role == "admin" or recipient.role == "admin"
    if not can_message:
        return # Silently fail or emit an error event

    if recipient:
        try:
            # 1. Database Save
            with safe_commit():
                msg = Message(sender=current_user, recipient=recipient, body=body)
                db.session.add(msg)
                # Flush to get msg.timestamp if needed, handled by commit

            # 2. Real-time Socket Emits
            socketio.emit('new_message', {
                'sender_id': current_user.id,
                'body': msg.body,
                'timestamp': msg.timestamp.isoformat(),
                'avatar': current_user.email 
            }, room=f"user_{recipient_id}")
            
            emit('message_sent_confirmation', {
                'temp_id': data.get('temp_id'),
                'status': 'success',
                'timestamp': msg.timestamp.isoformat()
            })

            # 3. Push Notification (Background Task)
            chat_url = url_for('chat', user_id=current_user.id, _external=True)
            
            # Use general notification system but customize logic
            socketio.start_background_task(
                send_notification_async,
                recipient.id,
                f"New message from {current_user.name}",
                msg.body,
                chat_url,
                "chat",
                icon_url=get_gravatar_url(current_user.email)
            )
        except Exception as e:
            logger.error(f"Socket message failed: {e}")

@socketio.on('typing')
def handle_typing(data):
    if data.get('recipient_id'):
        socketio.emit('display_typing', {'sender_id': current_user.id}, room=f"user_{data.get('recipient_id')}")

@socketio.on('stop_typing')
def handle_stop_typing(data):
    if data.get('recipient_id'):
        socketio.emit('hide_typing', {'sender_id': current_user.id}, room=f"user_{data.get('recipient_id')}")

@socketio.on('mark_read')
def handle_mark_read(data):
    sender_id = int(data.get('sender_id'))
    try:
        with safe_commit():
            db.session.execute(
                db.update(Message)
                .where(and_(Message.sender_id == sender_id, Message.recipient_id == current_user.id, Message.is_read == False))
                .values(is_read=True)
            )
        socketio.emit('messages_read_update', {'reader_id': current_user.id}, room=f"user_{sender_id}")
    except Exception as e:
        logger.error(f"Mark read failed: {e}")

# -------------------------------------------------------------------
# ENTRY POINT
# -------------------------------------------------------------------

if __name__ == "__main__":

    socketio.run(
        app,
        debug=(os.environ.get("ENV") != "production"),
        port=int(os.environ.get("PORT", 5002))
    )
