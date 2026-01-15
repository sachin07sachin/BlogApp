from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, TextAreaField, BooleanField, HiddenField
from wtforms.validators import DataRequired, URL, Email, Length, EqualTo, Regexp
from flask_ckeditor import CKEditorField
from utils.validators import validate_strong_password

class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    # body = CKEditorField("Blog Content", validators=[DataRequired()])
    body = TextAreaField("Blog Content", validators=[DataRequired()])
    # Default is True (checked) so comments are enabled by default
    can_comment = BooleanField(
        "Allow comments on this post",
        default="checked",
        render_kw={"class": "form-check-input"}
    )
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    email = EmailField(
        validators=[DataRequired(), Email(), Length(max=255)],
        render_kw={"class": "form-control", "placeholder": "Enter your email"}
    )
    
    # --- NEW: Username Field ---
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=4, max=30, message="Username must be between 4 and 30 characters."),
            # This Regex ensures the username is URL-safe (no spaces, no symbols like @ or !)
            Regexp(r'^\w+$', message="Username can only contain letters, numbers, or underscores.")
        ],
        render_kw={"class": "form-control", "placeholder": "Choose a unique username"}
    )

    name = StringField("Name", validators=[DataRequired(), Length(min=1, max=120)])
    
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            validate_strong_password
        ]
    )
    submit = SubmitField("Sign me up")

class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let Me In!")


class ResendVerificationForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Resend verification email")

class CommentForm(FlaskForm):
    # comment_text = CKEditorField("Comment", validators=[DataRequired()])
    comment_text = TextAreaField("Comment", validators=[DataRequired()])
    # Hidden field to store the ID of the comment being replied to
    parent_id = HiddenField()
    submit = SubmitField("Submit Comment")

class ContactForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(max=100)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    phone = StringField("Phone", validators=[DataRequired(), Length(max=20)])
    message = TextAreaField(
        "Message",
        validators=[DataRequired(), Length(min=10, max=2000)]
    )
    submit = SubmitField("Send Message")

class RequestResetForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Send Reset Link")

class ResetPasswordForm(FlaskForm):
    password = PasswordField(
        "New Password",
        validators=[
            DataRequired(),
            validate_strong_password
        ]
    )

    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords must match.")
        ]
    )

    # 🔐 Hidden field used only for validation
    email = StringField()

    submit = SubmitField("Reset Password")

class DeleteReasonForm(FlaskForm):
    reason = TextAreaField("Reason for deletion", validators=[DataRequired()])
    submit = SubmitField("Delete Post & Notify User")

class WarnUserForm(FlaskForm):
    message = TextAreaField("Warning Message", validators=[DataRequired()])
    submit = SubmitField("Send Warning Email")

class MessageForm(FlaskForm):
    message = TextAreaField(
        'Message', 
        validators=[DataRequired(), Length(min=1, max=1000)],
        render_kw={"rows": 5, "placeholder": "Write your private message here..."}
    )
    submit = SubmitField('Send Message')

class SettingsForm(FlaskForm):
    # --- IDENTITY ---
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=4, max=30, message="Username must be between 4 and 30 characters."),
            Regexp(r'^\w+$', message="Username can only contain letters, numbers, or underscores.")
        ],
        render_kw={"class": "form-control", "placeholder": "Update your handle"}
    )
    
    name = StringField(
        "Display Name", 
        validators=[
            DataRequired(), 
            Length(min=1, max=50, message="Name must be under 50 characters.")
        ],
        render_kw={"class": "form-control", "placeholder": "Update your display name"}
    )
    
    about_me = TextAreaField(
        "About Me", 
        validators=[Length(max=500, message="Bio must be under 500 characters.")],
        render_kw={"class": "form-control", "rows": 4, "placeholder": "Tell us a little about yourself..."}
    )
    
    # --- NOTIFICATIONS ---
    
    # Toggle 1: Engagement (Covers both Authors and Commenters)
    notify_on_comments = BooleanField(
        "Email me when someone comments on my posts or replies to my comments",
        render_kw={"class": "form-check-input"} 
    )
    
    # Toggle 2: Newsletter
    notify_new_post = BooleanField(
        "Email me when a new blog post is published",
        render_kw={"class": "form-check-input"}
    )
    
    # Toggle 3: Updates
    notify_post_edit = BooleanField(
        "Email me when a post is updated/edited",
        render_kw={"class": "form-check-input"}
    )
    
    # Toggle 4: DMs
    allow_dms = BooleanField(
        "Allow other users to send me private messages",
        description="Admins can always message you regardless of this setting.",
        render_kw={"class": "form-check-input"}
    )
    
    submit = SubmitField("Save Changes")
