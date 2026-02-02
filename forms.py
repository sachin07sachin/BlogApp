from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, TextAreaField, BooleanField, HiddenField, SelectField
from wtforms.validators import DataRequired, URL, Email, Length, EqualTo, Regexp
from flask_ckeditor import CKEditorField
from utils.validators import validate_strong_password

class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired(), Length(max=250, message="Title cannot exceed 250 characters.")])
    subtitle = StringField("Subtitle", validators=[DataRequired(), Length(max=250, message="Subtitle cannot exceed 250 characters.")])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL(), Length(max=500, message="Image URL is too long.")])
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

    name = StringField("Name", validators=[DataRequired(), Length(max=120, message="Name cannot exceed 120 characters.")])
    
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            validate_strong_password
        ]
    )
    # --- NEW: Mandatory Legal Agreement ---
    # The DataRequired validator ensures the form CANNOT be submitted unless this is checked.
    agree_terms = BooleanField(
        "Agree to Terms", 
        validators=[DataRequired(message="You must agree to the Terms of Service and Privacy Policy to register.")]
    )
    submit = SubmitField("Sign me up")

class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired(), Email()])
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
    name = StringField("Name", validators=[DataRequired(), Length(max=120, message="Name cannot exceed 120 characters.")])
    email = StringField("Email", validators=[DataRequired(), Email()])
    phone = StringField("Phone", validators=[DataRequired(), Length(max=20)])
    message = TextAreaField(
        "Message",
        validators=[DataRequired(), Length(min=10, max=2000, message="Message must be between 10 and 2000 characters.")]
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
    reason = TextAreaField("Reason for deletion", validators=[DataRequired(), Length(max=1000, message="Reason cannot exceed 1000 characters.")])
    submit = SubmitField("Delete Post & Notify User")

class WarnUserForm(FlaskForm):
    message = TextAreaField("Warning Message", validators=[DataRequired(), Length(max=2000, message="Warning message cannot exceed 2000 characters.")])
    submit = SubmitField("Send Warning Email")

class DeleteAccountForm(FlaskForm):
    password = PasswordField(
        "Confirm Password", 
        validators=[DataRequired()],
        render_kw={"placeholder": "Enter your password to confirm"}
    )
    reason = SelectField(
        "Why are you leaving?",
        choices=[
            ('privacy', 'Privacy concerns'),
            ('usability', 'Too difficult to use'),
            ('content', 'Not enough content'),
            ('fresh_start', 'Want a fresh start'),
            ('other', 'Other')
        ],
        validators=[DataRequired()]
    )
    submit = SubmitField("Permanently Delete Account")

class AdminDeleteUserForm(FlaskForm):
    reason = TextAreaField(
        "Reason for termination", 
        validators=[DataRequired(), Length(max=1000, message="Reason cannot exceed 1000 characters.")]
    )
    submit = SubmitField("Permanently Ban User")

class MessageForm(FlaskForm):
    message = TextAreaField(
        'Message', 
        validators=[DataRequired(), Length(max=1000, message="Message cannot exceed 1000 characters.")],
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
            Length(max=50, message="Name cannot exceed 50 characters.")
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
        "Notify me when someone comments on my posts or replies to my comments",
        render_kw={"class": "form-check-input"} 
    )
    
    # Toggle 2: Newsletter
    notify_new_post = BooleanField(
        "Notify me when a new blog post is published",
        render_kw={"class": "form-check-input"}
    )
    
    # Toggle 3: Updates
    notify_post_edit = BooleanField(
        "Notify me when a post is updated/edited",
        render_kw={"class": "form-check-input"}
    )

    # Toggle 4: Direct Messages (Notification)
    notify_on_message = BooleanField(
        "Notify me when I receive a new private message",
        render_kw={"class": "form-check-input"}
    )
    
    # Toggle 5: DMs
    allow_dms = BooleanField(
        "Allow other users to send me private messages",
        description="Admins can always message you regardless of this setting.",
        render_kw={"class": "form-check-input"}
    )
    
    submit = SubmitField("Save Changes")
