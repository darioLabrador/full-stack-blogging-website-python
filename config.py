# Import pre-installed
import base64
import hashlib
import logging
import os

import flask_admin.model.template
import pyotp
import secrets

# Import libraries for login
from flask_login import LoginManager, current_user
from flask_login import UserMixin
from flask_qrcode import QRcode
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import MetaData
from datetime import datetime
from flask import Flask, url_for
from werkzeug.utils import redirect

# Import libraries for security
from functools import wraps
from logging import WARNING
from flask_talisman import Talisman
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from argon2 import PasswordHasher
from flask_limiter import Limiter
from flask import flash, render_template, request
from flask_limiter.util import get_remote_address

# Import Admin
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink

# Load to env
load_dotenv('data.env')

# Set app
app = Flask(__name__)

# SECRET KEY FOR FLASK FORMS
app.config['SECRET_KEY'] = os.getenv('HEX')

# DATABASE CONFIGURATION
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_ECHO=True'] = os.getenv('SQLALCHEMY_ECHO=True')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS=False'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS=False')

# CAPTCHA CONFIGURATION
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LdgyVUqAAAAAOlpHkzRlx7dr2F0SYp3QTp5Mo96'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LdgyVUqAAAAANmq8UrWlHqa4taLr7ZR8nJWh_Pd'

# Make Admin view wider
app.config['FLASK_ADMIN_FLUID_LAYOUT'] = True

# METADATA
metadata = MetaData(
    naming_convention={
        "ix": 'ix_%(column_0_label)s',
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s"
    }
)
db = SQLAlchemy(app, metadata=metadata)

# Set Migrate function
migrate = Migrate(app, db)

# Content Security Policy Initialization
csp = {'default-src': ['self', '\'self\''],
       'img-src': ['self', '\'self\'', 'data:', 'www.google.com'],
       'script-src': ['self', '\'self\'', 'https://www.google.com/recaptcha/', 'https://www.gstatic.com/recaptcha/',
                      'https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/js/bootstrap.bundle.min.js'],
       'style-src': ['self', '\'self\'', 'https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css'],
       'frame-src': ['self', '\'self\'', 'https://www.google.com/recaptcha/', 'https://recaptcha.google.com/recaptcha/']}

talisman = Talisman(app, content_security_policy=csp)


# DATABASE TABLES
# Create Post model
class Post(db.Model):
    __tablename__ = 'posts'

    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.Integer, db.ForeignKey('users.id'))
    created = db.Column(db.DateTime, nullable=False)
    title = db.Column(db.Text, nullable=False)
    body = db.Column(db.Text, nullable=False)
    user = db.relationship("User", back_populates="posts")

    # Constructor
    def __init__(self, userid, title, body):
        self.created = datetime.now()
        self.userid = userid
        self.title = title
        self.body = body

    # Updates a specific post
    def update(self, userid, title, body):
        self.created = datetime.now()
        self.userid = userid
        self.title = title
        self.body = body
        db.session.commit()

    # Decrypt and display title
    def decrypt_title(self):
        cipher = Fernet(self.user.generate_key())

        post_to_show = Post.query.filter_by(id=self.id).first()

        decrypted_text =  cipher.decrypt(post_to_show.title).decode()
        return decrypted_text

    # Decrypt and display body
    def decrypt_body(self):
        cipher = Fernet(self.user.generate_key())

        post_to_show = Post.query.filter_by(id=self.id).first()

        decrypted_text = cipher.decrypt(post_to_show.body).decode()
        return decrypted_text

# Create User model
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    # Set ID as PK
    id = db.Column(db.Integer, primary_key=True)

    # User authentication information.
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)

    # User information
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)

    # User posts
    posts = db.relationship("Post", order_by=Post.id, back_populates="user")

    # Event logging
    log = db.relationship("Log",uselist=False, cascade="all, delete-orphan",back_populates="user")

    # MFA key
    mfa_key = db.Column(db.String(32), nullable=False, default=pyotp.random_base32(), name="MFA KEY")

    # MFA enabled checker
    mfa_enabled = db.Column(db.Boolean(), nullable=False, default=False)

    # UserMixin column
    active = db.Column(db.Boolean(), nullable=False, default=True)

    # Job role column
    role = db.Column(db.String(32), nullable=False, default="end_user")

    # Salt
    salt = db.Column(db.String(100), nullable=False)

    # Constructor
    def __init__(self, email, firstname, lastname, phone, password, role):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.password = password
        self.salt = base64.b64encode(secrets.token_bytes(32)).decode()
        if role == "db_admin":
            self.role = role
        if role == "sec_admin":
            self.role = role
        if role == "end_user":
            self.role = "end_user"

    # Password Matching
    def verify_password(self, password):
        return PasswordHasher.verify(self, self.password, password)

    # MFA pin Matching
    def verify_mfa_pin(self, pin):
        if pyotp.TOTP(self.mfa_key).verify(pin):
            return True
        return False

    # QR Code create
    def get_uri(self):
        return str(pyotp.totp.TOTP(self.mfa_key).provisioning_uri(self.email, 'CSC2031 Blog'))

    # Login Manager Properties
    @property
    def is_active(self):
        return self.active

    # Generates log entry in DB for the User instance
    def generate_log(self):
        if self.id:

            # Create a new log entry
            log_entry = Log(user_id=self.id)

            # Add the log to the session and commit it
            db.session.add(log_entry)
            db.session.commit()

    # Generate symmetric encryption key
    def generate_key(self):
        key = hashlib.scrypt(password=self.password.encode(), salt=self.salt.encode(), n=2048, r=8, p=1, dklen=32)
        key = base64.b64encode(key)
        return key

# Event Logging Database
class Log(db.Model):
    __tablename__ = "logs"

    # Primary key
    id = db.Column(db.Integer, primary_key=True)

    # Foreign key referencing users table
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    # Registration time
    registration = db.Column(db.DateTime, nullable=False, default=datetime.utcnow())

    # Latest login time
    latest_login = db.Column(db.DateTime, nullable=True)

    # Previous login time
    previous_login = db.Column(db.DateTime, nullable=True)

    # Latest IP address
    latest_ip = db.Column(db.String(45), nullable=True)

    # Previous IP address
    previous_ip = db.Column(db.String(45), nullable=True)

    # Set up relationship between User and Log models
    user = db.relationship("User", back_populates="log")

    # Constructor
    def __init__(self, user_id, registration=None):
        self.user_id = user_id
        self.registration = registration or datetime.now()

# DATABASE ADMINISTRATOR
class MainIndexLink(MenuLink):
    def get_url(self):
        return url_for('index')

# Create Post DB View
class PostView(ModelView):
    column_display_pk = True
    column_hide_backrefs = False
    column_list = ('id', 'userid', 'created', 'title', 'body', 'user')

    # Define what specific users can access view
    def is_accessible(self):
        return current_user.is_authenticated and current_user.role == "db_admin"

    # Define outcome of wrong view access
    def inaccessible_callback(self, name, **kwargs):
        if current_user.is_authenticated:
            return render_template("errors/forbidden.html")
        flash("Administrator access required", category='error')
        return redirect(url_for('accounts.login'))

# Create User DB View
class UserView(ModelView):
    column_display_pk = True
    column_hide_backrefs = False
    column_list = ('id', 'email', 'password', 'firstname', 'lastname', 'phone', 'posts', 'mfa_key', 'mfa_enabled', 'active', 'salt', 'role')

    # Define what specific users can access view
    def is_accessible(self):
        return current_user.is_authenticated and current_user.role == "db_admin"

    # Define outcome of wrong view access
    def inaccessible_callback(self, name, **kwargs):
        if current_user.is_authenticated:
            return render_template("errors/forbidden.html")
        flash("Administrator access required", category='error')
        return redirect(url_for('accounts.login'))

    # Override database delete function
    def delete_model(self, model):

        if model.log:
            model.log.user_id = None
            db.session.commit()

        db.session.delete(model)
        db.session.commit()


# Create Admin Menu
admin = Admin(app, name='DB Admin', template_mode='bootstrap4')
admin._menu = admin._menu[1:]
admin.add_link(MainIndexLink(name='Home Page'))
admin.add_view(PostView(Post, db.session))
admin.add_view(UserView(User, db.session))

# Set Limiter
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=['500/day'])

# Initialize QR Code
qrcode = QRcode(app)

# Set up Login Manager
login_manager = LoginManager()
login_manager.login_view = "accounts.login"
login_manager.init_app(app)
login_manager.login_message = 'Please login to access this page.'
login_manager.login_message_category = 'info'

# Wraps function deciding which users can call such function
def roles_required(*roles):
    def inner_decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):

            # Redirect anonymous users to login page
            if current_user.is_anonymous:
                logger.warning('[User Email:None, User Role:None, URL Requested:{}, User IP Address:{}] Unauthorised role access attempt (Anonymous)'.format(
                        request.url, request.remote_addr))

                return render_template("accounts/login.html")

            # Redirect unauthorised authentic users to error page
            if current_user.role not in roles and current_user.is_authenticated:
                logger.warning('[User Email:{}, User Role:{}, URL Requested:{}, User IP Address:{}] Unauthorised role access attempt (Anonymous)'.format(
                        current_user.email, current_user.role, request.url, request.remote_addr))
                return render_template("errors/forbidden.html")
            return f(*args, **kwargs)

        return wrapped
    return inner_decorator

# Set up Logger
logger = logging.getLogger("LoggerUniqueName")
handler = logging.FileHandler("security.log")
handler.setLevel(WARNING)
formatter = logging.Formatter('%(asctime)s : %(message)s', '%d/%m/%Y %I:%M:%S %p')
handler.setFormatter(formatter)
logger.addHandler(handler)

# IMPORT BLUEPRINTS
from accounts.views import accounts_bp
from posts.views import posts_bp, delete
from security.views import security_bp

# REGISTER BLUEPRINTS
app.register_blueprint(accounts_bp)
app.register_blueprint(posts_bp)
app.register_blueprint(security_bp)


