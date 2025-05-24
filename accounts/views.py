from datetime import datetime
from argon2 import PasswordHasher
from config import logger
from flask_login import login_user, logout_user, current_user, login_required
import config
from markupsafe import Markup
from flask import session, request
from flask import Blueprint, render_template, flash, redirect, url_for
from accounts.forms import RegistrationForm, LoginForm
from config import User, db, limiter

accounts_bp = Blueprint('accounts', __name__, template_folder='templates')

# Registers a new user
@accounts_bp.route('/registration', methods=['GET', 'POST'])
@limiter.exempt()
def registration():

    form = RegistrationForm()

    if form.validate_on_submit():

        # Searches for existing user with same email
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already exists', category="danger")
            return render_template('accounts/registration.html', form=form)

        # Hash given password
        ph = PasswordHasher()
        form.password.data = ph.hash(form.password.data)

        # Register new user
        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        role=form.role.data)


        db.session.add(new_user)
        db.session.commit()

        # Generate a log entry for the user
        new_user.generate_log()

        # Log user registration
        logger.warning('[User Email:{}, User Role:{}, IP:{}] Registered'.format(new_user.email, new_user.role, request.remote_addr))

        flash('Account Created. You must enable Multi-Factor Authentication (MFA) to login', category='success')
        return render_template('accounts/mfa_setup.html', secret=new_user.mfa_key, uri=new_user.get_uri())

    return render_template('accounts/registration.html',form=form)

# Logs in existing user
@accounts_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit('20/minute')
def login():

    # Sets authentication attempts to zero
    if not session.get("auth_attempts"):
        session["auth_attempts"] = 0

    form = LoginForm()

    if form.validate_on_submit():

        # Searches for existing users with given email
        user = User.query.filter_by(email=form.email.data).first()

        ph = PasswordHasher()

        try:
            # Checks if email doesn't match or email matches but password is incorrect
            if user and user.active and ph.verify(user.password, form.password.data):

                # Checks password and MFA pin if password is correct
                if user.verify_mfa_pin(form.pin.data):

                    # Check if user is logging in for the first time
                    if not user.mfa_enabled:

                        user.mfa_enabled = True

                        # Commit to db
                        db.session.commit()

                    # Reset authentication attempts to 0
                    session["auth_attempts"] = 0

                    login_user(user)

                    # Update Login log after user logs in
                    if user.log:
                        # Update log
                        user.log.previous_login = user.log.latest_login
                        user.log.latest_login = datetime.now()
                        user.log.previous_ip = user.log.latest_ip
                        user.log.latest_ip = request.remote_addr

                        db.session.commit()

                    # Log user in
                    flash('Successfully logged in', category='success')
                    logger.warning('[User Email:{}, User Role:{}, IP:{}] User Login'.format(current_user.email, current_user.role, request.remote_addr))

                    # Redirect user according to their role
                    if current_user.role == "db_admin":
                        return redirect(url_for('admin.index'))
                    if current_user.role == "sec_admin":
                        return redirect(url_for('security.security'))
                    else:
                        return redirect(url_for('posts.posts'))

                # If user has wrong MFA pin and not enabled MFA redirect user
                if not user.verify_mfa_pin(form.pin.data) and not user.mfa_enabled:
                    flash('MFA was not enabled, please enable first before login.', category="warning")
                    return render_template('accounts/mfa_setup.html', secret=user.mfa_key, uri=user.get_uri())

        # If login is unsuccessful due to an error caused by user
        except Exception as e:

            # Increase authentication attempts by 1
            session["auth_attempts"] += 1

            # Checks if authentication attempts are more than limit
            if session["auth_attempts"] >= 4:

                # Lock user
                if user:
                    user.active = False
                    db.session.commit()

                flash(Markup('<h6>Account Locked</h6><br>Click <a href="/unlock">here</a> to Unlock Account.'))
                logger.warning(
                    '[User email:{}, User Attempts Made:{}, IP:{}] Max invalid login attempts reached'.format(
                        form.email.data, session["auth_attempts"], request.remote_addr))
                return render_template('accounts/login.html')

            # Throw error message, redirect user to login page, and mention remaining authentication attempts
            flash('Please check your login details and try again, {} attempts remaining.'.format(
                4 - session["auth_attempts"]), category="danger")

            logger.warning('[User email:{}, User Attempts Made:{}, IP:{}] Invalid login attempt'.format(
                form.email.data, session["auth_attempts"], request.remote_addr))
            return redirect(url_for('accounts.login'))

        # If login is unsuccessful due to invalid user details

        # Increase authentication attempts by 1
        session["auth_attempts"] += 1

        # Checks if authentication attempts are more than limit
        if session["auth_attempts"] >= 4:

            # Lock user out
            if user:
                user.active = False
                db.session.commit()

            flash(Markup('<h6>Account Locked</h6><br>Click <a href="/unlock">here</a> to Unlock Account.'))
            logger.warning('[User email:{}, User Attempts Made:{}, IP:{}] Max invalid login attempts reached'.format(
                form.email.data, session["auth_attempts"], request.remote_addr))
            return render_template('accounts/login.html')

        # Throw error message, redirect user to login page, and mention remaining authentication attempts
        flash('Please check your login details and try again, {} attempts remaining.'.format(
            4 - session["auth_attempts"]), category="danger")

        logger.warning('[User email:{}, User Attempts Made:{}, IP:{}] Invalid login attempt'.format(
            form.email.data, session["auth_attempts"], request.remote_addr))
        return redirect(url_for('accounts.login'))

    return render_template('accounts/login.html', form=form)

# Log user out
@limiter.exempt()
@accounts_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return render_template('home/index.html')

# Redirect to user account
@limiter.exempt()
@accounts_bp.route('/account')
@login_required
def account():
    return render_template('accounts/account.html')

# Unlocks locked user account
@accounts_bp.route('/unlock')
@limiter.exempt()
@login_required
def unlock():
    session["auth_attempts"] = 0
    return redirect(url_for('accounts.login'))

# Display specific errors
@config.app.errorhandler(429)
def display_429_error(e):
    return render_template('errors/429.html'), 429

@config.app.errorhandler(400)
def display_400_error(e):
    return render_template('errors/400.html'), 400

@config.app.errorhandler(404)
def display_404_error(e):
    return render_template('errors/404.html'), 404

@config.app.errorhandler(500)
def display_500_error(e):
    return render_template('errors/500.html'), 500

@config.app.errorhandler(501)
def display_501_error(e):
    return render_template('errors/501.html'), 501