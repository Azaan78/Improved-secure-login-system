import traceback
from flask import request, render_template, redirect, url_for, session, Blueprint, flash, abort
from sqlalchemy import text
from app import db
from app.models import User


# Additional imports
import re
import html
from flask import current_app
from sqlalchemy import bindparam
import datetime
from functools import wraps
from cryptography.fernet import Fernet, InvalidToken
import secrets


# Server side format for regex (Regular expressions)
email_re = re.compile( r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')

# Setting whitelist for tags and attributes
allowed_tags = {'b','i','u','em','strong','a','p','ul','ol','li','br'}
attr_re = re.compile(r'([a-zA-Z0-9_\-]+)\s*=\s*"([^"]*)"')

# Password blacklist
Password_Blacklist = {"Password123$", "Qwerty123!", "Adminadmin1@", "weLcome123!"}
Repeated_seq = re.compile(r'(.)\1\1')



# Checks to see if email (username) is valid and under 120 characters
def is_valid_email(username):
    return bool(username and email_re.match(username) and len(username)<=120)



# Checks to see if bio (length) is valid
def is_valid_bio_length(bio):
    return len(bio or '') <=1500


# Checks to see if password is valid and is greater than 10 characters and under 120 characters
def is_valid_password(password):
    return bool(password and 10 <= len(password) <= 120)


# New checks to see if password is valid by checking length, upper and lower cases, comparing password blacklists, and using RegEx to check special and non-special characters
def strong_password_check(password:str, username:str):
    if len(password) < 10 or len(password) > 120:
        return False

    if username and username.lower() in password.lower():
        return False

    if password in Password_Blacklist:
        return False

    if Repeated_seq.search(password):
        return False

    if not re.search(r'[A-Z]', password):
        return False

    if not re.search(r'[a-z]', password):
        return False

    if not re.search(r'\d', password):
        return False

    if not re.search(r'[^A-Za-z0-9]', password):
        return False



    return True



# Defining roles
def role_required(role_name):
    # fn is function route (admin, moderator, user_dashboard)
    def decorator(fn):
        # @wraps helps with metadata
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # Gets username from current session
            username = session.get('user')

            # If user is not logged in, send to home page
            if not username:
                return redirect(url_for('main.login'))

            # Gets record from the database
            user = db.session.query(User).filter_by(username=username).first()

            # If user can't be found or does not match the role
            if not user or user.role != role_name:
                # Log attempted login as unauthorised/warning as credentials aren't valid
                current_app.logger.warning('authorization_failure',extra={'user': username, 'required_role': role_name, 'ip': request.remote_addr})
                # Deny access
                abort(403)

            # If user credentials valid then authorise
            return fn(*args, **kwargs)
        return wrapper
    return decorator



# Takes raw bio (as string) and sanatises
def sanatize_bio(raw: str) ->str:
    if not raw:
        return ''
    s = raw
    out = []
    i = 0
    # Loops through bio (raw)
    while i <len(s):

        # If the begining of a tag is found '<' then find the end '>'
        if s[i] == '<':
            j = s.find('>', i+1)
            # If position of '>' not valid then skip the tag and convert it to a string
            if j == -1:
                out.append(html.escape(s[i])); i += 1; continue

            # Takes all content inside the <>
            tag_content = s[i+1:j].strip()
            is_close = tag_content.startswith('/')
            tag_name = (tag_content[1:].split()[0] if is_close else tag_content.split()[0]).lower()

            # Checks to see if tags are in allowed list
            if tag_name in allowed_tags:

                # If tag is (a) hyperlink then further checks attribute list
                if tag_name == 'a' and not is_close:
                    attrs_text = ''
                    for m in attr_re.finditer(tag_content):

                        # Returns parts of strings where there are attributes
                        attr, val = m.group(1).lower(), m.group(2)
                        if attr in ('href', 'title'):
                            if attr == 'href' and val.strip().lower().startswith('javascript:'):
                                continue
                            # Appends attribute test with the name of each used attribute with the matching text
                            attrs_text += f' {attr}="{html.escape(val, quote=True)}"'

                    # Appends attribute text in a (a) tag
                    out.append(f'<a{attrs_text}>')

                else:
                    # If tag is not a then append tag name (close tag if open and vice versa)
                    out.append(f'</{tag_name}>' if is_close else f'<{tag_name}>')

            else:
                # If tag not in allowed tags then append and increment by 1
                out.append(html.escape(s[i:j+1]))
            i = j + 1

        else:
            # If no opened tag then append and increment
            out.append(html.escape(s[i])); i += 1

    return ''.join(out)



# Set up for encryption (decides if needed or not)
def get_fernet():
    # Fetch encryption key from flask
    key = current_app.config.get('FERNET_KEY')

    # If there is no key, then disable encryption
    if not key:
        current_app.logger.warning('FERNET_KEY not set', extra={'user':'system','ip':request.remote_addr if request else 'N/A'})
        return None

    try:
        # Sends fernet key as bytes
        return Fernet(key.encode())

    # If key not valid then fail
    except Exception:
        current_app.logger.error('FERNET_KEY not set')
        return None



# Encrypts bio text
def encrypt_bio(plain: str) -> str:
    # Avoid encrypting null/empty values to save time
    if not plain:
        return ''

    # Get fernet to encrypt
    f = get_fernet()

    # Encrypts text into a string for database storage
    if f:
        return f.encrypt(plain.encode()).decode()

    # If encryption is not needed or fails
    return plain



# Decrypts bio text
def decrypt_bio(token: str) -> str:
    # Avoid encrypting null/empty values to save time
    if not token:
        return ''

    # Get fernet to encrypt
    f = get_fernet()

    # Encrypts text into a string for database storage
    if f:
        try:
            return f.decrypt(token.encode()).decode()

        # Logs a warning if an issue occurs with the tokens
        except InvalidToken:
            current_app.logger.warning('bio_decrypt_failed')
            return ''

    # If encryption is not needed or fails
    return token


main = Blueprint('main', __name__)


# Render home page templates
@main.route('/')
def home():
    return render_template('home.html')



# Rendering login page
@main.route('/login', methods=['GET', 'POST'])
def login():
    # Initialising a dictionary of errors
    errors = {}

    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)

    # If post request, then save username and password
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''

        # CSRF token checks
        submitted = request.form.get('csrf_token' , '')
        if not submitted or submitted != session.get('csrf_token'):
            abort(400)

        # Username and password checks
        if not is_valid_email(username):
            errors['username'] = 'Enter a valid email address.'

        if not is_valid_password(password):
            errors['password'] = 'Emter a valid password.'

        if not password:
            errors['password'] = 'Enter your password.'

        # If there are any issues/errors then render template with errors
        if errors:
            return render_template('login.html', errors=errors)

        # Query database for username to login
        user = User.query.filter_by(username=username).first()

        # Checks username query and saves account details in session
        if user and user.check_password(password, current_app.config.get('PASSWORD_PEPPER')):
            session.clear()
            session['csrf_token'] = secrets.token_hex(16)
            session['user'] = user.username
            session['role'] = user.role
            session['has_bio'] = bool(user.bio)
            session.permanent = True
            session['authen_time'] = datetime.datetime.utcnow().isoformat()
            current_app.logger.info('login_successful', extra={'user': username, 'ip': request.remote_addr})
            return redirect(url_for('main.dashboard'))

       # If there was an issue selecting the record then flash, and log an error, then redirect
        else:
            flash('Login credentials are invalid, please try again')
            current_app.logger.warning('login_failed', extra={'user': username, 'ip': request.remote_addr})

    # If a get request then render login form
    return render_template('login.html', errors=errors)



# Render dashboard page
@main.route('/dashboard')
def dashboard():
    # If user is logged in and account type is 'user', then save session data and render template
    if 'user' in session:
        username = session['user']
        user = db.session.query(User).filter_by(username=username).first()
        bio = user.bio if user else''
        bio = decrypt_bio(bio)
        return render_template('dashboard.html', username=username, bio=bio)

    # If account is not a 'user' account type
    return redirect(url_for('main.login'))



# Render register page
@main.route('/register', methods=['GET', 'POST'])
def register():
    # Initialising a dictionary of errors
    errors ={}

    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)

    # If post request, then save username, password and other data for account creation
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        bio = request.form.get('bio') or ''
        role = request.form.get('role', 'user')

        # CSRF token checks
        submitted = request.form.get('csrf_token', '')
        if not submitted or submitted != session.get('csrf_token'):
            abort(400)

        # Username and password checks
        if not is_valid_email(username):
            errors['username'] = 'Enter a valid email address (max 120 characters)'

        if not strong_password_check(password, username):
            errors['password'] = 'Enter a valid password (10-120 characters)'

        if not is_valid_bio_length(bio):
            errors['bio'] = 'Enter a valid biography (1500 characters max)'

        # If there are any issues/errors then render template with errors
        if errors:
            current_app.logger.warning('register_failed', extra={'user': username, 'ip': request.remote_addr})
            return render_template('register.html', errors=errors)

        # Sanatises bio
        safe_bio = sanatize_bio(bio)
        stored_bio = encrypt_bio(safe_bio)

        # Secure inserts
        user = User(username=username, password='', role=role, bio=stored_bio)
        user.set_password(password, current_app.config.get('PASSWORD_PEPPER'))
        db.session.add(user)

        # Commits, logs and redirects new account
        db.session.commit()
        current_app.logger.info('register_successful', extra={'user': username, 'ip': request.remote_addr})
        return redirect(url_for('main.login'))

    # If a get request then render register form
    return render_template('register.html', errors=errors)



# Render admin-panel page
@main.route('/admin-panel')
@role_required('admin')
def admin():
    return render_template('admin.html')



# Render moderator page
@main.route('/moderator')
@role_required('moderator')
def moderator():
    return render_template('moderator.html')



# Render user-dashboard
@main.route('/user-dashboard')
@role_required('user')
def user_dashboard():
    return render_template('user_dashboard.html', username=session.get('user'))



# Render change-password template
@main.route('/change-password', methods=['GET', 'POST'])
def change_password():
    # Initialising a dictionary of errors and saves username in current session
    errors = {}

    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)

    # User needs to be logged in
    if 'user' not in session:
        abort(403)

    username = session['user']

    # If post request, then save current and new password
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')

        # CSRF token checks
        submitted = request.form.get('csrf_token', '')
        if not submitted or submitted != session.get('csrf_token'):
            abort(400)

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(current_password, current_app.config.get('PASSWORD_PEPPER')):
            errors['current_password'] = 'Current password is incorrect.'

        if not strong_password_check(new_password, username):
            errors['new_password'] = 'Enter your new password.'

        if new_password == current_password:
            errors['new_password'] = 'New password must be different from current password.'

        # If there are any issues/errors then render template and log with errors
        if errors:
            current_app.logger.warning('password_change_failed', extra={'user': username, 'ip': request.remote_addr})
            return render_template('change_password.html', errors=errors)

        # Selects record to have password overwritten
        user.set_password(new_password, current_app.config.get('PASSWORD_PEPPER'))
        db.session.commit()

        # If there is no row to overwrite the password, flash and log error, as well as render template
        if not user:
            flash('Current password is incorrect', 'error')
            current_app.logger.warning('password_change_failed', extra={'user': username, 'ip': request.remote_addr})
            return render_template('change_password.html', errors=errors)

        # Flashes and logs successful password change and redirects to dashboard
        flash('Password changed successfully', 'success')
        current_app.logger.info('password_change_successful', extra={'user': username, 'ip': request.remote_addr})
        return redirect(url_for('main.dashboard'))

    # If a get request then render change password form
    return render_template('change_password.html', errors=errors)



@main.route('/logout', methods=['POST', 'GET'])
def logout():
    session.clear()
    return redirect(url_for('main.login'))



# Error handling
@main.app_errorhandler(400)
def bad_request(e):
    return render_template('400.html', message=str(e)), 400

@main.app_errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@main.app_errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@main.app_errorhandler(500)
def internal_error(e):
    current_app.logger.exception('internal_server_error')
    return render_template('500.html'), 500
