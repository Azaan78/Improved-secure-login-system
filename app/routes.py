import traceback
from flask import request, render_template, redirect, url_for, session, Blueprint, flash, abort
from sqlalchemy import text
from app import db
from app.models import User

#Additional imports
import re
import html
from flask import current_app as app
from sqlalchemy import bindparam
import datetime

#Server side format for regex (Regular expressions)
email_re = re.compile(r'^[^@+@[^@]+\.[^@]+$')

#Setting whitelist for tags and attributes
allowed_tags = {'b','i','u','em','strong','a','p','ul','ol','li','br'}
attr_re = re.compile(r'([a-zA-Z0-9_\-]+)\s*=\s*"([^"]*)"')

#Password blacklist
Password_Blacklist = {"Password123$", "Qwerty123!", "Adminadmin1@", "welcome123!"}
Repeated_seq = re.compile(r'(.)\1\1')

#Checks to see if email is valid
def is_valid_email(username):
    return bool(username and email_re.match(username) and len(username)<=120)


def is_valid_bio_length(bio):
    return len(bio or '') <=1500


def is_valid_password(password):
    return bool(password and 10 <= len(password) <= 120)


def strong_password_check(password:str, username:str):
    if len(password) < 10 or len(password) > 120:
        return False

    if username and username.lower() in password.lower():
        return False

    if password in Password_Blacklist:
        return False

    if Repeated_seq.search(password):
        return False

    if not re.search(r'[a-z]', password):
        return False

    if not re.search(r'\d', password):
        return False

    if not re.search(r'[A-Za-z0-9]', password):
        return False

    return True


#Takes raw bio (as string) and sanatises
def sanatize_bio(raw: str) ->str:
    if not raw:
        return ''
    s = raw
    out = []
    i = 0
    #Loops through bio (raw)
    while i <len(s):

        #If the begining of a tag is found '<' then find the end '>'
        if s[i] == '<':
            j = s.find('>', i+1)
            #If position of '>' not valid then skip the tag and convert it to a string
            if j == -1:
                out.append(html.escape(s[i])); i += 1; continue

            #Takes all content inside the <>
            tag_content = s[i+1:j].strip()
            is_close = tag_content.startswith('/')
            tag_name = (tag_content[1:].split()[0] if is_close else tag_content.split()[0]).lower()

            #Checks to see if tags are in allowed list
            if tag_name in allowed_tags:

                #If tag is (a) hyperlink then further checks attribute list
                if tag_name == 'a' and not is_close:
                    attrs_text = ''
                    for m in attr_re.finditer(tag_content):

                        #Returns parts of strings where there are attributes
                        attr, val = m.group(1).lower(), m.group(2)
                        if attr in ('href', 'title'):
                            if attr == 'href' and val.strip().lower().startswith('javascript:'):
                                continue
                            #Appends attribute test with the name of each used attribute with the matching text
                            attrs_text += f' {attr}="{html.escape(val, quote=True)}"'

                    #Appends attribute text in a (a) tag
                    out.append(f'<a{attrs_text}>')

                else:
                    #If tag is not a then append tag name (close tag if open and vice versa)
                    out.append(f'</{tag_name}>' if is_close else f'<{tag_name}>')

            else:
                #If tag not in allowed tags then append and increment by 1
                out.append(html.escape(s[i:j+1]))
            i = j + 1

        else:
            #If no opened tag then append and increment
            out.append(html.escape(s[i])); i += 1

    return ''.join(out)


main = Blueprint('main', __name__)



@main.route('/')
def home():
    return render_template('home.html')



@main.route('/login', methods=['GET', 'POST'])
def login():
    errors = {}
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''

        if not is_valid_email(username):
            errors['username'] = 'Enter a valid email address.'

        if not password:
            errors['password'] = 'Enter your password.'

        if not strong_password_check(password):
            errors['password'] = 'Enter a valid password.'

        if errors:
            return render_template('login.html', errors=errors)

        select = text('SELECT * FROM user WHERE username = :username AND password = :password')
        row = db.session.execute(select.bindparams(
            bindparam('username', type = db.String),
            bindparam('password', type=db.String)
        ),{'username' : username, 'password' : password}).mappings().first()

        if row:
            user = db.session.get(User, row['id'])
            session.clear()
            session['user'] = user.username
            session['role'] = user.role
            session['has_bio'] = bool(user.bio)
            session.permanent = True
            session['authen_time'] = datetime.datetime.utc().isoformat()
            return redirect(url_for('main.dashboard'))
        else:
            flash('Login credentials are invalid, please try again')
    return render_template('login.html', errors=errors)



@main.route('/dashboard')
def dashboard():
    if 'user' in session:
        username = session['user']
        user = db.session.query(User).filter_by(username=username).first()
        bio = user.bio if user else''
        return render_template('dashboard.html', username=username, bio=bio)
    return redirect(url_for('main.login'))



@main.route('/register', methods=['GET', 'POST'])
def register():
    errors ={}

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        bio = request.form.get('bio') or ''
        role = request.form.get('role', 'user')

        if not is_valid_email(username):
            errors['username'] = 'Enter a valid email address (max 120 characters)'

        if not strong_password_check(password):
            errors['password'] = 'Enter a valid password (10-120 characters)'

        if not is_valid_bio_length(bio):
            errors['bio'] = 'Enter a valid biography (1500 characters max)'

        if errors:
            return render_template('register.html', errors=errors)

        #Sanatises bio
        safe_bio = sanatize_bio(bio)

        #Secure inserts
        insert = text ("INSERT INTO user (username, password, role, bio) VALUES (:username, :password, :role, :bio)")
        db.session.execute(insert).bindparams(
            bindparam('username', type = db.String),
            bindparam('password', type = db.String),
            bindparam('role', type = db.String),
            bindparam('bio', type = db.String)
        ), {'username': username, 'password': password, 'role': role, 'bio': safe_bio}
        db.session.commit()
        return redirect(url_for('main.login'))
    return render_template('register.html', errors=errors)



@main.route('/admin-panel')
def admin():
    if session.get('role') != 'admin':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('admin.html')



@main.route('/moderator')
def moderator():
    if session.get('role') != 'moderator':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('moderator.html')



@main.route('/user-dashboard')
def user_dashboard():
    if session.get('role') != 'user':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('user_dashboard.html', username=session.get('user'))



@main.route('/change-password', methods=['GET', 'POST'])
def change_password():
    # Require basic "login" state
    if 'user' not in session:
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")

    username = session['user']

    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')

        errors = {}
        if not strong_password_check(current_password):
            errors['current_password'] = 'Enter your current password.'

        if not strong_password_check(new_password):
            errors['new_password'] = 'Enter your new password.'

        if new_password == current_password:
            errors['new_password'] = 'New password must be different from current password.'

        if errors:
            return render_template('change_password.html', errors=errors)

        select = text("SELECT * FROM user WHERE username = :username AND password = :current_password LIMIT 1")
        row = db.session.execute(select.bindparams(
            bindparam('username', type = db.String),
            bindparam('current_password', type = db.String)
        ), {'username':username, 'current_password':current_password}).mappings().first()

        if not row:
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html', errors=errors)

        update = text("UPDATE user SET password = :new_password WHERE username = :username")
        db.session.execute(update.bindparams(
            bindparam('new_password', type = db.String),
            bindparam('username', type = db.String)
        ), {'new_password': new_password, 'username': username})
        db.session.commit()

        flash('Password changed successfully', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('change_password.html')
