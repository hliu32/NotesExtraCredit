import json
import random
import os
import time
import hashlib

from flask import Flask
from flask import render_template
from flask import request
from flask import make_response
from flask import jsonify
from flask import redirect
from flask import flash

import storage

app = Flask(__name__)
app.config['SECRET_KEY'] = 'this is a temp secret key'
_message=""


def login_required(func):
    def wrapper(*args, **kwargs):
        print('\nwrapper\n')
        key = request.cookies.get("session_key")
        # create a rejection response
        response = make_response(redirect("/login"))
        response.set_cookie("session_key", "", expires=0)
        if not key:
            response.set_cookie("message", "User is not logged in.")
            flash('User is not logged in.')
            return response
        session = storage.get_session(key)
        if not session:
            response.set_cookie("message", "User is not logged in.")
            flash('User is not logged in.')
            return response
        ret = func(*args, **kwargs)
        # response.set_cookie("session_key", key, max_age=600)
        # response.set_cookie("message", "", expires=0)
        storage.update_session(key, {"pages": (session.get("pages", 0) + 1)})
        return ret
    return wrapper


@app.route('/')
@app.route('/index')
def index():

    key = request.cookies.get("session_key")
    if not key:
        session = {}
    else:
        session = storage.get_session(key)

    return render_template('index.html', session=session)


def encrypt(password, salt):
    return hashlib.sha256((password+salt).encode()).hexdigest()


@app.route('/register', methods=['GET'])
def get_register():
    message = request.cookies.get("message")
    response = make_response(render_template("register.html", message=message, session=None))
    response.set_cookie("message","",expires=0)
    return response


@app.route('/register', methods=['POST'])
def post_register():
    salt = str(time.time())[3:]
    # save the registration to the profile database
    user = request.form.get("user")
    password = request.form.get("password")
    password = encrypt(password, salt)
    email = request.form.get("email")
    profile = {
        'user': user,
        'password': password,
        'salt': salt,
        'email': email,
    }
    try:
        storage.add_profile(profile)
        flash('Your profile created, please login with your credential.')
        return redirect('/login')
    except (ValueError, TypeError) as e:
        flash(str(e)+', please try again')
        return render_template('register.html')


@app.route('/login', methods=['GET'])
def get_login():
    message = request.cookies.get("message")
    response = make_response(render_template("login.html", message=message, session=None))
    response.set_cookie("message","",expires=0)
    return response


@app.route('/login', methods=['POST'])
def post_login():
    user = request.form.get("user")
    password = request.form.get("password")
    profile = storage.get_profile(user)
    # create a rejection response
    response = make_response(redirect("/login"))
    response.set_cookie("session_key", "", expires=0)
    if not profile:
        response.set_cookie("message","User/password not found, please try again.")
        flash("User/password not found, please try again.")
        return response
    if profile['password'] != encrypt(password, profile['salt']):
        # NEED TO HANDLE PASSWORDS CORRECTLY
        response.set_cookie("message","User/password not found, please try again.")
        return response
    # create a success response
    response = make_response(redirect("/notes"))
    # generate a (not really) random string
    key = "session." + str(random.randint(1000000000,1999999999))
    # create a session based on that key
    storage.add_session({"key":key, "user":user, "login":int(time.time()), "pages":1})
    # store the key in a cookie
    response.set_cookie("session_key", key, max_age=600)
    return response


@app.route('/notes', methods=['GET'])
def get_notes():
    message = request.cookies.get("message")
    key = request.cookies.get("session_key")
    # create a rejection response
    response = make_response(redirect("/login"))
    response.set_cookie("session_key", "", expires=0)
    if not key:
        response.set_cookie("message","User is not logged in.")
        return response
    session = storage.get_session(key)
    if not session:
        response.set_cookie("message","User is not logged in.")
        return response

    notes = storage.get_user_notes(session['user']) # only current user's note for privacy
    notes.reverse()

    response = make_response(render_template("notes.html", message=message, session=session, notes=notes))
    storage.update_session(key, {"pages":(session.get("pages",0) + 1)})
    response.set_cookie("session_key", key, max_age=600)
    response.set_cookie("message","",expires=0)
    return response


@app.route('/notes', methods=['POST'], endpoint='post_notes')
@login_required
def post_notes():
    key = request.cookies.get("session_key")
    session = storage.get_session(key)
    user = session['user']
    note = request.form.get("note")
    note_id = request.form.get('note_id')

    # if note is not None and note != "":
    if note:
        if note_id:  # update note
            try:
                note_id = int(note_id)
                n = storage.note_table.get(doc_id=note_id)
                n['text'] = note
                print(n)
                storage.note_table.write_back([n])
            except ValueError:
                pass
        else:  # add a new note
            # storage.add_note({'text': str(user + ": " + note)})
            storage.add_note({'text': note, 'user': user, 'time': int(time.time())})
    response = make_response(redirect("/notes"))
    response.set_cookie("session_key", key, max_age=600)
    response.set_cookie("message","",expires=0)
    return response


@app.route('/search/<key_word>', methods=['GET'], endpoint='search_notes')
@login_required
def search_notes(key_word):
    if not key_word:
        return redirect('/notes')
    key = request.cookies.get("session_key")
    session = storage.get_session(key)
    notes = storage.get_notes(key_word)
    print(notes)
    response = make_response(render_template("search.html", session=session, notes=notes))
    response.set_cookie("session_key", key, max_age=600)
    response.set_cookie("message","",expires=0)
    return response


@app.route('/logout', methods=['GET'], endpoint='get_logout')
@login_required
def get_logout():
    key = request.cookies.get("session_key")
    if key:
        storage.delete_session(key)
    response = make_response(redirect("/login"))
    response.set_cookie("session_key", "", expires=0)
    response.set_cookie("message","",expires=0)
    return response


@app.route('/reset', methods=['GET'])
def reset_password():
    message = request.cookies.get("message")
    key = request.cookies.get("session_key")
    # create a rejection response
    response = make_response(redirect("/login"))
    response.set_cookie("session_key", "", expires=0)
    if not key:
        response.set_cookie("message", "User is not logged in.")
        return response
    session = storage.get_session(key)
    if not session:
        response.set_cookie("message", "User is not logged in.")
        return response
    user_name = session['user']
    user = storage.get_profile(user=user_name)

    forget = request.args.get('kind')

    response = make_response(render_template("reset_password.html", session=session, forget=forget))
    response.set_cookie("session_key", key, max_age=600)
    response.set_cookie("message", "", expires=0)
    return response


@app.route('/reset', methods=['post'])
def reset_password_post():
    key = request.cookies.get("session_key")
    # create a rejection response
    response = make_response(redirect("/login"))
    response.set_cookie("session_key", "", expires=0)
    if not key:
        response.set_cookie("message", "User is not logged in.")
        return response
    session = storage.get_session(key)
    if not session:
        response.set_cookie("message", "User is not logged in.")
        return response

    user_name = session['user']
    profile = storage.get_profile_to_update(user=user_name)
    old_password = request.form.get("old_password")
    new_password = request.form.get("new_password")
    forget = request.form.get('forget')
    if forget != 'forget':
        if not old_password or not new_password:
            response.set_cookie("message",
                                "You must supply old password and new password to reset password, please try again.")
            return response

        if profile['password'] != encrypt(old_password, profile['salt']):
            response.set_cookie("message","You must supply old password to reset password, please try again.")
            return response
    print(profile)
    profile['password'] = encrypt(new_password, profile['salt'])
    print(profile)
    response = make_response(redirect("/notes"))
    storage.delete_session(key)
    storage.profile_table.write_back([profile])
    response.set_cookie("session_key", '', expires=0)
    if forget == 'forget':
        response.set_cookie("message", "Your password updated, please login with new password", expires=0)
    return response


# API ROUTES


@app.route("/content/")
@app.route("/content/<search>")
def get_content(search=None):
    items = storage.get_notes(search)
    data = { "data": items }
    return jsonify(data)


@app.route("/remove/<int:id>")
def get_remove(id):
    storage.delete_note(id)

    return redirect("/notes")


@app.route('/profile', methods=['get', 'post'], endpoint='profile')
@login_required
def profile():
    key = request.cookies.get("session_key")
    session = storage.get_session(key)
    profile = storage.get_profile_to_update(session['user'])

    if request.method == 'POST':
        email = request.form.get('email')
        a1 = request.form.get('question01')
        a2 = request.form.get('question02')
        a3 = request.form.get('question03')
        if not all([email, a1, a2, a3]):
            flash('all entries must be filled')
        else:
            profile.update(
                email=email,
                secret_answer_1=a1,
                secret_answer_2=a2,
                secret_answer_3=a3,
            )
            try:
                storage.profile_table.write_back([profile])
                flash('Your profile updated')
            except:
                flash('Profile update failed')
    profile = storage.get_profile_to_update(session['user'])
    response = make_response(render_template("profile.html", profile=dict(profile), session=session))
    response.set_cookie("session_key", key, max_age=600)
    response.set_cookie("message", "", expires=0)
    return response


@app.route('/profile_del', endpoint='profile_del')
@login_required
def profile_del():
    key = request.cookies.get("session_key")
    session = storage.get_session(key)
    profile = storage.get_profile_to_update(session['user'])
    try:
        storage.delete_profile(session['user'])
    except:
        response = make_response(render_template("profile.html", profile=dict(profile), session=session))
        response.set_cookie("session_key", key, max_age=600)
        response.set_cookie("message", "", expires=0)
        flash('Failed to delete your profile')
        return response

    storage.delete_session(key)
    response = make_response(redirect("/login"))
    response.set_cookie("session_key", "", expires=0)
    response.set_cookie("message", "", expires=0)
    flash('Your profile deleted!')
    return response


@app.route('/forget', methods=['post', 'get'])
def forget():
    if request.method == 'POST':
        name = request.form.get('name')
        a1 = request.form.get('question01')
        a2 = request.form.get('question02')
        a3 = request.form.get('question03')
        if not all([name, a1, a2, a3]):
            flash('all entries must be filled')
        else:
            profile = storage.get_profile_to_update(name)
            if not profile:
                flash('User Not exist, Please check and try again')
            else:
                if profile['secret_answer_1'] == a1 \
                        and profile['secret_answer_2'] == a2 \
                        and profile['secret_answer_3'] == a3:
                    response = make_response(redirect("/reset?kind=forget"))
                    key = "session." + str(random.randint(1000000000, 1999999999))
                    storage.add_session({"key": key, "user": profile['user'], "login": int(time.time()), "pages": 1})
                    response.set_cookie("session_key", key, max_age=600)
                    flash('You Have to Reset your password')
                    return response
                else:
                    flash('Please check your answers, and try again!')
    response = make_response(render_template('forget.html'))
    response.set_cookie("session_key", "", expires=0)
    response.set_cookie("message", "", expires=0)
    # flash('Please answer all all the questions!')
    return response


@app.route('/feedback', methods=['post', 'get'], endpoint='feedback')
@login_required
def feedback():
    key = request.cookies.get("session_key")
    session = storage.get_session(key)
    profile = storage.get_profile_to_update(session['user'])

    if request.method == 'POST':
        feed = request.form.get('feed')
        print(feed)
        response = make_response(redirect("/"))
        response.set_cookie("session_key", key, max_age=600)
        flash('Thank you very much for feedback')
        return response

    response = make_response(render_template('feedback.html', session=session))
    response.set_cookie("session_key", key, max_age=600)
    response.set_cookie("message", "", expires=0)
    # flash('Please answer all all the questions!')
    return response



@app.context_processor
def convert_timestamp():
    '''convert timestamp to "year-month-day hour:minute:second"'''
    def convert(timestamp: int):
        try:
            timestamp = int(float(timestamp))
        except ValueError:
            return ''

        return time.strftime('%Y-%m-%d %X', time.gmtime(timestamp))

    return dict(convert_timestamp=convert)




if __name__ == '__main__':
    app.run(debug=True)