
# A very simple Flask Hello World app for you to get started with...

from flask import Flask
from flask import render_template
from flask import request, make_response
from flask import jsonify
from flask import redirect

import notes_api

app = Flask(__name__)

_message=""

_user = ""

@app.route('/')
@app.route('/notes', methods=['GET'])
def get_notes():
    cookies = request.cookies
    print(cookies)
    user = cookies['user']
    response = make_response(render_template("notes.html", message=_message, user=user))
    response.set_cookie("user", user)
    return response

@app.route('/notes', methods=['POST'])
def post_notes():
    user = request.form.get("user")
    note = request.form.get("note")
    if note != None and note != "":
        notes_api.add_note(str(user + ": " + note))
    response = make_response(redirect("/notes"))
    response.set_cookie("user", user)
    return(response)

@app.route("/content/")
@app.route("/content/<search>")
def get_content(search=None):
    items = notes_api.get_notes(search)
    data = { "data": items }
    return jsonify(data)

@app.route("/remove/<int:id>")
def get_remove(id):
    notes_api.delete_note(id)
    return redirect("/notes")
