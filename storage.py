# storage.py

import os
import json
import re
from tinydb import TinyDB, Query, where

this_dir = os.path.abspath(os.path.dirname(__file__))

notes_db = TinyDB(os.path.join(this_dir, "notes_tinydb.json"))
profile_table = notes_db.table("profile")
note_table = notes_db.table("note")
session_table = notes_db.table("session")


# Manage user profiles


def add_profile(profile):
    if not isinstance(profile, dict):
        raise TypeError
    base_profile = {
        'user': None,
        'password': None,
        'salt': None,
        'secret_answer_1': '',  # what's your favorite color?
        'secret_answer_2': '',  # what's your favorite food?
        'secret_answer_3': '',  # what's your favorite movie?
        'address': '',
        'email': None
    }
    base_profile.update(profile)
    for k, v in base_profile.items():
        if not isinstance(v, str):
            raise TypeError('user profile not invalid')
    old = get_profile(base_profile['user'])  # username must be unique
    if old:
        raise ValueError('{} exits'.format(base_profile['user']))
    profile_table.insert(profile)


def get_profile(user):
    profile = profile_table.get(where('user') == user)
    if profile:
        return dict(profile)
    return None


def get_profile_to_update(user):
    profile = profile_table.get(where('user') == user)
    if profile:
        return profile
    return None


def delete_profile(user):
    profile = get_profile_to_update(user)
    if not profile:
        raise ValueError('{} do not exist'.format(user))
    user_notes = get_user_notes(username=user)
    try:
        note_table.remove(doc_ids=[d.doc_id for d in user_notes])
    except KeyError:
        pass
    profile_table.remove(where('user') == user)


###############################
# Manage sessions
###############################


def add_session(session):
    assert type(session) is dict
    assert 'key' in session
    assert type(session['key']) is str
    session_table.insert(session)


def get_session(key):
    session = session_table.get(where('key') == key)
    if session:
        return dict(session)
    return None


def update_session(key, updates):
    assert type(updates) is dict
    session_table.update(updates, where('key') == key)


def delete_session(key):
    session_table.remove(where('key') == key)


# Manage notes
def get_notes(search = None):
    query = Query()
    if search:
        notes = note_table.search(query.text.matches(".*"+search+".*", flags=re.IGNORECASE))
    else:
        notes = note_table.all()
    for note in notes:
        note['id'] = note.doc_id
    return [dict(n) for n in notes]


def get_user_notes(username):
    query = Query()
    notes = note_table.search(query.user == username)
    return notes


def add_note(note):
    assert type(note) is dict
    assert 'text' in note
    assert 'user' in note
    assert 'time' in note
    assert type(note['text']) is str
    assert type(note['user']) is str
    assert type(note['time']) is int
    id = note_table.insert(note)
    return id


def delete_note(id):
    try:
        note_table.remove(doc_ids=[id])
    except KeyError:
        pass
