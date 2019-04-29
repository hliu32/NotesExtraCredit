# storage.py

import os
import json
import re
from tinydb import TinyDB, Query

notes_db = TinyDB("notes_tinydb.json")
profiles_table = notes_db.table("profiles")
notes_table = notes_db.table("notes")

# Manage user profiles

def get_profiles(search=None):
    query = Query()
    if search:
        profiles = profiles_table.search(query.user.matches(".*"+search+".*", flags=re.IGNORECASE))
    else:
        profiles = profiles_table.all()
    for profile in profiles:
        profile['id'] = profile.doc_id
    return profiles

def add_profile(profile):
    assert type(profile) is dict
    assert 'user' in profile
    assert type(profile['user']) is str
    id = profiles_table.insert(profile)
    return id

def delete_profile(id):
    try:
        profiles_table.remove(doc_ids = [id])
    except KeyError:
        pass

# Manage notes

def get_notes(search = None):
    query = Query()
    if search:
        notes = notes_table.search(query.text.matches(".*"+search+".*", flags=re.IGNORECASE))
    else:
        notes = notes_table.all()
    for note in notes:
        note['id'] = note.doc_id
    return note

def add_note(note):
    assert type(note) is dict
    assert 'text' in note
    assert type(note['text']) is str
    id = notes_table.insert(note)
    return id

def delete_note(id):
    try:
        notes_table.remove(doc_ids = [id])
    except KeyError:
        pass
        
# Manage sessions

def get_session(key):
    try:
        return session = sessions_table.get(where('key') == key)
    except:
        return None

def add_session(session):
    assert type(session) is dict
    assert 'key' in session
    assert type(session['key']) is str
    sessions_table.insert(note)

def delete_session(key):
    try:
        notes_table.remove(where('key') == key)
    except KeyError:
        pass
