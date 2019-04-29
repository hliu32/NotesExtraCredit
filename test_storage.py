import storage
import time

def test_profiles():
    test_user = "user."+str(time.time())
    p = storage.get_profile(test_user)
    assert p == None
    storage.add_profile({'user':test_user})
    p = storage.get_profile(test_user)
    assert type(p) is dict
    assert 'user' in p
    assert p['user'] == test_user
    storage.delete_profile(test_user)
    p = storage.get_profile(test_user)
    assert p == None

def test_sessions():
    test_session = "session."+str(time.time())
    s = storage.get_session(test_session)
    assert s == None
    storage.add_session({'key':test_session})
    s = storage.get_session(test_session)
    assert type(s) is dict
    assert 'key' in s
    assert s['key'] == test_session
    storage.update_session(test_session,{'elephant':12})    
    s = storage.get_session(test_session)
    assert type(s) is dict
    assert 'key' in s
    assert s['key'] == test_session
    assert 'elephant' in s
    assert s['elephant'] == 12
    storage.delete_session(test_session)
    s = storage.get_session(test_session)
    assert s == None

def test_notes():
    test_note = "note."+str(time.time())
    notes = storage.get_notes()
    for note in notes:
        assert not test_note in note['text']
    id = storage.add_note({'text':test_note})
    notes = storage.get_notes()
    count = sum([1 for n in notes if test_note in n['text']])
    assert count == 1
    notes = storage.get_notes(test_note)
    assert len(notes) > 0
    assert test_note in notes[0]['text']
    storage.delete_note(id)
    notes = storage.get_notes()
    for note in notes:
        assert not test_note in note['text']

if __name__ == "__main__":
    test_profiles()
#    test_notes()


