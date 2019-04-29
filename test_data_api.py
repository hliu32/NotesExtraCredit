import data_api

def test_notes():
    n = data_api.get_notes()
    data_api.add_note("aaa")
    n = data_api.get_notes("aaa")
    assert len(n) > 0
    assert "aaa" in n[0]['text']
    print(n)

def test_profiles():
    p = data_api.get_profiles()
    data_api.add_profile({'user':"roberto"})
    p = data_api.get_profiles("roberto")
    assert len(p) > 0
    assert "roberto" in p[0]['user']
    print(p)

if __name__ == "__main__":
    test_notes()
    test_profiles()

