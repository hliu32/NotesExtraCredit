Feature: Notes management capabilities

  Scenario: Create a new note
    Given   we are at "http://localhost:5000/notes"
    When    we enter a new note containing "This is a new note"
     and    we submit the new note
    Then    we will get some notes in a list
     and    the list will contain "This is a new note"

  Scenario: Delete a note
    Given   we are at "http://localhost:5000/notes"
      and   we have some notes in a list
      and   one and only one of the notes says "This is a new note"
    When    we click the delete button next to "This is a new note"
    Then    we will get some notes in a list
     and    the list will not contain "This is a new note"
