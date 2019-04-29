from behave import *
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
import time

@given(u'we are at "{url}"')
def step_impl(context, url):
    context.browser = webdriver.Chrome()
    context.browser.get(url)

@when(u'we enter a new note containing "{text}"')
def step_impl(context, text):
    notes_text = context.browser.find_element_by_id("note_text")
    notes_text.clear()
    notes_text.send_keys(text)

@when(u'we submit the new note')
def step_impl(context):
    submit_button = context.browser.find_element_by_id("submit_button")
    submit_button.click()

@then(u'we will get some notes in a list')
def step_impl(context):
    content_div = context.browser.find_element_by_id("content")
    content_table = content_div.find_element_by_id("table")
    context.content_rows = content_table.find_elements_by_id("tr")
    assert len(context.content_rows) > 0

@then(u'the list will contain "{text}"')
def step_impl(context, text):
    assert context.content_rows
    for row in content_rows:
        if text in row:
            return
    assert False, "text does not appear in content"
