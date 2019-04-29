from behave import *

from selenium import webdriver
from selenium.webdriver.common.keys import Keys

_browser = None

@given(u'we have a Chrome browser')
def step_impl(context):
    global _browser
    _browser = webdriver.Chrome()
    assert _browser

@when(u'we navigate to www.amazon.com')
def step_impl(context):
    global _browser
    _browser.get("https://www.amazon.com")

@then(u'the browser title will contain Amazon')
def step_impl(context):
    global _browser
    assert "Amazon" in _browser.title

@then(u'the page source will contain "Deal"')
def step_impl(context):
    global _browser
    assert "Deal" in _browser.page_source
