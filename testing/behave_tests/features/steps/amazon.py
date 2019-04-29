from behave import *
from selenium import webdriver
from selenium.webdriver.common.keys import Keys

@given(u'We are at www.amazon.com')
def step_impl(context):
    context.browser = webdriver.Chrome()
    context.browser.get("https://www.amazon.com")
    assert "amazon" in context.browser.title.lower()

@when(u'we search for "{item}"')
def step_impl(context, item):
    search_box = context.browser.find_element_by_id("twotabsearchtextbox")
    search_box.clear()
    search_box.send_keys(item)
    search_box.send_keys(Keys.RETURN)

@then(u'we will get at least 20 results')
def step_impl(context):
    context.result_items = context.browser.find_elements_by_class_name("s-result-item")
    assert len(context.result_items) >= 20

@then(u'75% of the results will contain "{item}"')
def step_impl(context, item):
    n = 0
    for result_item in context.result_items:
        if item in result_item.text.lower():
            n += 1
    assert n * 4 >= len(context.result_items) * 3
