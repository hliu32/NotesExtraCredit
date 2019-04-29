from selenium import webdriver
from selenium.webdriver.common.keys import Keys
import time

browser = webdriver.Chrome()
try:
    browser.get("https://www.amazon.com")
    assert "Amazon" in browser.title

    target = "toaster"
    brand = "hamilton beach"

    search_box = browser.find_element_by_id("twotabsearchtextbox")
    search_box.clear()
    search_box.send_keys(target)
    search_box.send_keys(Keys.RETURN)

    result_items = browser.find_elements_by_class_name("s-result-item")
    print(len(result_items))
    n = len(result_items)
    k = 0
    for result_item in result_items:
        print(result_item.text)
        if brand.lower() in result_item.text.lower():
            k += 1
    assert k >= 3
    print("enough " + brand + " items were found.")
finally:
    browser.close()