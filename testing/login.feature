Feature: Navigate to Amazon

  Scenario: go to Amazon Home Page
    Given   we have a Chrome browser
    When    we navigate to www.amazon.com
    Then    the browser title will contain Amazon

  Scenario: Amazon Home Page has Deal link
    Given   we have a Chrome browser
    When    we navigate to www.amazon.com
    Then    the page source will contain "Deal"
