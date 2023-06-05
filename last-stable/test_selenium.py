import selenium
import requests
import time
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException



#method to create and initializate selenium browser
def create_webdriver():
    #create options object
    optionss = webdriver.ChromeOptions()
    #block all popup windows
    optionss.add_argument("--disable-popup-blocking")
    #block all browser extensions
    optionss.add_argument("--disable-extensions")
    #create Selenium browser with options
    browser = webdriver.Chrome('chrome_driver/chromedriver', chrome_options=optionss)
    return browser

driver = create_webdriver()
driver.get('https://support.apple.com/en-ae/HT208050')


