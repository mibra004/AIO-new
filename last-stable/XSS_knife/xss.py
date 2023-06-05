#Import libs
import numpy as np #variables used: array,payload_verify,line
import requests #variables used: request
import string #None

#Creating class Xssrun
class Xssrun:
    def __init__(self,link,payload,title_rerun,style_rerun,textarea_rerun,noscript_rerun,script_rerun,user_agent):
        #Create a request on the victim site
        #Variable who defines if there is a successfully XSS
        found_xss=0
        #Variable to identify if there is a <noscript> tag on code, 0 = no, 1 = yes
        noscript_tag=0

        #Get the arguments passed through runxss.py
        self.link=link
        self.payload=payload
        self.title_rerun=title_rerun
        self.style_rerun=style_rerun
        self.textarea_rerun=textarea_rerun
        self.noscript_rerun=noscript_rerun
        self.script_rerun=script_rerun
        self.user_agent=user_agent

        #Convert the payload to string to ease manipulation
        payload=str(payload)
        user_agent=str(user_agent)
        if not user_agent == "none":
            headers = {
                'User-Agent': user_agent
            }
            request = requests.get(link+payload, headers=headers)
        else:
            #Initiate a request on the site that was send to class
            request = requests.get(link+payload)


        #Parse the data
        parseHTML=str(request.content)
        #Prepare the data to create a array
        parseHTML = parseHTML.split("\\n")
        #Create the array
        array=np.array(parseHTML)
        #Create a array with successfully xss to compare with the source code
        payload_verify=np.array(["/\"><svg onload=alert(34305489723146875555666)>","<svg onload=alert(34305489723146875555666)>","</script><svg onload=alert(34305489723146875555666)>"])
        #Variable to help to count the array position
        arr_count=0
        #Variable to identify if there is a <title> tag on code, 0 = no, 1 = yes
        title_tag=0
        #Variable to identify if there is a <style> tag on code, 0 = no, 1 = yes
        style_tag=0
        #Variable to identify if there is a <textarea> tag on code, 0 = no, 1 = yes
        textarea_tag=0
        #Variable to identify if there is a <noscript> tag on code, 0 = no, 1 = yes
        noscript_tag=0
        #Variable to identify if there is a <script> tag on code, 0 = no, 1 = yes
        script_tag=0

        #Variable used to pass to runxss.py if there is a <title> tag on code, 0 = no, 1 = yes
        title_xss=0
        #Variable used to pass to runxss.py if there is a <style> tag on code, 0 = no, 1 = yes
        style_xss=0
        #Variable used to pass to runxss.py if there is a <textarea> tag on code, 0 = no, 1 = yes
        textarea_xss=0
        #Variable used to pass to runxss.py if there is a <noscript> tag on code, 0 = no, 1 = yes
        noscript_xss=0
        #Variable used to pass to runxss.py if there is a <script> tag on code, 0 = no, 1 = yes
        script_xss=0

        #Variable used to mark if there is the payload in code
        self.found_xss=0

        #Create a loop with the array values
        for x in array:
            #Transform to string, it will us"</script>ed for some tests
            self.x = str(x)
            find_payload=x.find(payload)
            #print(x)
        ##Verify if the payload is between <title></title>, if so, the XSS will not get success
        ##############################################################################################
            if not x in string.whitespace:
                #Test and set to 1 if there is a <title> tag on reflection
                if "<title" in x:
                    title_tag=1

                if "</title>" in x:
                    title_tag=0

                if "34305489723146875555666" in x and title_tag == 1:
                    title_xss=1
                #Test some special cases, if exists in reflection, means there is  XSS
                if "\\'&lt;/title>\\'-alert(34305489723146875555666)-\\'" in x:
                    found_xss=1
                if "\\'\\'-alert(34305489723146875555666)-\\'" in x:
                    found_xss=1
                if "\\'\\\\\\\\\\'-alert(34305489723146875555666)\/\/" in x:
                    found_xss=1
                if "\\'&lt;/title>\\\\\\\\\\'-alert(34305489723146875555666)//" in x:
                    found_xss=1
        ##Verify if the payload is between <style></style>, if so, the XSS will not get success
        ##############################################################################################
            if not x in string.whitespace:
                #Test and set to 1 if there is a <style> tag on reflection
                if "<style" in x:
                    style_tag=1

                if "</style>" in x:
                    style_tag=0

                if "34305489723146875555666" in x and style_tag == 1:
                    style_xss=1
                #Test some special cases, if exists in reflection, means there is  XSS
                if "\\'&lt;/style>\\'-alert(34305489723146875555666)-\\'" in x:
                    found_xss=1
                if "\\'\\'-alert(34305489723146875555666)-\\'" in x:
                    found_xss=1
                if "\\'\\\\\\\\\\'-alert(34305489723146875555666)\/\/" in x:
                    found_xss=1
                if "\\'&lt;/style>\\\\\\\\\\'-alert(34305489723146875555666)//" in x:
                    found_xss=1
        ##Verify if the payload is between <textarea></textarea>, if so, the XSS will not get success
        ##############################################################################################
            if not x in string.whitespace:
                #Test and set to 1 if there is a <textarea> tag on reflection
                if "<textarea" in x:
                    textarea_tag=1

                if "</textarea>" in x:
                    textarea_tag=0

                if "34305489723146875555666" in x and textarea_tag == 1:
                    textarea_xss=1
                #Test some special cases, if exists in reflection, means there is  XSS
                if "\\'&lt;/textarea>\\'-alert(34305489723146875555666)-\\'" in x:
                    found_xss=1
                if "\\'\\'-alert(34305489723146875555666)-\\'" in x:
                    found_xss=1
                if "\\'\\\\\\\\\\'-alert(34305489723146875555666)\/\/" in x:
                    found_xss=1
                if "\\'&lt;/script>\\\\\\\\\\'-alert(34305489723146875555666)//" in x:
                    found_xss=1
        ##Verify if the payload is between <noscript></noscript>, if so, the XSS will not get success
        ##############################################################################################
            if not x in string.whitespace:
                #Test and set to 1 if there is a <noscript> tag on reflection
                if "<noscript" in x:
                    noscript_tag=1

                if "</noscript>" in x:
                    noscript_tag=0

                if "34305489723146875555666" in x and noscript_tag == 1:
                    noscript_xss=1
                #Test some special cases, if exists in reflection, means there is  XSS
                if "\\'&lt;/noscript>\\'-alert(34305489723146875555666)-\\'" in x:
                    found_xss=1
                if "\\'\\'-alert(34305489723146875555666)-\\'" in x:
                    found_xss=1
                if "\\'\\\\\\\\\\'-alert(34305489723146875555666)\/\/" in x:
                    found_xss=1
                if "\\'&lt;/noscript>\\\\\\\\\\'-alert(34305489723146875555666)//" in x:
                    found_xss=1
            #Verify if the payload is between <script></script>, if so, the XSS will not get success
            ##############################################################################################

            if not x in string.whitespace:
                #Test and set to 1 if there is a <script> tag on reflection
                if "<script" in x:
                    script_tag=1

                if "</script>" in x:
                    script_tag=0

                if "34305489723146875555666" in x and script_tag == 1:
                    script_xss=1
                #Test some special cases, if exists in reflection, means there is  XSS
                if "\\'&lt;/script>\\'-alert(34305489723146875555666)-\\'" in x:
                    found_xss=1
                if "\\'\\'-alert(34305489723146875555666)-\\'" in x:
                    found_xss=1
                if "\\'\\\\\\\\\\'-alert(34305489723146875555666)\/\/" in x:
                    found_xss=1
                if "\\'&lt;/script>\\\\\\\\\\'-alert(34305489723146875555666)//" in x:
                    found_xss=1

            ##############################################################################################

                #Here test the opposite, if exists in reflection, means there is no XSS and suspend the current loop step
                if "&lt;svg onload=alert(34305489723146875555666)>" in x:
                    break
                if "&apos;-alert(34305489723146875555666)-&apos;" in x:
                    break
                if "-alert" in x:
                    break

                #Do some tests with the payload_verify array who contains a successfully XSS in reflection to test
                for a in payload_verify:
                    #Verifies if the code contained in the loop step coincides with array step and the <script> tag verification variable is set
                    if a in x and script_tag == 1 and "34305489723146875555666" in x:
                        #Verifies if the re-run variable is set, if set, set a script_xss variable to on to send to runxss.py confirmation there really is a <script> around reflection.
                        if script_rerun == 0:
                            script_xss=1
                        #Verifies if this is a re-run with </script> in payload and if the code contained in the loop step coincides with array, if yes, there is a XSS
                        elif script_rerun == 1 and x in a:
                            found_xss=1
                    #Verifies if the code contained in the loop step coincides with array and there is no <script> tag signal enabled.
                    elif a in x and script_tag == 0:
                        found_xss=1

        #Define the parameters to return to runxss.py
        self.title_xss=title_xss
        self.style_xss=style_xss
        self.textarea_xss=textarea_xss
        self.noscript_xss=noscript_xss
        self.script_xss=script_xss
        self.found_xss=found_xss

#Define a class who open the payload file containing the test lines
class Payloads:
    def __init__(self):
        file = open('payloads', 'r')
        Lines = file.readlines()
        self.line=np.array(Lines)
        file.close()
