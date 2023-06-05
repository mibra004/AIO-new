import argparse
from SQLi_knife.injection_manager import InjectionManager
import traceback

"""
Entry point of the script
imports:
-argparse -  parse terminal arguments
-scripts.injection_manager (script is folder name and injection_manager is file name) - main controller of the app to manage all subscripts
-traceback - to print detailed info about exceptions
"""



#entry point allows to call script fro mother scripts
def sqli(url, event_VUL,  event_LOG,  event_RES):
    try:
        print('\033[93m')
        #if user pass -u parameter
        if url:
            #initialize excetion manager object
            injection_manager = InjectionManager()
            #looking for vulburables (it looks like (DB, site) tuple)
            vulnerables_detected = injection_manager.scan_url(url, event_VUL,  event_LOG,  event_RES)
            if vulnerables_detected:
                #print relust in nice black/white box
                for v in vulnerables_detected:
                    event_VUL.emit('DB:{} Site:{}'.format(v[1], v[0]))
                #do injection. We need to cut parameters with arguments.url[:arguments.url.find("=") + 1]
                injection_manager.do_injection(url[:url.find("=") + 1], event_LOG,  event_RES)
            print('\033[0m')
        #if user pass --help ot nothing or any wronng parameter
        else:
            print('\033[0m')
            event_RES.emit("Please pass url with parameters")
            print('\033[0m')
    except Exception as e:
        #prints extended info about exception
        event_RES.emit("[ERR]: {}".format(e))
        event_RES.emit(traceback.format_exc())


#NB(!) After studying this code, it is advisable to start studying the file scripts.injection_manage.py
