from gui import Ui_Form
from PyQt5 import QtCore, QtWidgets, QtGui
from PyQt5.QtWidgets import *
import traceback
import sys
from _thread import start_new_thread

from sqli_bot import sqliBot
from xss_bot import xssBot
from lfi_bot import lfiBot
from brute_bot import bruteBot


class mywindow(QWidget):
    def __init__(self):
        '''Returns argument a is squared.'''
        try:
            super().__init__()
            self.ui = Ui_Form()
            self.ui.setupUi(self)
            self.threads_list = []
            self.ui.sqli_run.clicked.connect(self.start_sqli_bot)
            self.ui.llfi_run.clicked.connect(self.start_lfi_bot)
            self.ui.xss_run.clicked.connect(self.start_xss_bot)
            self.ui.brut_run.clicked.connect(self.start_brute_bot)
            self.ui.brute_selectfile.clicked.connect(self.rescrape_from_file)




        except Exception as e:
            print(traceback.format_exc())
            print(str(e))

    def start_sqli_bot(self):
        for each in self.threads_list:
            start_new_thread(each.terminate, ())
        params = [self.ui.sqli_url.toPlainText()]

        t = sqliBot(params)
        t.LOG.connect(self.sqli_log)
        t.LAB.connect(self.sqli_result)
        t.VUL.connect(self.update_all_vulinfo)
        t.setTerminationEnabled(True)
        self.threads_list.append(t)
        self.sqli_log("STARTED")
        t.start()

    def start_xss_bot(self):
        for each in self.threads_list:
            start_new_thread(each.terminate, ())
        params = [self.ui.xss_target.toPlainText()]

        t = xssBot(params)
        t.LOG.connect(self.xss_log)
        t.LAB.connect(self.xss_res)
        t.setTerminationEnabled(True)
        self.threads_list.append(t)
        self.xss_log("STARTED")
        t.start()

    def start_lfi_bot(self):
        params = [self.ui.lfi_target.toPlainText()]

        for each in self.threads_list:
            start_new_thread(each.terminate, ())

        t = lfiBot(params)
        t.LOG.connect(self.sqli_log)
        t.LAB.connect(self.sqli_result)
        t.setTerminationEnabled(True)
        self.threads_list.append(t)
        self.lfi_log("STARTED")
        t.start()

    def rescrape_from_file(self):
        qf = QFileDialog()
        new_zippath = QtWidgets.QFileDialog.getOpenFileName(qf, '/', '.txt')[0]
        self.ui.brute_path_to_password.setText(str(new_zippath))

    def start_brute_bot(self):
        params = [self.ui.brute_site.toPlainText(),
                  self.ui.brute_login.toPlainText(),
                  self.ui.brute_pass.toPlainText(),
                  self.ui.brute_button.toPlainText(),
                  self.ui.brute_path_to_password.toPlainText(),
                  self.ui.prediction_report_29.toPlainText(),
                  ]

        for each in self.threads_list:
            start_new_thread(each.terminate, ())

        t = bruteBot(params)
        t.LOG.connect(self.sqli_log)
        t.LAB.connect(self.sqli_result)
        t.setTerminationEnabled(True)
        self.threads_list.append(t)
        self.brute_log("STARTED")
        t.start()

    def update_all_vulinfo(self, message):
        appl.processEvents()
        self.ui.sqli_vulinfo.append(message)
        self.ui.lfi_vulinfo.append(message)
        self.ui.xss_vulinfo.append(message)
        self.ui.brute_vulinfo.append(message)

    def sqli_log(self, message):

        appl.processEvents()
        self.ui.sqli_log.append(message)

    def sqli_result(self, message):

        appl.processEvents()
        self.ui.sqli_result.append(message)

    def brute_log(self, message):

        appl.processEvents()
        self.ui.brute_log.append(message)

    def brute_result(self, message):

        appl.processEvents()
        self.ui.brute_result.append(message)

    def xss_log(self, message):

        appl.processEvents()
        self.ui.xss_log.append(message)

    def xss_res(self, message):

        appl.processEvents()
        self.ui.xss_result.append(message)

    def lfi_log(self, message):

        appl.processEvents()
        self.ui.lfi_log.append(message)

    def lfi_res(self, message):

        appl.processEvents()
        self.ui.lfi_result.append(message)

    # autoLogs of all prints and errors


print("STARTED")
try:
    print('1')
    appl = QtWidgets.QApplication(sys.argv)
    print('2')

    appl.processEvents()
    print('3')

    form = mywindow()
    print('4')

    form.show()
    print('5')

    sys.exit(appl.exec_())
    print('6')

except Exception:
    print(traceback.format_exc())
