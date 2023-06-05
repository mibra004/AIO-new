# -*- coding: utf-8 -*-

from PyQt5.QtCore import *
import gc
import traceback
from SQLi_knife import sqli_knife

class sqliBot(QThread):
    LOG = pyqtSignal('QString')
    LAB = pyqtSignal('QString')
    VUL = pyqtSignal('QString')

    def __init__(self, params, parent=None):
        super(sqliBot, self).__init__(parent)
        QThread.__init__(self, parent)
        self.setTerminationEnabled(True)
        self.params = params



    def run(self):
        try:
            print(self.params)

            #sqli_knife.sqli('http://www.asfaa.org/members.php?id=1', self.VUL,  self.LOG, self.LAB)
            sqli_knife.sqli(str(self.params[0]), self.VUL,  self.LOG, self.LAB)

            self.VUL.emit("Some info")
            print('OMG')
        except Exception as e:
            print(e)
            print(traceback.format_exc())
        gc.collect()

