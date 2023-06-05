# -*- coding: utf-8 -*-

from PyQt5.QtCore import *
import gc
import traceback
from XSS_knife.runxss import xss



class xssBot(QThread):
    LOG = pyqtSignal('QString')
    LAB = pyqtSignal('QString')

    def __init__(self, params, parent=None):
        super(xssBot, self).__init__(parent)
        QThread.__init__(self, parent)
        self.setTerminationEnabled(True)
        self.params = params


    def run(self):
        try:
            xss(self.params[0], self.LOG)
            print(self.params)
        except Exception as e:
            print(e)
            print(traceback.format_exc())
        gc.collect()

