# -*- coding: utf-8 -*-

from PyQt5.QtCore import *
import gc
import traceback
from LFI_knife.LFI import lfi



class lfiBot(QThread):
    LOG = pyqtSignal('QString')
    LAB = pyqtSignal('QString')

    def __init__(self, params, parent=None):
        super(lfiBot, self).__init__(parent)
        QThread.__init__(self, parent)
        self.setTerminationEnabled(True)
        self.params = params


    def run(self):
        try:
            print(self.params)
            lfi(self.params[0], self.LOG)
        except Exception as e:
            print(e)
            print(traceback.format_exc())
        gc.collect()

