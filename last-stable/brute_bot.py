# -*- coding: utf-8 -*-

from PyQt5.QtCore import *
import gc
import traceback
from bruteLogin_knife.main import brute_force


class bruteBot(QThread):
    LOG = pyqtSignal('QString')
    LAB = pyqtSignal('QString')

    def __init__(self, params, parent=None):
        super(bruteBot, self).__init__(parent)
        QThread.__init__(self, parent)
        self.setTerminationEnabled(True)
        self.params = params

    def run(self):
        try:

            brute_force(self.params[5], self.params[1], self.params[2], self.params[3], self.params[0], self.params[4],
                        self.LOG, self.LAB)


            print(self.params)
        except Exception as e:
            print(e)
            print(traceback.format_exc())
        gc.collect()
