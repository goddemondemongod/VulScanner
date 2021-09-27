import threading

from django.http import HttpRequest

import PocModel.models
from . import fileUtil


class Poc(threading.Thread):

    def __init__(self, module, service, risk):
        threading.Thread.__init__(self)
        self.module = module
        self.service = service
        self.risk = risk
        self.result = []
        self.specify = ""

    def run(self):
        module = __import__("vulscan_Project.modules.%s_poc" % self.module, fromlist=self.module)
        Cls = getattr(module, "POC")
        cls = Cls(self.service)
        fingerprint = getattr(cls, "fingerprint")
        poc = getattr(cls, "poc")
        try:
            fingerprint_result = fingerprint()
            if fingerprint_result:  # 指纹检测，如满足特征则进行漏洞扫描
                if not type(fingerprint_result) == bool:
                    self.service.speciality = fingerprint_result
                self.result = poc()
<<<<<<< HEAD
                if type(self.result) == tuple:
=======
                if type(self.result) == tuple:  # 如果为元组，则保存传入的第二个变量，作为特征
>>>>>>> master
                    self.specify = self.result[1]
                    self.result = self.result[0]
                else:
                    self.result = self.result
                if not type(self.result) == list:
                    self.result = []
                elif len(self.result) > 1:
<<<<<<< HEAD
                    if len(self.result) == 2:
=======
                    if len(self.result) == 2:   # 如果为2，则漏洞等级为默认等级，否则传入自定义等级
>>>>>>> master
                        self.result.append(self.risk)
                    self.result.append(self.module)
                    self.result.append(self.specify)
            else:
                self.result = []
        except Exception as e:
            print(e)
            self.result = []

    def get_result(self):
        return self.result
