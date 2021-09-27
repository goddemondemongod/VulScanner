# -*- coding:utf-8 -*-
# Apache ActiveMQ 弱密码

from .. import fileUtil
from ServiceScanModel.models import ServiceScan
from vulscan_Project.requestClass import Requests



class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil= Requests(service.cookies)

    def login(self, url):
        resp = self.requestUtil.get(url.strip("/") + "/admin", header={"Authorization": "Basic YWRtaW46YWRtaW4="})
        print(resp.status_code)
        if resp.status_code == 200:
            return True

    def fingerprint(self):
        try:
            if self.service.port == 8161:
                return True
        except:
            return False

    def poc(self):
        try:
            if self.login(self.service.url):
                return ["Apache ActiveMQ 弱密码", "用户名: admin<br>密码: admin"]
        except:
            return []