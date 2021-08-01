# -*- coding:utf-8 -*-
# 深信服行为感知系统RCE
from ServiceScanModel.models import ServiceScan
from ..requestClass import Requests


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil= Requests(service.cookies)
        self.result = False

    def sangfor_rce(self):
        resp = self.requestUtil.get(self.service.url + "/tool/log/c.php")
        if not resp.status_code == 200:
            return ["深信服行为感知系统RCE", "path:/tool/log/c.php"]
        else:
            return []

    def fingerprint(self):
        resp = self.requestUtil.get(self.service.url)
        if "isHighPerformance : !!SFIsHighPerformance" in resp.text:
            return True

    def poc(self):
        return self.sangfor_rce()
