# -*- coding:utf-8 -*-
# 泛微OA9.0 任意文件上传
from ServiceScanModel.models import ServiceScan
from ..requestClass import Requests

vul_path_9 = "/page/exportImport/uploadOperation.jsp"


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = False

    def wui_file_poc(self, url):
        resp = self.requestUtil.get(url + vul_path_9)
        if resp.status_code == 200:
            return ["泛微OA9.0 任意文件上传", "uploadOperation.jsp"]
        else:
            return []

    def fingerprint(self):
        try:
            if not self.service.url == "" and "/help/sys/help.html" in self.requestUtil.get(self.service.url).text:
                return True
        except:
            return False

    def poc(self):
        try:
            return self.wui_file_poc(self.service.url)
        except:
            return []
