# -*- coding:utf-8 -*-
# docker未授权

from vulscan_Project.requestClass import Requests
from ServiceScanModel.models import ServiceScan


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = False

    def docker_poc(self, url):
        resp = self.requestUtil.get(url)
        if resp.status_code == 200:
            return ["docker未授权", "docker remote api未授权"]
        else:
            return []

    def fingerprint(self):
        if self.service.port == 2375:
            return True

    def poc(self):
        return self.docker_poc("http://%s:%s/info" % (self.service.ip, self.service.port))
