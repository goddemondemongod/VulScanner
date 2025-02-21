# -*- coding:utf-8 -*-
# 帆软报表8.0 任意文件读取

from VulnScanModel.models import VulnScan
from VulnScanModel.models import VulnScan
from ServiceScanModel.models import ServiceScan
from vulscan_Project.requestClass import Requests

from vulscan_Project.modules.fineport_v8_file_poc import POC

class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln
        self.requestUtil = Requests(vuln.cookies)


    def exp(self, cmd, content=""):
        poc = POC(ServiceScan(url=self.vuln.url, cookies=self.vuln.cookies))
        return poc.fineport_file_poc(cmd, "exp")