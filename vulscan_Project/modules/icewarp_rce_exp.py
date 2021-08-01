# -*- coding:utf-8 -*-
# IceWarp WebClient  远程命令执行

from VulnScanModel.models import VulnScan
from ServiceScanModel.models import ServiceScan
from vulscan_Project.requestClass import Requests
from vulscan_Project.modules.icewarp_rce_poc import POC

class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln
        self.requestUtil = Requests(vuln.cookies)


    def exp(self, cmd, content=""):
        poc = POC(ServiceScan(url=self.vuln.url, cookies=self.vuln.cookies))
        return poc.rce(cmd)