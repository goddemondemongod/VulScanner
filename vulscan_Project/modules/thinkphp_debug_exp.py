# -*- coding:utf-8 -*-
# Thinkphp debug命令执行
from ServiceScanModel.models import ServiceScan
from VulnScanModel.models import VulnScan
from .. import requestUtil
from .thinkphp_debug_poc import POC

class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln


    def exp(self, cmd, content=""):
        poc = POC(ServiceScan(url=self.vuln.url, cookies=self.vuln.cookies))
<<<<<<< HEAD
        return poc.thinphp_debug(self.vuln.url, cmd)
=======
        return poc.thinphp_debug(self.vuln.url, cmd, content)
>>>>>>> master
