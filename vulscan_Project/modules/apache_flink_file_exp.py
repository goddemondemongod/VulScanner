# -*- coding:utf-8 -*-
# Apache Flink 任意文件读取

from VulnScanModel.models import VulnScan
from ServiceScanModel.models import ServiceScan
from vulscan_Project.requestClass import Requests
from vulscan_Project.modules.apache_flink_file_poc import POC

class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln
        self.requestUtil = Requests(vuln.cookies)

    def exp(self, cmd, content=""):
        poc = POC(ServiceScan(cookies=self.vuln.cookies))
        return poc.flink_file_poc(self.vuln.url, cmd, "exp")