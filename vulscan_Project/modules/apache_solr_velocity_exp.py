# -*- coding:utf-8 -*-
# Apache Solr Velocity模板远程执行 

from VulnScanModel.models import VulnScan
from ServiceScanModel.models import ServiceScan
from vulscan_Project.requestClass import Requests
from vulscan_Project.modules.apache_solr_velocity_poc import POC


class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln
        self.requestUtil = Requests(vuln.cookies)


    def exp(self, cmd, content=""):
        poc = POC(ServiceScan(cookies=self.vuln.cookies))
        return poc.rce(self.vuln.url, self.vuln.specify, cmd)
