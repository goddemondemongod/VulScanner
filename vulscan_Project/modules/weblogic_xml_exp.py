# -*- coding:utf-8 -*-
# weblogic_XML反序列化
from ServiceScanModel.models import ServiceScan
from VulnScanModel.models import VulnScan
from .weblogic_xml_poc import POC

class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln


    def exp(self, cmd, content=""):
<<<<<<< HEAD
        poc = POC(ServiceScan(url=self.vuln.url, cookies=self.vuln.cookies))
        return poc.xml_deserialize(self.vuln.url, cmd, "<![CDATA[  %s  ]]>" % content, "exp")
=======
        poc = POC(self.vuln)
        return poc.xml_deserialize(cmd, "<![CDATA[  %s  ]]>" % content, "exp")
>>>>>>> master
