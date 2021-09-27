# -*- coding:utf-8 -*-
# 禅道 11.6 远程命令执行
import re

from .. import requestUtil, fileUtil
from ServiceScanModel.models import ServiceScan
from . import zentao_sql_poc
from ..requestClass import Requests

class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = False

    def fingerprint(self):
        try:
            poc = zentao_sql_poc.POC(self.service)
            return poc.fingerprint()
        except:
            return False

    def poc(self):
        try:
            if True:
                poc = zentao_sql_poc.POC(self.service)
                path = re.findall("zentao_path: (.*?),", self.service.speciality, re.DOTALL)[0]
                url = self.service.url + path
                print(url)
                if not "version" in self.service.speciality:
                    version = poc.get_version(url)
                    self.service.speciality += "version: %s," % version
                    poc.service.save()
                else:
                    version = float(re.findall("version: (.*?),", self.service.speciality)[0])
                if version == 11.6:
                    return (["禅道 11.6 远程命令执行", "禅道版本: %s" % version], path)
        except:
            return []
