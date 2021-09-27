# -*- coding:utf-8 -*-
# 禅道 V8.2-9.2.1 sql注入
import re

from .. import fileUtil
from ServiceScanModel.models import ServiceScan
from ..requestClass import Requests


def get_value(v):
    fv = v.split(".")[0]
    lv = "".join(v.split(".")[1:])
    return float(f"{fv}.{lv}")

class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = False

    def get_version(self, url):
        resp = self.requestUtil.get(url + "?mode=getconfig").json()
        version = get_value(resp["version"])
        print(version)
        return version

    def fingerprint(self):
        try:
            service = self.service
            if service.url:
                if not "zentao_path: " in service.speciality:
                    resp = self.requestUtil.get(service.url)
                    if "self.location=" in resp.text:
                        service.speciality = "zentao_path: /, "
                    elif "欢迎使用禅道集成运行环境" in resp.text and "开源版" in resp.text:
                        service.speciality = "zentao_path: %s, " % re.findall("href='(.*?)'.*?开源版", resp.text)[0]
                    service.save()
            return service.speciality
        except:
            return False



    def poc(self):
        try:
            service = self.service
            path = re.findall("zentao_path: (.*?),", service.speciality, re.DOTALL)[0]
            url = service.url + path
            if not "version" in service.speciality:
                version = self.get_version(url)
                service.speciality += "version: %s," % version
                service.save()
            else:
                version = float(re.findall("version: (.*?),", service.speciality)[0])
            if 8.2 < version < 9.21:
                return (["禅道 V8.2-9.2.1 sql注入", "禅道版本: %s" % version], path)
        except Exception as e:
            print(e)
            return []
