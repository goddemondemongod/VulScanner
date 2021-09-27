# -*- coding:utf-8 -*-
# ftp弱密码

import ftplib
import socket
from threading import Thread
from .. import fileUtil
from ServiceScanModel.models import ServiceScan
from ..requestClass import Requests, session


class Burp(Thread):
    def __init__(self, ip, username, password):
        Thread.__init__(self)
        self.ip = ip
        self.username = username
        self.password = password
        self.result = False

    def run(self):
        try:
            ftp = ftplib.FTP(self.ip, timeout=0.5)
            ftp.login(self.username, self.password)
            self.result = True
        except:
            pass

    def get_result(self):
        return self.result


class POC:
    def __init__(self, service: ServiceScan = None):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = False

    def fingerprint(self):
        try:
            if self.service.port == 22:
                return True
        except:
            return False

    def poc(self):
        try:
            def Test(test_list):
                for t in test_list:
                    t.start()
                for t in test_list:
                    t.join()
                for t in test_list:
                    if t.get_result():
                        return (t.username, t.password)
                return False

            burp_list = fileUtil.get_burp_list("ftp")
            test_list = []
            for i in burp_list:
                test_list.append(Burp(self.service.ip, i[0], i[1]))
                if len(test_list) % 30 == 0:
                    result = Test(test_list)
                    if result:
                        return ["ftp弱密码", f"用户名: {result[0]}<br>密码: {result[1]}"]
            result = Test(test_list)
            if result:
                return ["ftp弱密码", f"用户名: {result[0]}<br>密码: {result[1]}"]
        except:
            return []
