# -*- coding:utf-8 -*-
# vSphere Client RCE

from .. import fileUtil
from ServiceScanModel.models import ServiceScan
from ..requestClass import Requests

vuln_path = "/ui/vropspluginui/rest/services/uploadova"
SM_TEMPLATE = b"""<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <env:Body>
      <RetrieveServiceContent xmlns="urn:vim25">
        <_this type="ServiceInstance">ServiceInstance</_this>
      </RetrieveServiceContent>
      </env:Body>
      </env:Envelope>"""


def getValue(sResponse, sTag="vendor"):
    try:
        return sResponse.split("<" + sTag + ">")[1].split("</" + sTag + ">")[0]
    except:
        pass
    return ""


class POC:
    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)
        self.result = False

    def getVersion(self, sURL):
        oResponse = self.requestUtil.post(sURL + "/sdk", data=SM_TEMPLATE)
        if oResponse.status_code == 200:
            sResult = oResponse.text
            if not "VMware" in getValue(sResult, "vendor"):
                return False
            else:
                sVersion = getValue(sResult, "version")  # e.g. 7.0.0
                sBuild = getValue(sResult, "build")  # e.g. 15934073
                return (sVersion, sBuild)
        return False

    def check_vul(self, url):
        resp = self.requestUtil.get(url + vuln_path)
        if resp.status_code == 405:
            (sVersion, sBuild) = self.getVersion(url)
            if (
                    int(sVersion.split(".")[0]) == 6
                    and int(sVersion.split(".")[1]) == 7
                    and int(sBuild) >= 13010631
            ) or (
                    (int(sVersion.split(".")[0]) == 7 and int(sVersion.split(".")[1]) == 0)
            ):
                return False
            else:
                return f"VMware vCenter Server {sVersion}"
        return False

    def fingerprint(self):
        try:
            if self.service.url and "ID_VC_Welcome" in self.service.title:
                return True
        except:
            return False

    def poc(self):
        try:
            version = self.check_vul(self.service.url)
            if version:
                return ["vSphere Client RCE", f"{version}"]
            else:
                return []
        except:
            return []
