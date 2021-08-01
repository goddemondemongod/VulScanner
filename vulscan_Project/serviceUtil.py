import base64
import json
import re
import configparser
import os

import threading
import socket
import traceback

import requests
import warnings

from GroupModel.models import Group
from ServiceScanModel.models import ServiceScan
from ScanTaskModel.models import ScanTask
from VulnScanModel.models import VulnScan
from . import IpUtil, requestUtil, vpnUtil

conf = configparser.ConfigParser()
conf.read((os.path.dirname(os.path.abspath("settings.py"))) + "\config.ini")
FOFA_EMAIL = conf.get("setting", "FOFA_EMAIL")
FOFA_KEY = conf.get("setting", "FOFA_KEY")

port_label = {
    1433: "mssql-1433",
    3306: "mysql-3306",
    5432: "postgresql-5432",
    6379: "redis-6379",
    443: "https-443",
    2375: "docker-2375",
    22: "ssh-22",
    23: "telnet-23",
    1521: "oracle-1521",
    3389: "rdp-3389"
}

type_dict = {
    "high": [2375, 1099, 3389, 22],
    "medium": [1433, 1521, 3306, 5432, 6379]
}

title_key_dict = {
    "锐捷网络--登录页面": "锐捷网络--登录页面",
    'title ng-bind="settings.title"': "DELL IDAR登录",
    'icewarp': "ICEWARP WEBCLIENT",
}


warnings.filterwarnings("ignore")


class Scan(threading.Thread):
    def __init__(self, ip, port, task_id, url="", cookies="", webvpn=""):
        threading.Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.task_id = task_id
        self.cookies = cookies
        self.webvpn = webvpn
        if self.port in type_dict["high"]:
            self.type = "high"
        elif self.port in type_dict["medium"]:
            self.type = "medium"
        else:
            self.type = "low"
        if not url == "":
            self.url = "http://" + url if not ("http" in url) else url
        else:
            self.url = ""

    def run(self):
        service_scan = None
        try:
            if self.url == "" and not "http" in self.webvpn:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect((self.ip, self.port))
                if not self.port in type_dict["high"] and not self.port in type_dict["medium"]:
                    if self.port != 443 and self.port != 8443:
                        url = "http://%s:%s" % (self.ip, self.port)
                    else:
                        url = "https://%s:%s" % (self.ip, self.port)
                    resp = requestUtil.get(url, cookies=self.cookies)
                    print(resp.status_code)
                else:
                    resp = None
                service_scan = ServiceScan(ip=self.ip, port=self.port, taskid=self.task_id, type=self.type)
            else:
                if "http" in self.webvpn:
                    vpn = vpnUtil.VPN(vpn_url=self.webvpn)
                    url = vpn.get_url(self.ip, self.port)
                    print(url)
                    resp = requestUtil.get(url, cookies=self.cookies)
                    if not resp or "fail" in resp.text or "Not Found" in resp.text or "访问出错" in resp.text:
                        return
                else:
                    url = self.url
                    resp = requestUtil.get(url, cookies=self.cookies)
                    if not resp:
                        return
                service_scan = ServiceScan(ip=self.ip, port=self.port, taskid=self.task_id, type=self.type)
            if resp == None:
                raise Exception
            try:
                index = resp.content.find(b'<title')
                content = resp.content[index:index + 100]
                title = re.findall(r"<title.*?>(.*?)</title>", content.decode("utf-8"), re.DOTALL)[0]
                if title == "":
                    title = "空标题"
            except UnicodeDecodeError:
                try:
                    title = re.findall(r"<title.*?>(.*?)</title>", content.decode("gbk"), re.DOTALL)[0]
                except:
                    title = "空标题"
            except Exception as e:
                title = "空标题"
            try:
                server = resp.headers["Server"]
            except:
                server = "None"
            service_scan.title = title
            service_scan.server = server
            service_scan.url = url
            service_scan.cookies = self.cookies
            fingerprint(resp, service_scan)
        except Exception as e:
            pass
        finally:
            try:
                service_scan.save()
            except Exception as e:
                return


def port_scan(ips, port_list, isStart=False, description="", group=1, webvpn="", cookies=""):
    ip_list = IpUtil.get_all_ips(ips)
    if ip_list == []:
        return False
    task = ScanTask(ip_range=ips, task_count=len(ip_list) * len(port_list), isStart=isStart, description=description, group=group)
    task.save()
    tid = task.id
    scan_list = []
    threads = 200 if not "http" in webvpn else 100
    for i in ip_list:
        for p in port_list:
            scan_list.append(Scan(i, p, tid, cookies=cookies, webvpn=webvpn))
            if len(scan_list) % threads == 0:
                for s in scan_list:
                    s.start()
                for s in scan_list:
                    s.join()
                    task.service_process += 1
                    task.save(update_fields=["service_process"])
                scan_list = []
    for s in scan_list:
        s.start()
    for s in scan_list:
        s.join()
        task.service_process += 1
        task.save(update_fields=["service_process"])
    return True

def get_services(query, page=0, each_num=0):
    service_list = ServiceScan.objects.values("ip").extra(where=[query]).distinct()
    return service_list


def get_count(task_id, page=0, each_num=0):    # 获取结果集总数
    query = "1=1"
    query += " and taskid=%s" % (task_id)
    service_list = get_services(query, page, each_num)
    return service_list.count()


def get_results(task_id, isAll=False, page=1, each_num=100):  # 获取扫描结果，isAll=True获取所有结果，否则获取未显示结果
    result_list = []
    if isAll:
        query = "1=1"
    else:
        query = "isShown=False"
    query += " and taskid=%s and ip in (select t.ip from (select distinct ip from servicescanmodel_servicescan where taskid=%s limit %d, %d) t)" % (task_id, task_id, (page-1)*each_num, each_num)
    service_list = ServiceScan.objects.order_by("ip").extra(where=[query])
    temp_ip = ""
    result = {}
    for i in service_list:
        if i.ip != temp_ip:
            temp_ip = i.ip
            if not result == {}:
                result_list.append(result)
                result = {}
            result["ip"] = temp_ip
            result["vulnerable"] = i.vulnerable
            result["note"] = i.note
            result["ports"] = []
        result["ports"].append({"label": port_label[i.port] if i.port in port_label else "http-%d" % i.port,
                                "type": i.type, "title": i.title, "server": i.server, "url": i.url,
                                "port": i.port})
        i.isShown = True
        i.save()
    if result:
        result_list.append(result)
    return result_list


def delete_task(task_id):
    task = ScanTask.objects.get(id=task_id)
    service_list = ServiceScan.objects.filter(taskid=task_id)
    vuln_list = VulnScan.objects.filter(taskid=task_id)
    task.delete()
    for i in service_list:
        i.delete()
    return True


def fofa_scan(query, isStart=False, description=""):
    if not "country" in query:
        query += ' && country="CN" && region != "HK"'
    b_query = base64.b64encode(query.encode()).decode()
    resp = requestUtil.get(f"https://fofa.so/api/v1/search/all?email={FOFA_EMAIL}&key={FOFA_KEY}&qbase64={b_query}", timeout=20)
    print(resp.text)
    results = (json.loads(resp.text))["results"]
    task = ScanTask(ip_range=query.replace(' && country="CN" && region != "HK"', ''), task_count=len(results), isStart=isStart, mode="fofa", description=description)
    task.save()
    tid = task.id
    scan_list = []
    count = 0
    for i in results:
        count += 1
        scan_list.append(Scan(i[1], i[2], tid, i[0]))
        if len(scan_list) % 5 == 0:
            for s in scan_list:
                task.service_process += 1
                task.save(update_fields=["service_process"])
                s.start()
            for s in scan_list:
                s.join()
            scan_list = []
    for s in scan_list:
        task.service_process += 1
        task.save(update_fields=["service_process"])
        s.start()
    for s in scan_list:
        s.join()
    return True


def fingerprint(resp, service_scan):
    page = resp.content.decode()
    for k, v in title_key_dict.items():
        if k in page:
            service_scan.title = v
            break


