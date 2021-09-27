import codecs
import os
import re
import traceback
import configparser
import time

from django.http import HttpRequest, HttpResponse, FileResponse
from django.shortcuts import render

from ScanTaskModel.models import ScanTask
from ServiceScanModel.models import ServiceScan
from VulnScanModel.models import VulnScan
from UserModel.models import User
from GroupModel.models import Group

from . import serviceUtil, pageUtil, fileUtil, vulnUtil, pocUtil, pocModelUtil, ExpUtil, IpModelUtil

port_dict = {
    "0": [22, 3389, 80, 443, 8080, 8081, 7001, 3306, 1433, 1521, 6379, 2375, 5432, 8443],
    "1": [80, 81, 8080, 8081, 3306, 1433, 5432],
    "2": [i for i in range(1, 65535)]
}

vpn_port_list = [80, 81, 8080, 8081]

port_label = {
    1433: "mssql-1433",
    3306: "mysql-3306",
    5432: "postgresql-5432",
    6379: "redis-6379",
    443: "https-443",
}

poc_type_list = pocModelUtil.poc_type_list

conf = configparser.ConfigParser()
conf.read((os.path.dirname(os.path.abspath("settings.py"))) + "\config.ini")


def _auth():  # args 是传入的，需要验证的权限
    def __auth(func):
        def _login(request, *args):
            if request.session.get('user', False) or conf.get("setting", "isLogin") == "True":  # 判断是否登录
                return func(request, *args)  # 权限验证通过，继续执行视图
            else:  # 否则执行禁止视图
                return login(request)

        return _login

    return __auth


def get_ctx(ctx, showmenu, query="1=1", mode="", group=1):
    ctx["showmenu"] = showmenu
    # task_list = ScanTask.objects.all().extra(where=[query])
    if mode == "task":
        task_list = ScanTask.objects.order_by("id").all().filter(mode="",
                                                                 group=group).extra(
            where=[query])
    else:
        task_list = ScanTask.objects.order_by("id").all().filter(
            mode="" if (mode == 'service' or mode == "vuln") else mode).extra(where=[query])
    if mode == "service":
        ports = []
        for p in port_dict.values():
            ports.append([str(i) for i in p])
        ctx["ports"] = [",".join(i) for i in ports]
    ctx["groups"] = Group.objects.all()
    ctx["task_list"] = task_list
    ctx["mode"] = mode
    ctx["gid"] = group
    return ctx

# /scan/vuln/、/scan/service/、/scan/fofa/、/scan/ip/
@_auth()
def scan(request: HttpRequest, mode, query):
    t = time.time()
    ctx = get_ctx({}, False, query, mode)
    each_num = 100
    if "page" in request.GET:
        page = int(request.GET['page'])
    else:
        page = 1
    try:
        if not "id" in request.GET:
            task = ctx["task_list"].last()
            task_id = task.id
        else:
            task_id = request.GET["id"]
            task = ScanTask.objects.get(id=task_id)
        if mode == "service" or mode == "fofa":
            ctx["process"] = task.service_process / task.task_count * 100 if not task.task_count == 0 else 0
            count = serviceUtil.get_count(task_id)
            result_list = serviceUtil.get_results(task_id, isAll=True, page=page, each_num=each_num)
        elif mode == "vuln":
            ctx["process"] = task.vuln_process / task.vuln_count * 100 if not task.vuln_count == 0 else 0
            ctx["poc_type_list"] = poc_type_list
            count = vulnUtil.get_count(task_id)
            result_list = vulnUtil.get_results(task_id, isAll=True, page=page, each_num=each_num)
        elif mode == "ip":
            ctx["process"] = task.service_process / task.task_count * 100 if not task.task_count == 0 else 0
            count = IpModelUtil.get_count(task_id)
            result_list = IpModelUtil.get_results(task_id, isAll=True, page=page, each_num=each_num)
        ctx["task"] = task
        ctx["isPause"] = task.isPause
    except:
        traceback.print_exc()
        result_list = []
        count = 0
        ctx["count"] = 0
        ctx["task_id"] = 0
    finally:
        if "new_ip" in request.GET:
            ctx["new_ip"] = request.GET["new_ip"]
        if "new_query" in request.GET:
            ctx["new_ip"] = request.GET["new_query"]
        if "desc" in request.GET:
            ctx["description"] = request.GET["desc"]
        if "port" in request.GET:
            ctx["port"] = request.GET["port"]
        else:
            ctx["port"] = 0
        if "type" in request.GET:
            ctx["type"] = request.GET["type"]
        else:
            ctx["type"] = 0
        if "port2" in request.GET:
            ctx["port2"] = request.GET["port2"]
        if "group" in request.GET:
            ctx["gid"] = request.GET["group"]
            ctx["group"] = Group.objects.get(id=ctx["gid"])
    last_page = pageUtil.get_lastpage(count, each_num)
    ctx = pageUtil.get_ctx(ctx, "result_list", result_list, page, last_page,
                           "扫描", request.get_full_path())
    print(time.time()-t)
    return render(request, "%s_scan.html" % mode, ctx)


@_auth()
def service_scan(request: HttpRequest):
    return scan(request, "service", "1=1")


@_auth()
def vuln_scan(request: HttpRequest):
    return scan(request, "vuln", "vuln_process>0")


# 开始扫描  /scan/start
@_auth()
def start_scan(request: HttpRequest):
    if request.method == "POST":
        print(request.POST)
        mode = request.POST["mode"]
        group = request.POST["group"] if "group" in request.POST else 1
        if mode == 'service':
            if "start" in request.POST and request.POST["start"] == "true":
                isStart = True
            else:
                isStart = False
            ips = request.POST["ips"].strip()
            port_list = port_dict[request.POST["port"]] if request.POST["port"] != '3' else request.POST["port2"].split(
                ",")
            if "webvpn" in request.POST and "http" in request.POST["webvpn"]:
                port_list = vpn_port_list
            else:
                port_list = [int(i) for i in port_list]
            description = request.POST["description"]
            try:
                webvpn = request.POST["webvpn"]
                cookies = request.POST["cookies"]
            except:
                webvpn = cookies = ""
            if not serviceUtil.port_scan(ips, port_list, isStart, description, group, webvpn, cookies):
                return HttpResponse("fail")
        elif mode == "vuln":
            task_id = request.POST["id"]
            vuln_type = request.POST["type"]  # 后期添加漏洞库支持，根据vuln_type获取扫描漏洞类型
            if not vulnUtil.vuln_scan(task_id, int(vuln_type)):
                return HttpResponse("fail")
        elif mode == "fofa":
            query = request.POST["ips"]
            description = request.POST["description"]
            if not serviceUtil.fofa_scan(query, False, description):
                return HttpResponse("fail")
        elif mode == "ip":
            query = request.POST["location"].strip()
            if not IpModelUtil.ip_scan(query):
                return HttpResponse("fail")
        return HttpResponse("success")


@_auth()
def get_query(request: HttpRequest):  # 过滤任务
    query = "1=1"
    if "ip" in request.GET:
        query += r" and ip_range LIKE '%%{}%%'".format(request.GET["ip"])
    if "service" in request.GET:
        if request.GET["service"] == "1":
            query += " and service_process = task_count"
        elif request.GET["service"] == "-1":
            query += " and not service_process = task_count"
    if "vuln" in request.GET:
        if request.GET["vuln"] == "1":
            query += " and vuln_process = vuln_count and not vuln_count = 0"
        elif request.GET["vuln"] == "-1":
            query += " and not vuln_process = vuln_count or vuln_count = 0"
    return query


# /scan/tasklist/
@_auth()
def task_list(request: HttpRequest, mode="task"):  # 获取任务列表
    if mode == "ip":
        page_file = "ip_list.html"
    else:
        page_file = "task_list.html"
    query = get_query(request)
    if "group" in request.GET:
        group = int(request.GET["group"])
    else:
        if "group" in request.session:
            try:
                group = int(request.session["group"])
            except:
                group = 1
        else:
            group = 1
    ctx = get_ctx({}, True, query, mode, group)
    ctx["group"] = group
    each_num = 15 if mode == "task" else 20  # 每页显示行数
    if "page" in request.GET:
        page = int(request.GET["page"])
    else:
        if "page" in request.session:
            page = int(request.session["page"])
        else:
            page = 1
    task_list = ctx["task_list"]
    last_page = pageUtil.get_lastpage(task_list.count(), each_num)
    ctx = pageUtil.get_ctx(ctx, "task_list", task_list[(page - 1) * each_num:page * each_num], page, last_page,
                           "任务", request.get_full_path())
    return render(request, page_file, ctx)


@_auth()
def fofa_list(request: HttpResponse):  # 获取fofa采集结果列表
    return task_list(request, "fofa")


@_auth()
def export_file(request: HttpRequest):
    data = fileUtil.export_file(request.GET["id"], request.GET["mode"])
    resp = HttpResponse(data)
    resp.write(codecs.BOM_UTF8)
    resp["content-type"] = "text/csv;charset=utf-8"
    resp["Content-Disposition"] = "attachment; filename=%s_%s.csv" % (request.GET["id"], request.GET["mode"])
    return resp


@_auth()
def delete_task(request: HttpRequest):
    if serviceUtil.delete_task(request.GET["id"]):
        return HttpResponse("success")


@_auth()
def stop_task(request: HttpRequest):
    task = ScanTask.objects.get(id=request.GET["id"])
    if "pause" in request.GET and request.GET["pause"] != '-1':
        task.isPause = True
        task.service_process = task.task_count
        task.isPause = False
    else:
        task.isPause = not task.isPause
    task.save()
    return HttpResponse("success")


@_auth()
def repeat_scan(request: HttpRequest):
    print("1111111111111111111111")
    task_id = request.GET["id"]
    task = ScanTask.objects.get(id=task_id)
    vuln_list = VulnScan.objects.filter(taskid=task_id)
    task.vuln_count = task.vuln_process = 0
    task.isPause = False
    task.save()
    for i in vuln_list:
        i.delete()
    return HttpResponse("success")


@_auth()
def fofa_scan(request: HttpRequest):
    return scan(request, "fofa", "mode='fofa'")


def get_poc_ctx(ctx, type=""):
    all_down = True
    ctx["showmenu"] = False
    ctx["poc_list"] = pocModelUtil.get_pocs(type)
    for i in ctx["poc_list"]:
        if i.isUse:
            all_down = False
            break
    ctx["all_down"] = all_down
    ctx["mode"] = "poc"
    ctx["risk_dict"] = {
        "danger": "高危",
        "warning": "中危",
        "success": "低危"
    }
    ctx["type"] = poc_type_list
    return ctx


@_auth()
def poc_list(request: HttpRequest):
    if "type" in request.GET:
        if request.GET["type"] == "-1":
            type = "其他"
        else:
            type = poc_type_list[int(request.GET["type"]) - 1]
    else:
        type = ""
    ctx = get_poc_ctx({}, type)
    each_num = 20  # 每页显示行数
    page = 1
    if "page" in request.GET:
        page = int(request.GET["page"])
    poc_list = ctx["poc_list"]
    last_page = pageUtil.get_lastpage(poc_list.count(), each_num)
    ctx = pageUtil.get_ctx(ctx, "poc_list", poc_list[(page - 1) * each_num:page * each_num], page, last_page,
                           "POC", request.get_full_path())
    return render(request, "poc_list.html", ctx)


@_auth()
def add_poc(request: HttpRequest):
    pocModelUtil.add_poc(request)
    return HttpResponse("success")


@_auth()
def exp(request: HttpRequest):
    return HttpResponse(ExpUtil.exp(request))


@_auth()
def ip_scan(request: HttpRequest):
    return scan(request, "ip", "1=1")


@_auth()
def ip_list(request: HttpRequest):
    return task_list(request, "ip")


def login(request: HttpRequest):
    if request.method == "GET":
        if request.session.get("user", False) or conf.get("setting", "isLogin") == "True":
            return render(request, "menu.html", {"showmenu": True})
        else:
            return render(request, "login.html", {"showmenu": False})
    else:
        username = request.POST["name"]
        pwd = request.POST["pwd"]
        try:
            user = User.objects.get(username=username)
            if pwd == user.password:
                request.session["user"] = "admin"
                return render(request, "menu.html", {"showmenu": True})
            else:
                raise Exception
        except:
            return render(request, "login.html", {"showmenu": False})


def logout(request: HttpRequest):
    request.session.flush()
    return render(request, "login.html", )


@_auth()
def user(request: HttpRequest):
    if not request.session.get("user", False):
        return logout(request)
    user = User.objects.get(username=request.session["user"])
    if request.method == "POST":
        user.password = request.POST["passwd"]
        user.save()
    return render(request, "user.html", {"showmenu": True, "username": user.username, "passwd": user.password})


@_auth()
def add_group(requset: HttpRequest):
    name = requset.GET["name"].strip()
    group = Group.objects.filter(name=name)
    if not group:
        if not name == "":
            group = Group(name=name)
            group.save()
        else:
            return HttpResponse("")
    else:
        group = group[0]
    return HttpResponse(group.id)


@_auth()
def move_group(request: HttpRequest):
    task = ScanTask.objects.get(id=request.GET["tid"])
    task.group = request.GET["gid"]
    task.save()
    return HttpResponse("success")


@_auth()
def delete_group(request: HttpRequest):
    group = request.GET["gid"]
    print(group)
    try:
        task_list = ScanTask.objects.filter(group=group)
        for i in task_list:
            serviceUtil.delete_task(i.id)
    finally:
        group = Group.objects.get(id=group)
        group.delete()
    return HttpResponse("success")


def config_group(request: HttpRequest):
    print(request.POST)
    group = Group.objects.get(id=request.POST["gid"])
    group.name = request.POST["name"]
    group.webvpn = request.POST["webvpn"]
    group.cookies = request.POST["cookies"]
    group.save()
    return HttpResponse("success")
