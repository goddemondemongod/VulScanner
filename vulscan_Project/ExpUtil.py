from django.http import HttpRequest
from VulnScanModel.models import VulnScan
import traceback


def exp(request: HttpRequest):
    v = VulnScan.objects.get(id=request.GET["id"])
    module = __import__("vulscan_Project.modules.%s_exp" % v.module, fromlist=v.module)
    Cls = getattr(module, "EXP")
    cls = Cls(v)
    func = getattr(cls, "exp")
    if "content" in request.GET:
        content = request.GET["content"]
    else:
        content = ""
    try:
        print(request.GET["cmd"])
        result = func(request.GET["cmd"], content).replace("\\t", " "*4).strip()
    except Exception as e:
        traceback.print_exc()
        result = ""
    return result