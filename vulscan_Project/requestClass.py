import requests
from urllib3 import encode_multipart_formdata

from ServiceScanModel.models import ServiceScan
from vulscan_Project import requestUtil


class Requests:
    def __init__(self, cookies: object = "") -> object:
        """

        :rtype: object
        """
        self.cookies = cookies

    def get(self, url, cookies="", header=None, timeout=10, session=""):
        if header == None:
            header = {}
        cookies = self.cookies.strip().strip(";") + ";" + cookies
        return requestUtil.get(url=url, cookies=cookies, header=header,timeout=timeout, session=session)

    def post(self, url, data="", cookies="", header=None, timeout=10, session="", files=None, shell=False):
        cookies = self.cookies.strip().strip(";") + ";" + cookies
        return requestUtil.post(url=url,data=data, cookies=cookies, header=header,timeout=timeout, session=session, files=files, shell=shell)

    def get_file_data(self, filename, filedata, param="file"):  # param: 上传文件的POST参数名
        data = {}
        data[param] = (filename, filedata)  # 名称，读文件
        encode_data = encode_multipart_formdata(data)
        return encode_data

def session():
    return requests.session()