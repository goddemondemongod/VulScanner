import requests
from Crypto.Cipher import AES


key = "wrdvpnisthebest!"
iv = "wrdvpnisthebest!"
model = AES.MODE_OFB
cookies = {
    "wengine_vpn_ticket": "e3436dc1fae3c051",
    "refresh": "1"
}
headers = {
"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0",
"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
"Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
"Accept-Encoding": "gzip, deflate"
}

def add_16(text, mode):
    segmentByteSize = 16 if mode == "utf-8" else 32
    if len(text) % segmentByteSize == 0:
        return text
    else:
        return text + "0" * (segmentByteSize - len(text))


def enc_ip(ip, port):
    aes = AES.new(key.encode("utf-8"), model, iv.encode("utf-8"))
    hash_ip = add_16(ip, "utf-8").encode("utf-8")
    protocal = f"http-{port}/"
    return protocal + iv.encode().hex() + aes.encrypt(hash_ip).hex()[0:len(ip) * 2]


def decrpt_ip(ip):
    aes = AES.new(key.encode("utf-8"), model, iv.encode("utf-8"))
    return aes.decrypt(bytes.fromhex(ip[32:]))

class VPN:
    def __init__(self, vpn_url):
        self.vpn_url = vpn_url

    def get_url(self, ip, port):
        return self.vpn_url + enc_ip(ip, port) + "/?wrdrecordvisit=record"



if __name__ == '__main__':
    print(decrpt_ip("77726476706e69737468656265737421e3e44ed22f2566516b468ca88d1b203b"))
