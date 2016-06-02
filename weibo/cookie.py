#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'aiwuxt'

import json
import base64
import requests


class GetCookie():

    def __init__(self, account, password):
        self.account = account
        self.password = password

    def getCookie(self):
        cookie = []
        login_url = r'https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.15)'
        username = base64.b64encode(self.account.encode('utf-8')).decode('utf-8')
        post_data = {
            "entry": "sso",
            "gateway": "1",
            "from": "null",
            "savestate": "30",
            "useticket": "0",
            "pagerefer": "",
            "vsnf": "1",
            "su": username,
            "service": "sso",
            "sp": self.password,
            "sr": "1440*900",
            "encoding": "UTF-8",
            "cdult": "3",
            "domain": "sina.com.cn",
            "prelt": "0",
            "returntype": "TEXT",
        }
        session = requests.Session()
        r = session.post(login_url, data=post_data)
        json_str = r.content.decode('gbk')
        info = json.loads(json_str)
        if info['retcode'] == "0":
            print('Get cookie success! (Account:%s)' % self.account)
            cookie = session.cookies.get_dict()
        else:
            print("Failed! (Reason: %s)" % info['reason'])
        return cookie
