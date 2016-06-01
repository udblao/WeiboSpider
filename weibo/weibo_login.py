#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'aiwuxt'

import base64
import binascii
import hashlib
import json
import os
import re
from http import cookiejar
from urllib import request, parse

import rsa


class WbLogin():
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.cookie_file = 'weibo_login_cookies.dat'

    def login(self):
        if os.path.exists(self.cookie_file):
            try:
                cookie_jar = cookiejar.LWPCookieJar(self.cookie_file)
                cookie_jar.load(ignore_discard=True, ignore_expires=True)
                loaded = True
            except cookiejar.LoadError:
                loaded = False
                print('Loading cookies error')

            if loaded:
                cookie_support = request.HTTPCookieProcessor(cookie_jar)
                opener = request.build_opener(cookie_support, request.HTTPHandler)
                request.install_opener(opener)
                print('Loading cookies success')
                return True
            else:
                print('Local cookies out of date')
                return self.__do_login(self.username, self.password, self.cookie_file)
        else:
            print('Local cookies not exists')
            return self.__do_login(self.username, self.password, self.cookie_file)

    def __get_prelogin_status(self, username):
        prelogin_url = 'http://login.sina.com.cn/sso/prelogin.php' \
                       '?entry=weibo' \
                       '&callback=sinaSSOController.preloginCallBack&su='\
                       + self.__get_user(username) + \
                       '&rsakt=mod' \
                       '&checkpin=1' \
                       '&client=ssologin.js(v1.4.11)'
        data = request.urlopen(prelogin_url).read()
        str_data = data.decode()
        pattern = re.compile('\((.*)\)')
        try:
            json_data = re.search(pattern, str_data).group(1)
            print(json_data)
            data = json.loads(json_data)
            print(data)
            servertime = str(data['servertime'])
            nonce = data['nonce']
            rsakv = data['rsakv']
            return servertime, nonce, rsakv
        except Exception as e:
            print('Getting prelogin status met error!: ' + str(e))
            return None

    def __do_login(self, username, pwd, cookie_file):
        login_data = {
            'entry': 'weibo',
            'gateway': '1',
            'from': '',
            'savestate': '7',
            'userticket': '1',
            'pagerefer':'',
            'vsnf': '1',
            'su': '',
            'service': 'miniblog',
            'servertime': '',
            'nonce': '',
            'pwencode': 'rsa2',
            'rsakv': '',
            'sp': '',
            'encoding': 'UTF-8',
            'prelt': '45',
            'url': 'http://weibo.com/ajaxlogin.php'
                   '?framelogin=1'
                   '&callback=parent.sinaSSOController.feedBackUrlCallBack',
            'returntype': 'META'
        }

        cookie_jar2 = cookiejar.LWPCookieJar()
        cookie_support2 = request.HTTPCookieProcessor(cookie_jar2)
        opener2 = request.build_opener(cookie_support2, request.HTTPHandler)
        request.install_opener(opener2)
        login_url = 'http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.11)'
        try:
            servertime, nonce, rsakv = self.__get_prelogin_status(username)
        except:
            print('Getting servertime, nonce, rsakv failed!!')
            return

        print('Starting to set login_data')
        login_data['servertime'] = servertime
        login_data['nonce'] = nonce
        login_data['rsakv'] = rsakv
        login_data['su'] = self.__get_user(username)
        login_data['sp'] = self.__get_pwd_rsa(pwd, servertime, nonce)
        login_data = parse.urlencode(login_data).encode('utf-8')
        http_headers = {'User-Agent':'Mozilla/5.0 (X11; Linux i686; rv:8.0) Gecko/20100101 Firefox/8.0'}
        req_login = request.Request(url=login_url, data=login_data, headers=http_headers)
        result = request.urlopen(req_login)
        text = result.read()
        str_text = text.decode('gbk')
        pattern = re.compile('location\.replace\(\'(.*?)\'\)')
        try:
            login_url = re.search(pattern, str_text).group(1)
            data = request.urlopen(login_url).read()
            data = data.decode()
            patt_feedback = 'feedBackUrlCallBack\((.*)\)'
            pattern = re.compile(patt_feedback, re.MULTILINE)
            feedback = pattern.search(data).group(1)
            feedback_json = json.loads(feedback)
            if feedback_json['result']:
                cookie_jar2.save(cookie_file, ignore_discard=True, ignore_expires=True)
                return True
            else:
                return False
        except Exception as e:
            print(e)
            return False

    def __get_pwd_wsse(self, pwd, servertime, nonce):
        pwd1 = hashlib.sha1(pwd).hexdigest()
        pwd2 = hashlib.sha1(pwd1).hexdigest()
        pwd3_ = pwd2 + servertime + nonce
        pwd3 = hashlib.sha1(pwd3_).hexdigest()
        return pwd3

    def __get_pwd_rsa(self, pwd, servertime, nonce):
        weibo_rsa_n = 'EB2A38568661887FA180BDDB5CABD5F21C7BFD59C090CB2D245A87AC25306288' \
                      '2729293E5506350508E7F9AA3BB77F4333231490F915F6D63C55FE2F08A49B35' \
                      '3F444AD3993CACC02DB784ABBB8E42A9B1BBFFFB38BE18D78E87A0E41B9B8F73' \
                      'A928EE0CCEE1F6739884B9777E4FE9E88A1BBE495927AC4A799B3181D6442443'
        weibo_rsa_e = 65537
        message = str(servertime) + '\t' + str(nonce) + '\n' + str(pwd)
        bytes_message = message.encode('utf-8')
        key = rsa.PublicKey(int(weibo_rsa_n, 16), weibo_rsa_e)
        encropy_pwd = rsa.encrypt(bytes_message, key)
        return binascii.b2a_hex(encropy_pwd)

    def __get_user(self, username):
        username_ = request.quote(username)
        print(username_)
        username = base64.encodestring(('%s' % username_).encode()).decode().replace('\n', '')
        print(username)
        return username
