# coding: utf-8
from __future__ import division

import base64
import json
import os
import random
import re
import socket
import threading
import urllib
import uuid
from collections import OrderedDict
import tempfile
import demjson
import datetime

import requests
import six

import time
import rsa
import binascii
try:
    from PIL import Image
except:
    pass
try:
    from urllib.parse import quote_plus
except:
    from urllib import quote_plus


from . import helpers
from .webtrader import WebTrader, NotLoginError


class GetPageError(Exception):
    def __init__(self, result=None):
        super(GetPageError, self).__init__()
        self.result = result


'''
如果没有开启登录保护，不用输入验证码就可以登录
如果开启登录保护，需要输入验证码

'''

log = helpers.get_logger(__file__)

# 移除心跳线程产生的日志
debug_log = log.debug


def remove_heart_log(*args, **kwargs):
    if six.PY2:
        if threading.current_thread().name == 'MainThread':
            debug_log(*args, **kwargs)
    else:
        if threading.current_thread() == threading.main_thread():
            debug_log(*args, **kwargs)


log.debug = remove_heart_log


class SinaMoniTrader(WebTrader):
    config_path = os.path.dirname(__file__) + '/config/sinamoni.json'

    def __init__(self):
        super(SinaMoniTrader, self).__init__()
        self.account_config = None
        self.s = None
        self.usr_info = None

    def login(self, throw=False):
        """实现新浪模拟盘的自动登录"""

        login_status, result = self.__go_sina_login()
        if not login_status and throw:
            raise NotLoginError(result)

        self.usr_info = self.__get_user_info()
        
        return True        

    def __get_su(self, username):
        """
        对 email 地址和手机号码 先 javascript 中 encodeURIComponent
        对应 Python 3 中的是 urllib.parse.quote_plus
        然后在 base64 加密后decode
        """
        username_quote = quote_plus(username)
        username_base64 = base64.b64encode(username_quote.encode("utf-8"))
        return username_base64.decode("utf-8")

    # 预登陆获得 servertime, nonce, pubkey, rsakv
    def __get_server_data(self, su):
        pre_url = "http://login.sina.com.cn/sso/prelogin.php?entry=weibo&callback=sinaSSOController.preloginCallBack&su="
        pre_url = pre_url + su + "&rsakt=mod&checkpin=1&client=ssologin.js(v1.4.18)&_="
        pre_url = pre_url + str(int(time.time() * 1000))
        pre_data_res = self.s.get(pre_url, headers=self.headers)

        sever_data = eval(pre_data_res.content.decode("utf-8").replace("sinaSSOController.preloginCallBack", ''))
        return sever_data
        # print(sever_data)

    def __get_password(self, password, servertime, nonce, pubkey):
        rsaPublickey = int(pubkey, 16)
        key = rsa.PublicKey(rsaPublickey, 65537)  # 创建公钥
        message = str(servertime) + '\t' + str(nonce) + '\n' + str(password)  # 拼接明文js加密文件中得到
        message = message.encode("utf-8")
        passwd = rsa.encrypt(message, key)  # 加密
        passwd = binascii.b2a_hex(passwd)  # 将加密信息转换为16进制。
        return passwd

    def __get_cha(self, pcid):
        cha_url = "http://login.sina.com.cn/cgi/pin.php?r="
        cha_url = cha_url + str(int(random.random() * 100000000)) + "&s=0&p="
        cha_url = cha_url + pcid
        cha_page = session.get(cha_url, headers=headers)
        with open("cha.jpg", 'wb') as f:
            f.write(cha_page.content)
            f.close()
        try:
            im = Image.open("cha.jpg")
            im.show()
            im.close()
        except:
            print(u"请到当前目录下，找到验证码后输入")


    def __go_sina_login(self):

        # 构造 Request headers
        agent = 'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0'
        self.headers = {
            'User-Agent': agent
        }

        self.s = requests.session()

        # 访问 初始页面带上 cookie
        index_url = self.config['login_api'] 
        try:
            self.s.get(index_url, headers=self.headers, timeout=2)
        except:
            self.s.get(index_url, headers=self.headers)
        try:
            input = raw_input
        except:
            pass

        username = self.account_config['username']
        password = self.account_config['password']
        # su 是加密后的用户名
        su = self.__get_su(username)
        sever_data = self.__get_server_data(su)
        servertime = sever_data["servertime"]
        nonce = sever_data['nonce']
        rsakv = sever_data["rsakv"]
        pubkey = sever_data["pubkey"]
        showpin = sever_data["showpin"]
        password_secret = self.__get_password(password, servertime, nonce, pubkey)

        postdata = {
            'entry': 'weibo',
            'gateway': '1',
            'from': '',
            'savestate': '7',
            'useticket': '1',
            'pagerefer': "http://login.sina.com.cn/sso/logout.php?entry=miniblog&r=http%3A%2F%2Fweibo.com%2Flogout.php%3Fbackurl",
            'vsnf': '1',
            'su': su,
            'service': 'miniblog',
            'servertime': servertime,
            'nonce': nonce,
            'pwencode': 'rsa2',
            'rsakv': rsakv,
            'sp': password_secret,
            'sr': '1366*768',
            'encoding': 'UTF-8',
            'prelt': '115',
            'url': 'http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
            'returntype': 'META'
            }
        login_url = 'http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.18)'
        if showpin == 0:
            login_page = self.s.post(login_url, data=postdata, headers=self.headers)
        else:
            pcid = sever_data["pcid"]
            self.__get_cha(pcid)
            postdata['door'] = input(u"请输入验证码")
            login_page = self.s.post(login_url, data=postdata, headers=self.headers)
        login_loop = (login_page.content.decode("GBK"))
        # print(login_loop)
        pa = r'location\.replace\([\'"](.*?)[\'"]\)'
        loop_url = re.findall(pa, login_loop)[0]
        # print(loop_url)
        # 此出还可以加上一个是否登录成功的判断，下次改进的时候写上
        login_index = self.s.get(loop_url, headers=self.headers)
        uuid = login_index.text
        uuid_pa = r'"uniqueid":"(.*?)"'
        uuid_res = re.findall(uuid_pa, uuid, re.S)[0]
        web_weibo_url = "http://weibo.com/%s/profile?topnav=1&wvr=6&is_all=1" % uuid_res
        weibo_page = self.s.get(web_weibo_url, headers=self.headers)
        weibo_pa = r'<title>(.*?)</title>'
        # print(weibo_page.content.decode("utf-8"))
        userID = re.findall(weibo_pa, weibo_page.content.decode("utf-8", 'ignore'), re.S)[0]
        log.debug("欢迎你 %s," % userID)

        return True, "SUCCESS"

    def __get_user_info(self):        
        """ 请求页面获取用户信息"""
        userinfo_response = self.s.get(self.config['userinfo']['api'], headers=self.headers)        
        # 查找user id信息
        usr_result_dct = json.loads(userinfo_response.content)        
        usr_rst = usr_result_dct['result']['status']['code']
        if 0 != usr_rst:
            raise GetPageError('get usr info failed.[%d]' %usr_rst)
        log.debug('usr info: %s' %usr_result_dct['result']['data'])

        self.__sid = usr_result_dct['result']['data']['sid']        
        self.__usrinfo = usr_result_dct['result']['data']    
        return self.__usrinfo

    def create_basic_params(self):
        basic_params = OrderedDict(
                sid=self.__sid
        )
        return basic_params

    def request(self, params):

        request_headers = self.headers.copy()

        if params.has_key('Host'):            
            request_headers.update({'Host': params.pop('Host')})
        if params.has_key('Referer'):
            request_headers.update({'Referer': params.pop('Referer')})
        if params.has_key('sid'):
            params.update({'sid': self.__sid})

        api = params.pop('api')

        if six.PY2:
            params_str = urllib.urlencode(params)
            unquote_str = urllib.unquote(params_str)
        else:
            params_str = urllib.parse.urlencode(params)
            unquote_str = urllib.parse.unquote(params_str)
        log.debug('request params: %s' % unquote_str)
        r = self.s.get(url='{prefix}/{api}'.format(prefix=self.trade_prefix, api=api), params=params, headers=request_headers)            
        return r.text

    def format_response_data(self, data):
        reg = re.compile(r'jsonp\(\((.*?)\)\);')
        text = reg.sub(r"\1", data.decode('gbk') if six.PY3 else data)
        return_data = demjson.decode(text)        
        log.debug('response data: %s' % return_data)
        if not isinstance(return_data, dict):
            return return_data        
        return return_data

    def fix_error_data(self, data):        
        return data if hasattr(data, 'get') else data[data.index('new Boolean('): -1]


    # TODO: 实现买入卖出的各种委托类型
    def buy(self, stock_code, price, amount=0, volume=0, entrust_prop=0):
        """买入卖出股票
        :param stock_code: 股票代码
        :param price: 买入价格
        :param amount: 买入股数
        :param volume: 买入总金额 由 volume / price 取 100 的整数， 若指定 amount 则此参数无效
        :param entrust_prop: 委托类型，暂未实现，默认为限价委托
        """
        referer = {}
        referer.update({
            "url": "http://jiaoyi.sina.com.cn/jy/myMatchBuy.php",
            "cid": self.account_config['cid'],
            "matchid": self.account_config['matchid']
        })
        params = self.config['buy']
        params.update({"Referer": referer})

        amount=amount if amount else volume // price // 100 * 100

        return self.__trade(stock_code, price, amount=amount, entrust_prop=entrust_prop, other=params)

    def sell(self, stock_code, price, amount=0, volume=0, entrust_prop=0):
        """卖出股票
        :param stock_code: 股票代码
        :param price: 卖出价格
        :param amount: 卖出股数
        :param volume: 卖出总金额 由 volume / price 取整， 若指定 amount 则此参数无效
        :param entrust_prop: 委托类型，暂未实现，默认为限价委托
        """
        referer = {}
        referer.update({
            "url": "http://jiaoyi.sina.com.cn/jy/myMatchSell.php",
            "cid": self.account_config['cid'],
            "matchid": self.account_config['matchid'],
            "stockId": stock_code
        })
        params = self.config['sell']
        params.update({"Referer": referer})

        entrust_amount=amount if amount else volume // price
        return self.__trade(stock_code, price, amount=entrust_amount, entrust_prop=entrust_prop, other=params)

    def __trade(self, stock_code, price, amount, entrust_prop, other):
        params = other
        params.update({            
            "cid": self.account_config['cid'],
            "symbol": '{:0>6}'.format(stock_code),
            "price": price,
            "amount": amount
        })
        return self.do(params)


    def cancel_entrust(self, entrust_no):
        """撤单
        :param entrust_no: 委托单号"""        
        params = self.config['cancel_entrust'].copy()
        params.update({
            "cid": self.account_config['cid'],
            "order_id": entrust_no,
            "Host": self.config['host'],            
        })

        referer = {}
        referer.update({
            "url": "http://jiaoyi.sina.com.cn/jy/myMatchSell.php",
            "cid": self.account_config['cid'],
            "matchid": self.account_config['matchid']
        })
        params.update({"Referer": referer})

        return self.do(params)

    def get_balance(self):
        """获取账户资金状况"""
        params = self.config['balance'].copy()
        params.update({
            "contest_id": self.account_config['cid'],
        })
        return self.do(params)     

    def get_position(self):
        """获取持仓"""
        params = self.config['position'].copy()
        params.update({
            "cid": self.account_config['cid'],
            "count": 100
        })
        return self.do(params)

    def get_entrust(self):
        """获取当日委托列表"""
        today = datetime.datetime.today().strftime("%Y-%m-%d")               
        
        params = self.config['entrust'].copy()
        params.update({
            "cid": self.account_config['cid'],
            "sdate": today,
            "edate": today,
            "from": 0,
            "count": "100",
            "sort": "1"
        })
        return self.do(params)

    def get_current_deal(self):
        """获取当日成交列表"""
        today = datetime.datetime.today().strftime("%Y-%m-%d")               
        
        params = self.config['deal'].copy()
        params.update({
            "cid": self.account_config['cid'],
            "sdate": today,
            "edate": today,
            "from": 0,
            "count": "100",
            "sort": "1"
        })

    def get_exchangebill(self, start_date, end_date):
        """
        查询指定日期内的交割单
        :param start_date: 20160211
        :param end_date: 20160211
        :return:
        """        
        params = self.config['exchangebill'].copy()
        params.update({
            "cid": self.account_config['cid'],
            "sdate": start_date,
            "edate": end_date,
            "from": 0,
            "count": "100",
            "sort": "1"
        })
