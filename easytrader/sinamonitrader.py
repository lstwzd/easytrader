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

    def __get_user_info(self):        
        raw_name = self.account_config['userName']
        use_index_start = 1
        return raw_name[use_index_start:] if raw_name.startswith('08') and self.remove_zero is True else raw_name

    def login(self, throw=False):
        """实现新浪模拟盘的自动登录"""
        self.__go_sina_login()

        verify_code = self.__handle_recognize_code()
        if not verify_code:
            return False

        is_login, result = self.__check_login_status(verify_code)
        if not is_login:
            if throw:
                raise NotLoginError(result)
            return False

        trade_info = self.__get_trade_info()
        if not trade_info:
            return False

        self.__set_trade_need_info(trade_info)

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
        pre_data_res = session.get(pre_url, headers=headers)

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
            login_page = session.post(login_url, data=postdata, headers=headers)
        else:
            pcid = sever_data["pcid"]
            self.__get_cha(pcid)
            postdata['door'] = input(u"请输入验证码")
            login_page = session.post(login_url, data=postdata, headers=headers)
        login_loop = (login_page.content.decode("GBK"))
        # print(login_loop)
        pa = r'location\.replace\([\'"](.*?)[\'"]\)'
        loop_url = re.findall(pa, login_loop)[0]
        # print(loop_url)
        # 此出还可以加上一个是否登录成功的判断，下次改进的时候写上
        login_index = session.get(loop_url, headers=headers)
        uuid = login_index.text
        uuid_pa = r'"uniqueid":"(.*?)"'
        uuid_res = re.findall(uuid_pa, uuid, re.S)[0]
        web_weibo_url = "http://weibo.com/%s/profile?topnav=1&wvr=6&is_all=1" % uuid_res
        weibo_page = session.get(web_weibo_url, headers=headers)
        weibo_pa = r'<title>(.*?)</title>'
        # print(weibo_page.content.decode("utf-8"))
        userID = re.findall(weibo_pa, weibo_page.content.decode("utf-8", 'ignore'), re.S)[0]
        log.debug("欢迎你 %s," % userID)


    #以下待实现
    def __get_trade_info(self):
        """ 请求页面获取交易所需的 uid 和 password """
        trade_info_response = self.s.get(self.config['trade_info_page'])

        # 查找登录信息
        search_result = re.search(r'var data = "([/=\w\+]+)"', trade_info_response.text)
        if not search_result:
            return False

        need_data_index = 0
        need_data = search_result.groups()[need_data_index]
        bytes_data = base64.b64decode(need_data)
        log.debug('trade info bytes data: ', bytes_data)
        try:
            str_data = bytes_data.decode('gbk')
        except UnicodeDecodeError:
            str_data = bytes_data.decode('gb2312', errors='ignore')
        log.debug('trade info: %s' % str_data)
        json_data = json.loads(str_data)
        return json_data

    def __set_trade_need_info(self, json_data):
        """设置交易所需的一些基本参数
        :param json_data:登录成功返回的json数据
        """
        for account_info in json_data['item']:
            if account_info['stock_account'].startswith('A'):
                # 沪 A  股东代码以 A 开头，同时需要是数字，沪 B 帐号以 C 开头
                if account_info['exchange_type'].isdigit():
                    self.__sh_exchange_type = account_info['exchange_type']
                self.__sh_stock_account = account_info['stock_account']
                log.debug('sh_A stock account %s' % self.__sh_stock_account)
            # 深 A 股东代码以 0 开头，深 B 股东代码以 2 开头
            elif account_info['stock_account'].startswith('0'):
                self.__sz_exchange_type = account_info['exchange_type']
                self.__sz_stock_account = account_info['stock_account']
                log.debug('sz_A stock account %s' % self.__sz_stock_account)

        self.__fund_account = json_data['fund_account']
        self.__client_risklevel = json_data['branch_no']
        self.__op_station = json_data['op_station']
        self.__trdpwd = json_data['trdpwd']
        self.__uid = json_data['uid']
        self.__branch_no = json_data['branch_no']

    def cancel_entrust(self, entrust_no):
        """撤单
        :param entrust_no: 委托单号"""
        cancel_params = dict(
                self.config['cancel_entrust'],
                entrust_no=entrust_no
        )
        return self.do(cancel_params)

    # TODO: 实现买入卖出的各种委托类型
    def buy(self, stock_code, price, amount=0, volume=0, entrust_prop=0):
        """买入卖出股票
        :param stock_code: 股票代码
        :param price: 买入价格
        :param amount: 买入股数
        :param volume: 买入总金额 由 volume / price 取 100 的整数， 若指定 amount 则此参数无效
        :param entrust_prop: 委托类型，暂未实现，默认为限价委托
        """
        params = dict(
                self.config['buy'],
                entrust_amount=amount if amount else volume // price // 100 * 100
        )
        return self.__trade(stock_code, price, entrust_prop=entrust_prop, other=params)

    def sell(self, stock_code, price, amount=0, volume=0, entrust_prop=0):
        """卖出股票
        :param stock_code: 股票代码
        :param price: 卖出价格
        :param amount: 卖出股数
        :param volume: 卖出总金额 由 volume / price 取整， 若指定 amount 则此参数无效
        :param entrust_prop: 委托类型，暂未实现，默认为限价委托
        """
        params = dict(
                self.config['sell'],
                entrust_amount=amount if amount else volume // price
        )
        return self.__trade(stock_code, price, entrust_prop=entrust_prop, other=params)

    def __trade(self, stock_code, price, entrust_prop, other):
        need_info = self.__get_trade_need_info(stock_code)
        return self.do(dict(
                other,
                stock_account=need_info['stock_account'],  # '沪深帐号'
                exchange_type=need_info['exchange_type'],  # '沪市1 深市2'
                entrust_prop=entrust_prop,  # 委托方式
                stock_code='{:0>6}'.format(stock_code),  # 股票代码, 右对齐宽为6左侧填充0
                entrust_price=price
        ))

    def __get_trade_need_info(self, stock_code):
        """获取股票对应的证券市场和帐号"""
        # 获取股票对应的证券市场
        exchange_type = self.__sh_exchange_type if helpers.get_stock_type(stock_code) == 'sh' \
            else self.__sz_exchange_type
        # 获取股票对应的证券帐号
        stock_account = self.__sh_stock_account if exchange_type == self.__sh_exchange_type \
            else self.__sz_stock_account
        return dict(
                exchange_type=exchange_type,
                stock_account=stock_account
        )

    def create_basic_params(self):
        basic_params = OrderedDict(
                uid=self.__uid,
                version=1,
                custid=self.account_config['userName'],
                op_branch_no=self.__branch_no,
                branch_no=self.__branch_no,
                op_entrust_way=7,
                op_station=self.__op_station,
                fund_account=self.fund_account,
                password=self.__trdpwd,
                identity_type='',
                ram=random.random()
        )
        return basic_params

    def request(self, params):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'
        }
        if six.PY2:
            item = params.pop('ram')
            params['ram'] = item
        else:
            params.move_to_end('ram')
        if six.PY2:
            params_str = urllib.urlencode(params)
            unquote_str = urllib.unquote(params_str)
        else:
            params_str = urllib.parse.urlencode(params)
            unquote_str = urllib.parse.unquote(params_str)
        log.debug('request params: %s' % unquote_str)
        b64params = base64.b64encode(unquote_str.encode()).decode()
        r = self.s.get('{prefix}/?{b64params}'.format(prefix=self.trade_prefix, b64params=b64params), headers=headers)
        return r.content

    def format_response_data(self, data):
        bytes_str = base64.b64decode(data)
        gbk_str = bytes_str.decode('gbk')
        log.debug('response data before format: %s' % gbk_str)
        filter_empty_list = gbk_str.replace('[]', 'null')
        filter_return = filter_empty_list.replace('\n', '')
        log.debug('response data: %s' % filter_return)
        response_data = json.loads(filter_return)
        if response_data['cssweb_code'] == 'error' or response_data['item'] is None:
            return response_data
        return_data = self.format_response_data_type(response_data['item'])
        log.debug('response data: %s' % return_data)
        return return_data

    def fix_error_data(self, data):
        last_no_use_info_index = -1
        return data if hasattr(data, 'get') else data[:last_no_use_info_index]

    @property
    def exchangebill(self):
        start_date, end_date = helpers.get_30_date()
        return self.get_exchangebill(start_date, end_date)

    def get_exchangebill(self, start_date, end_date):
        """
        查询指定日期内的交割单
        :param start_date: 20160211
        :param end_date: 20160211
        :return:
        """
        params = self.config['exchangebill'].copy()
        params.update({
            "start_date": start_date,
            "end_date": end_date,
        })
        return self.do(params)
