# -*- coding: utf-8 -*-
import binascii
import base64
import json
import re
import time
import traceback
import unicodedata
from urllib.parse import urljoin
import requests
import rsa
from bs4 import BeautifulSoup
from pyquery import PyQuery as pq
from requests import exceptions
from pprint import pprint
import sys
import os
import configparser
import login
import configparser
import requests
import login
import bs4
import configparser

CONF_FILE = './config.ini'
cf = configparser.ConfigParser()
cf.read(CONF_FILE)  # 读取配置文件
userName=cf.get("accountConfig","userName")
passWord=cf.get('accountConfig',"passWord")
base_url =cf.get('baseConfig',"baseUrl") 
isEnglishCourse=cf.get('baseConfig',"isEnglishCourse") 

class Login:
    raspisanie = []
    ignore_type = []

    def __init__(self, cookies={}, **kwargs):
        # 基础配置
        self.base_url = kwargs.get("base_url")
        self.ignore_type = kwargs.get("ignore_type", [])
        self.detail_category_type = kwargs.get("detail_category_type", [])
        self.timeout = kwargs.get("timeout", 3)
        Login.raspisanie = self.raspisanie
        Login.ignore_type = self.ignore_type

        self.key_url = ("http://jwxt.cumt.edu.cn/jwglxt/xtgl/login_getPublicKey.html")
        self.login_url = ( "http://jwxt.cumt.edu.cn/jwglxt/xtgl/login_slogin.html")
        self.kaptcha_url = ("http://jwxt.cumt.edu.cn/jwglxt/kaptcha")
        self.headers = requests.utils.default_headers()
        self.headers["Referer"] = self.login_url
        self.headers[
            "User-Agent"
        ] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36"
        self.headers[
            "Accept"
        ] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3"
        self.sess = requests.Session()
        self.sess.keep_alive = False
        self.cookies = cookies

    def login(self, sid, password):
        """登录教务系统"""
        need_verify = False
        try:
            # 登录页
            req_csrf = self.sess.get(
                self.login_url, headers=self.headers, timeout=self.timeout
            )
            if req_csrf.status_code != 200:
                return {"code": 2333, "msg": "教务系统挂了"}
            # 获取csrf_token
            doc = pq(req_csrf.text)
            csrf_token = doc("#csrftoken").attr("value")
            pre_cookies = self.sess.cookies.get_dict()
            # 获取publicKey并加密密码
            req_pubkey = self.sess.get(
                self.key_url, headers=self.headers, timeout=self.timeout
            ).json()
            modulus = req_pubkey["modulus"]
            exponent = req_pubkey["exponent"]
            if str(doc("input#yzm")) == "":
                # 不需要验证码
                encrypt_password = self.encrypt_password(password, modulus, exponent)
                # 登录数据
                login_data = {
                    "csrftoken": csrf_token,
                    "yhm": sid,
                    "mm": encrypt_password,
                }
                # 请求登录
                req_login = self.sess.post(
                    self.login_url,
                    headers=self.headers,
                    data=login_data,
                    timeout=self.timeout,
                )
                doc = pq(req_login.text)
                tips = doc("p#tips")
                if str(tips) != "":
                    if "用户名或密码" in tips.text():
                        return {"code": 1002, "msg": "用户名或密码不正确"}
                    return {"code": 998, "msg": tips.text()}
                self.cookies = self.sess.cookies.get_dict()
                return {"code": 1000, "msg": "登录成功", "data": {"cookies": self.cookies}}
            # 需要验证码，返回相关页面验证信息给用户，TODO: 增加更多验证方式
            need_verify = True
            req_kaptcha = self.sess.get(
                self.kaptcha_url, headers=self.headers, timeout=self.timeout
            )
            kaptcha_pic = base64.b64encode(req_kaptcha.content).decode()
            return {
                "code": 1001,
                "msg": "获取验证码成功",
                "data": {
                    "sid": sid,
                    "csrf_token": csrf_token,
                    "cookies": pre_cookies,
                    "password": password,
                    "modulus": modulus,
                    "exponent": exponent,
                    "kaptcha_pic": kaptcha_pic,
                    "timestamp": time.time(),
                },
            }
        except exceptions.Timeout:
            msg = "获取验证码超时" if need_verify else "登录超时"
            return {"code": 1003, "msg": msg}
        except (
            exceptions.RequestException,
            json.decoder.JSONDecodeError,
            AttributeError,
        ):
            traceback.print_exc()
            return {"code": 2333, "msg": "请重试，若多次失败可能是系统错误维护或需更新接口"}
        except Exception as e:
            traceback.print_exc()
            msg = "获取验证码时未记录的错误" if need_verify else "登录时未记录的错误"
            return {"code": 999, "msg": f"{msg}：{str(e)}"}

    def login_with_kaptcha(
        self, sid, csrf_token, cookies, password, modulus, exponent, kaptcha, **kwargs
    ):
        """需要验证码的登陆"""
        try:
            encrypt_password = self.encrypt_password(password, modulus, exponent)
            login_data = {
                "csrftoken": csrf_token,
                "yhm": sid,
                "mm": password,
                "yzm": kaptcha,
            }
            print(login_data)
            req_login = self.sess.post(
                self.login_url,
                headers=self.headers,
                cookies=cookies,
                data=login_data,
                timeout=self.timeout,
            )
            if req_login.status_code != 200:
                return {"code": 2333, "msg": "教务系统挂了"}
            # 请求登录
            doc = pq(req_login.text)
            tips = doc("p#tips")
            if str(tips) != "":
                if "验证码" in tips.text():
                    return {"code": 1004, "msg": "验证码输入错误"}
                if "用户名或密码" in tips.text():
                    return {"code": 1002, "msg": "用户名或密码不正确"}
                return {"code": 998, "msg": tips.text()}
            self.cookies = self.sess.cookies.get_dict()
            # 不同学校系统兼容差异
            if not self.cookies.get("route"):
                route_cookies = {
                    "JSESSIONID": cookies["JSESSIONID"],
                    'bocms_visite_user_session': cookies["bocms_visite_user_session"],  # Replace "bocms_visite_user_session" with the correct value
                    "route": cookies["route"],
                }
                self.cookies = route_cookies
            else:
                return {"code": 1000, "msg": "登录成功", "data": {"cookies": self.cookies}}
        except exceptions.Timeout:
            return {"code": 1003, "msg": "登录超时"}
        except (
            exceptions.RequestException,
            json.decoder.JSONDecodeError,
            AttributeError,
        ):
            traceback.print_exc()
            return {"code": 2333, "msg": "请重试，若多次失败可能是系统错误维护或需更新接口"}
        except Exception as e:
            traceback.print_exc()
            return {"code": 999, "msg": "验证码登录时未记录的错误：" + str(e)}
    def get_info(self):
        """获取个人信息"""
        url = ( "http://jwxt.cumt.edu.cn/jwglxt/xsxxxggl/xsxxwh_cxCkDgxsxx.html?gnmkdm=N100801")
        try:
            req_info = self.sess.get(
                url,
                headers=self.headers,
                cookies=self.cookies,
                timeout=self.timeout,
            )
            if req_info.status_code != 200:
                return {"code": 32333, "msg": "教务系统挂了"}
            doc = pq(req_info.text)
            if doc("h5").text() == "用户登录":
                return {"code": 1006, "msg": "未登录或已过期，请重新登录"}
            info = req_info.json()
            if info is None:
                return self._get_info()
            result = {
                "sid": info.get("xh"),
                "name": info.get("xm"),
                "college_name": info.get("zsjg_id", info.get("jg_id")),
                "major_name": info.get("zszyh_id", info.get("zyh_id")),
                "class_name": info.get("bh_id", info.get("xjztdm")),
                "status": info.get("xjztdm"),
                "enrollment_date": info.get("rxrq"),
                "candidate_number": info.get("ksh"),
                "graduation_school": info.get("byzx"),
                "domicile": info.get("jg"),
                "postal_code": info.get("yzbm"),
                "politics_status": info.get("zzmmm"),
                "nationality": info.get("mzm"),
                "education": info.get("pyccdm"),
                "phone_number": info.get("sjhm"),
                "parents_number": info.get("gddh"),
                "email": info.get("dzyx"),
                "birthday": info.get("csrq"),
                "id_number": info.get("zjhm"),
            }
            return {"code": 1000, "msg": "获取个人信息成功", "data": result}
        except exceptions.Timeout:
            return {"code": 1003, "msg": "获取个人信息超时"}
        except (
            exceptions.RequestException,
            json.decoder.JSONDecodeError,
            AttributeError,
        ):
            traceback.print_exc()
            return {"code": 2333, "msg": "请重试，若多次失败可能是系统错误维护或需更新接口"}
        except Exception as e:
            traceback.print_exc()
            return {"code": 999, "msg": "获取个人信息时未记录的错误：" + str(e)}  
    def _get_info(self):
        """获取个人信息"""
        url = ("http://jwxt.cumt.edu.cn/jwglxt/xsxxxggl/xsgrxxwh_cxXsgrxx.html?gnmkdm=N100801")
        try:
            req_info = self.sess.get(
                url, headers=self.headers, cookies=self.cookies, timeout=self.timeout
            )
            if req_info.status_code != 200:
                return {"code": 2333, "msg": "教务系统挂了"}
            doc = pq(req_info.text)
            if doc("h5").text() == "用户登录":
                return {"code": 1006, "msg": "未登录或已过期，请重新登录"}
            pending_result = {}
            # 学生基本信息
            for ul_item in doc.find("div.col-sm-6").items():
                content = pq(ul_item).find("div.form-group")
                # key = re.findall(r'^[\u4E00-\u9FA5A-Za-z0-9]+', pq(content).find('label.col-sm-4.control-label').text())[0]
                key = pq(content).find("label.col-sm-4.control-label").text()
                value = pq(content).find("div.col-sm-8 p.form-control-static").text()
                # 到这一步，解析到的数据基本就是一个键值对形式的html数据了，比如"[学号：]:123456"
                pending_result[key] = value
            # 学生学籍信息，其他信息，联系方式
            for ul_item in doc.find("div.col-sm-4").items():
                content = pq(ul_item).find("div.form-group")
                key = pq(content).find("label.col-sm-4.control-label").text()
                value = pq(content).find("div.col-sm-8 p.form-control-static").text()
                # 到这一步，解析到的数据基本就是一个键值对形式的html数据了，比如"[学号：]:123456"
                pending_result[key] = value
            if pending_result.get("学号：") == "":
                return {
                    "code": 1014,
                    "msg": "当前学年学期无学生时盒数据，您可能已经毕业了。\n\n如果是专升本同学，请使用专升本后的新学号登录～",
                }
            result = {
                "sid": pending_result["学号："],
                "name": pending_result["姓名："],
                # "birthday": "无" if pending_result.get("出生日期：") == '' else pending_result["出生日期："],
                # "id_number": "无" if pending_result.get("证件号码：") == '' else pending_result["证件号码："],
                # "candidate_number": "无" if pending_result.get("考生号：") == '' else pending_result["考生号："],
                # "status": "无" if pending_result.get("学籍状态：") == '' else pending_result["学籍状态："],
                # "entry_date": "无" if pending_result.get("入学日期：") == '' else pending_result["入学日期："],
                # "graduation_school": "无" if pending_result.get("毕业中学：") == '' else pending_result["毕业中学："],
                "domicile": "无"
                if pending_result.get("籍贯：") == ""
                else pending_result["籍贯："],
                "phone_number": "无"
                if pending_result.get("手机号码：") == ""
                else pending_result["手机号码："],
                "parents_number": "无",
                "email": "无"
                if pending_result.get("电子邮箱：") == ""
                else pending_result["电子邮箱："],
                "political_status": "无"
                if pending_result.get("政治面貌：") == ""
                else pending_result["政治面貌："],
                "national": "无"
                if pending_result.get("民族：") == ""
                else pending_result["民族："],
                # "education": "无" if pending_result.get("培养层次：") == '' else pending_result["培养层次："],
                # "postal_code": "无" if pending_result.get("邮政编码：") == '' else pending_result["邮政编码："],
                # "grade": int(pending_result["学号："][0:4]),
            }
            if pending_result.get("学院名称：") is not None:
                # 如果在个人信息页面获取到了学院班级
                result.update(
                    {
                        "college_name": "无"
                        if pending_result.get("学院名称：") == ""
                        else pending_result["学院名称："],
                        "major_name": "无"
                        if pending_result.get("专业名称：") == ""
                        else pending_result["专业名称："],
                        "class_name": "无"
                        if pending_result.get("班级名称：") == ""
                        else pending_result["班级名称："],
                    }
                )
            else:
                # 如果个人信息页面获取不到学院班级，则此处需要请求另外一个地址以获取学院、专业、班级等信息
                _url = urljoin(
                    self.base_url,
                    "xszbbgl/xszbbgl_cxXszbbsqIndex.html?doType=details&gnmkdm=N106005",
                )
                _req_info = self.sess.post(
                    _url,
                    headers=self.headers,
                    cookies=self.cookies,
                    timeout=self.timeout,
                    data={"offDetails": "1", "gnmkdm": "N106005", "czdmKey": "00"},
                )
                _doc = pq(_req_info.text)
                if _doc("p.error_title").text() != "无功能权限，":
                    # 通过学生证补办申请入口，来补全部分信息
                    for ul_item in _doc.find("div.col-sm-6").items():
                        content = pq(ul_item).find("div.form-group")
                        key = (
                            pq(content).find("label.col-sm-4.control-label").text()
                            + "："
                        )  # 为了保持格式一致，这里加个冒号
                        value = (
                            pq(content).find("div.col-sm-8 label.control-label").text()
                        )
                        # 到这一步，解析到的数据基本就是一个键值对形式的html数据了，比如"[学号：]:123456"
                        pending_result[key] = value
                    result.update(
                        {
                            "college_name": "无"
                            if pending_result.get("学院：") is None
                            else pending_result["学院："],
                            "major_name": "无"
                            if pending_result.get("专业：") is None
                            else pending_result["专业："],
                            "class_name": "无"
                            if pending_result.get("班级：") is None
                            else pending_result["班级："],
                        }
                    )
            return {"code": 1000, "msg": "获取个人信息成功", "data": result}
        except exceptions.Timeout:
            return {"code": 1003, "msg": "获取个人信息超时"}
        except (
            exceptions.RequestException,
            json.decoder.JSONDecodeError,
            AttributeError,
        ):
            traceback.print_exc()
            return {"code": 2333, "msg": "请重试，若多次失败可能是系统错误维护或需更新接口"}
        except Exception as e:
            traceback.print_exc()
            return {"code": 999, "msg": "获取个人信息时未记录的错误：" + str(e)}


    @classmethod
    def encrypt_password(cls, pwd, n, e):
        """对密码base64编码"""
        message = str(pwd).encode()
        rsa_n = binascii.b2a_hex(binascii.a2b_base64(n))
        rsa_e = binascii.b2a_hex(binascii.a2b_base64(e))
        key = rsa.PublicKey(int(rsa_n, 16), int(rsa_e, 16))
        encropy_pwd = rsa.encrypt(message, key)
        result = binascii.b2a_base64(encropy_pwd)
        return result
        
if __name__ == "__main__":
    from pprint import pprint
    import json
    import base64
    import sys
    import os

    '''
    print('************************************')
    print('\n')
    print("CUMT教务辅助系统2型 V1.0.0")
    print('\n')
    print('************************************')
    print("欢迎使用CUMT教务辅助系统！")
    print('请确保学号、密码已修改为自己的学号密码！\n在代码1641行修改')
    print('\n')
    '''

    # 教务系统URL
    sid = userName # 学号
    password = passWord  # 密码

    # 提供的 cookie 字符串
    cookie_string = "JSESSIONID=64E424A6AA7D8692F308F3C20B3D9371; bocms_visite_user_session=28143320542A410EFB2EA13766018F79; route=9a0873b8884eed5af7b419d835c4e479"

    # 解析 cookie 字符串
    cookies = dict(item.split("=") for item in cookie_string.split("; "))

    lgn_cookies = {
        "bocms_visite_user_session": cookies.get("bocms_visite_user_session", ""),
        "route": cookies.get("route", ""),
        "JSESSIONID": cookies.get("JSESSIONID", "")
    } if False else None  # cookies登录，调整成True使用cookies登录，反之使用密码登录

    # 初始化
    lgn = Login(cookies=lgn_cookies if lgn_cookies is not None else {}, base_url=base_url)

    # 判断是否需要使用cookies登录
    if lgn_cookies is None:
        # 登录
        pre_login = lgn.login(sid, password)
        # 判断登录结果
        if pre_login["code"] == 1001:
            # 需要验证码
            pre_dict = pre_login["data"]
            with open(os.path.abspath("temp.json"), mode="w", encoding="utf-8") as f:
                f.write(json.dumps(pre_dict))
            with open(os.path.abspath("kaptcha.png"), "wb") as pic:
                pic.write(base64.b64decode(pre_dict["kaptcha_pic"]))
            print('验证码在该代码文件夹下，kaptcha.png图片')
            kaptcha = input("输入验证码：")
            result = lgn.login_with_kaptcha(
                pre_dict["sid"],
                pre_dict["csrf_token"],
                pre_dict["cookies"],
                pre_dict["password"],
                pre_dict["modulus"],
                pre_dict["exponent"],
                kaptcha,
            )
            if result["code"] != 1000:
                pprint(result)
                sys.exit()
            lgn_cookies = lgn.cookies
            cookie_str = "; ".join([f"{key}={value}" for key, value in lgn.cookies.items()])
            print(f"Cookies string: {cookie_str}")  # 添加调试信息
            cf.set('baseConfig', 'cookies', cookie_str)  # 设置 cookies 字段

            # 将更新后的配置写回文件
            with open(CONF_FILE, 'w') as configfile:
                cf.write(configfile)

            #print(lgn_cookies)
        elif pre_login["code"] == 1000:
            # 不需要验证码，直接登录
            lgn_cookies = lgn.cookies
        else:
            # 出错
            pprint(pre_login)
            sys.exit()
    '''
    def main():
        while True:
            print("请选择要使用的功能：")
            print("1. 获取个人信息")
            print("0. 退出")
            
            choice = input("请输入选择的编号：")
            
            if choice == "1":
                """ 获取个人信息 """
                result = lgn.get_info()
                pprint(result)
            elif choice == "0":
                print("退出程序")
                break
            else:
                print("无效的选择，请重新输入")
                continue
            

    if __name__ == "__main__":
        main()
        '''
   